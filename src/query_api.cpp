#include "data360/query_api.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace data360 {
namespace {

std::string TrimTrailingSlash(std::string value) {
	while (!value.empty() && value.back() == '/') value.pop_back();
	return value;
}

bool IsTrustedTenantUrl(const std::string &value) {
	constexpr const char *scheme = "https://";
	constexpr const char *suffix = ".c360a.salesforce.com";
	if (value.rfind(scheme, 0) != 0) return false;
	auto host = value.substr(std::char_traits<char>::length(scheme));
	if (!host.empty() && host.back() == '/') host.pop_back();
	if (host.empty() || host.find_first_of("/?#@:\\%") != std::string::npos) return false;
	for (const unsigned char character : host) {
		if (character > 0x7f || std::iscntrl(character) || std::isupper(character)) return false;
	}
	const std::string expected_suffix(suffix);
	if (host.size() <= expected_suffix.size() ||
	    host.compare(host.size() - expected_suffix.size(), expected_suffix.size(), expected_suffix) != 0) return false;
	size_t label_start = 0;
	while (label_start < host.size()) {
		const auto label_end = host.find('.', label_start);
		const auto length = (label_end == std::string::npos ? host.size() : label_end) - label_start;
		if (length == 0 || length > 63 || !std::isalnum(static_cast<unsigned char>(host[label_start])) ||
		    !std::isalnum(static_cast<unsigned char>(host[label_start + length - 1]))) return false;
		for (size_t index = label_start; index < label_start + length; index++) {
			const auto character = static_cast<unsigned char>(host[index]);
			if (!std::isalnum(character) && character != '-') return false;
		}
		if (label_end == std::string::npos) break;
		label_start = label_end + 1;
	}
	return true;
}

bool IsSafeQueryId(const std::string &value) {
	if (value.empty() || value.size() > 128) return false;
	for (const unsigned char character : value) {
		if (!std::isalnum(character) && character != '-' && character != '_') return false;
	}
	return true;
}

bool IsSafeChunkPath(const std::string &value) {
	constexpr const char *prefix = "/api/v3/query/";
	constexpr const char *separator = "/chunks/";
	if (value.rfind(prefix, 0) != 0 || value.size() > 256 || value.find_first_of("\\?#%") != std::string::npos ||
	    value.find("..") != std::string::npos) return false;
	const auto rest = value.substr(std::char_traits<char>::length(prefix));
	const auto separator_at = rest.find(separator);
	if (separator_at == std::string::npos || rest.find(separator, separator_at + 1) != std::string::npos ||
	    !IsSafeQueryId(rest.substr(0, separator_at))) return false;
	const auto chunk_id = rest.substr(separator_at + std::char_traits<char>::length(separator));
	if (chunk_id.empty() || chunk_id.size() > 20) return false;
	for (const unsigned char character : chunk_id) {
		if (!std::isdigit(character)) return false;
	}
	return true;
}

std::string QueryIdFromChunkPath(const std::string &value) {
	constexpr const char *prefix = "/api/v3/query/";
	constexpr const char *separator = "/chunks/";
	const auto start = std::char_traits<char>::length(prefix);
	const auto end = value.find(separator, start);
	return value.substr(start, end - start);
}

std::string JsonEscape(const std::string &value) {
	static constexpr char hex[] = "0123456789abcdef";
	std::string escaped;
	for (const unsigned char character : value) {
		switch (character) {
		case '\\': escaped += "\\\\"; break;
		case '"': escaped += "\\\""; break;
		case '\b': escaped += "\\b"; break;
		case '\f': escaped += "\\f"; break;
		case '\n': escaped += "\\n"; break;
		case '\r': escaped += "\\r"; break;
		case '\t': escaped += "\\t"; break;
		default:
			if (character < 0x20) {
				escaped += "\\u00";
				escaped += hex[(character >> 4U) & 0x0fU];
				escaped += hex[character & 0x0fU];
			} else {
				escaped += static_cast<char>(character);
			}
		}
	}
	return escaped;
}

bool SameMetadata(const std::vector<ColumnMetadata> &left, const std::vector<ColumnMetadata> &right) {
	if (left.size() != right.size()) return false;
	for (size_t i = 0; i < left.size(); i++) {
		if (left[i].name != right[i].name || left[i].type != right[i].type || left[i].nullable != right[i].nullable)
			return false;
	}
	return true;
}

enum class QueryMode { NUMBERED_V3, DIRECT_LEGACY };

struct Session {
	HttpTransport *transport;
	QueryResponseCodec *codec;
	RuntimeHooks *runtime;
	QueryOptions options;
	QueryCredentials credentials;
	HttpRequest request;
	uint64_t started_at_ms = 0;
	uint64_t total_response_bytes = 0;
	QueryMode mode = QueryMode::DIRECT_LEGACY;
	std::vector<ColumnMetadata> metadata;
	std::string query_id;
	bool has_expected_chunks = false;
	uint64_t expected_chunks = 0;
	bool has_expected_rows = false;
	uint64_t expected_rows = 0;
	uint64_t next_chunk_index = 0;
	std::optional<QueryResponse> buffered_direct;
	std::string next_url;
	std::unordered_set<std::string> visited_urls;
	uint64_t fetched_chunks = 0;
	uint64_t rows = 0;
	uint64_t cells = 0;
	bool reconciled = false;
	bool terminal = false;

	~Session() noexcept { Cancel(); }

	void Cancel() noexcept {
		if (terminal || reconciled || !IsSafeQueryId(query_id)) return;
		terminal = true;
		HttpRequest cancellation = request;
		cancellation.method = "DELETE";
		cancellation.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query/" + query_id;
		cancellation.body.clear();
		cancellation.timeout_ms = options.cleanup_timeout_ms;
		cancellation.max_response_bytes = 64 * 1024;
		cancellation.cleanup_request = true;
		try {
			transport->Send(cancellation);
		} catch (...) {
		}
	}

	void CheckActive() {
		if (runtime->IsCancelled()) throw std::runtime_error("Data 360 query cancelled");
		const auto now = runtime->NowMs();
		if (now - started_at_ms >= options.overall_timeout_ms) throw std::runtime_error("Data 360 query timed out");
	}

	HttpResponse Send(HttpRequest &outbound) {
		CheckActive();
		const auto elapsed = runtime->NowMs() - started_at_ms;
		outbound.timeout_ms = std::min(options.request_timeout_ms, options.overall_timeout_ms - elapsed);
		const auto remaining = options.max_total_response_bytes -
		                       std::min(total_response_bytes, options.max_total_response_bytes);
		outbound.max_response_bytes = std::min(outbound.max_response_bytes, remaining);
		HttpResponse response;
		try {
			response = transport->Send(outbound);
		} catch (...) {
			if (runtime->IsCancelled()) throw std::runtime_error("Data 360 query cancelled");
			if (runtime->NowMs() - started_at_ms >= options.overall_timeout_ms)
				throw std::runtime_error("Data 360 query timed out");
			throw std::runtime_error("Data 360 transport failed");
		}
		if (response.body.size() > remaining)
			throw std::runtime_error("Data 360 Query API cumulative response limit exceeded");
		total_response_bytes += response.body.size();
		return response;
	}

	QueryResponse Decode(const HttpResponse &response) {
		try {
			return codec->Decode(response);
		} catch (...) {
			if (runtime->IsCancelled()) throw std::runtime_error("Data 360 query cancelled");
			throw std::runtime_error("Data 360 response decoding failed");
		}
	}

	void RememberQueryId(const QueryResponse &response) {
		if (!response.query_id.empty()) {
			if (!IsSafeQueryId(response.query_id))
				throw std::runtime_error("Data 360 Query API returned an invalid query ID");
			if (!query_id.empty() && response.query_id != query_id)
				throw std::runtime_error("Data 360 Query API query identity changed");
			query_id = response.query_id;
		}
		if (IsSafeChunkPath(response.chunk.next_url)) {
			const auto next_query_id = QueryIdFromChunkPath(response.chunk.next_url);
			if (!query_id.empty() && next_query_id != query_id)
				throw std::runtime_error("Data 360 Query API query identity changed");
			if (query_id.empty()) query_id = next_query_id;
		}
	}

	void Accept(QueryResponse &response, ResultChunk &result) {
		if (response.state != QueryState::COMPLETE)
			throw std::runtime_error("Data 360 Query API chunk retrieval failed");
		if (!response.metadata.empty() && !SameMetadata(metadata, response.metadata))
			throw std::runtime_error("Data 360 Query API result schema changed");
		if (fetched_chunks >= options.max_chunks)
			throw std::runtime_error("Data 360 Query API returned too many chunks");
		const auto chunk_rows = static_cast<uint64_t>(response.chunk.rows.size());
		if (response.has_returned_rows && response.returned_rows != chunk_rows)
			throw std::runtime_error("Data 360 Query API chunk row count mismatch");
		if (chunk_rows > options.max_rows - std::min(rows, options.max_rows))
			throw std::runtime_error("Data 360 Query API materialization limit exceeded");
		for (const auto &row : response.chunk.rows) {
			if (row.size() != metadata.size())
				throw std::runtime_error("Data 360 Query API returned an invalid row width");
			if (row.size() > options.max_cells - std::min(cells, options.max_cells))
				throw std::runtime_error("Data 360 Query API materialization limit exceeded");
			cells += row.size();
		}
		if (has_expected_rows && chunk_rows > expected_rows - std::min(rows, expected_rows))
			throw std::runtime_error("Data 360 Query API row count mismatch");
		rows += chunk_rows;
		fetched_chunks++;
		result = std::move(response.chunk);
	}

	bool Finish() {
		if (mode == QueryMode::NUMBERED_V3 && has_expected_chunks && fetched_chunks != expected_chunks)
			throw std::runtime_error("Data 360 Query API chunk count mismatch");
		if (has_expected_rows && rows != expected_rows)
			throw std::runtime_error("Data 360 Query API row count mismatch");
		if (mode == QueryMode::DIRECT_LEGACY && !next_url.empty())
			throw std::runtime_error("Data 360 Query API chunk chain was incomplete");
		reconciled = true;
		terminal = true;
		return false;
	}
};

} // namespace

struct PreparedQuery::State {
	explicit State(std::unique_ptr<Session> session_p) : session(std::move(session_p)) {}
	std::unique_ptr<Session> session;
};

struct QueryCursor::State {
	explicit State(std::unique_ptr<Session> session_p) : session(std::move(session_p)) {}
	std::unique_ptr<Session> session;
};

PreparedQuery::PreparedQuery(std::unique_ptr<State> state_p) : state(std::move(state_p)) {}
PreparedQuery::PreparedQuery(PreparedQuery &&) noexcept = default;
PreparedQuery &PreparedQuery::operator=(PreparedQuery &&) noexcept = default;
PreparedQuery::~PreparedQuery() noexcept = default;

const std::vector<ColumnMetadata> &PreparedQuery::Metadata() const {
	if (!state || !state->session) throw std::logic_error("Data 360 prepared query is not available");
	return state->session->metadata;
}

QueryCursor PreparedQuery::OpenCursor() && {
	if (!state || !state->session) throw std::logic_error("Data 360 prepared query is not available");
	auto session = std::move(state->session);
	state.reset();
	return QueryCursor(std::make_unique<QueryCursor::State>(std::move(session)));
}

QueryCursor::QueryCursor(std::unique_ptr<State> state_p) : state(std::move(state_p)) {}
QueryCursor::QueryCursor(QueryCursor &&) noexcept = default;
QueryCursor &QueryCursor::operator=(QueryCursor &&) noexcept = default;
QueryCursor::~QueryCursor() noexcept = default;

bool QueryCursor::NextChunk(ResultChunk &result) {
	if (!state || !state->session) throw std::logic_error("Data 360 query cursor is not available");
	auto &session = *state->session;
	if (session.reconciled) return false;
	if (session.terminal) throw std::logic_error("Data 360 query cursor is terminal");
	try {
		while (true) {
			QueryResponse response;
			if (session.mode == QueryMode::NUMBERED_V3) {
				if (session.next_chunk_index >= session.expected_chunks) return session.Finish();
				session.request.method = "GET";
				session.request.body.clear();
				session.request.url = TrimTrailingSlash(session.credentials.instance_url) + "/api/v3/query/" +
				                      session.query_id + "/chunks/" + std::to_string(session.next_chunk_index++);
				response = session.Decode(session.Send(session.request));
			} else if (session.buffered_direct) {
				response = std::move(*session.buffered_direct);
				session.buffered_direct.reset();
			} else {
				if (session.next_url.empty()) return session.Finish();
				if (!IsSafeChunkPath(session.next_url) || !session.visited_urls.insert(session.next_url).second)
					throw std::runtime_error("Data 360 Query API returned an unsafe chunk URL");
				const auto url = session.next_url;
				if (session.query_id.empty()) session.query_id = QueryIdFromChunkPath(url);
				session.request.method = "GET";
				session.request.body.clear();
				session.request.url = TrimTrailingSlash(session.credentials.instance_url) + url;
				response = session.Decode(session.Send(session.request));
			}
			session.RememberQueryId(response);
			session.CheckActive();
			ResultChunk accepted;
			session.Accept(response, accepted);
			if (session.mode == QueryMode::DIRECT_LEGACY) session.next_url = accepted.next_url;
			result = std::move(accepted);
			return true;
		}
	} catch (...) {
		session.Cancel();
		throw;
	}
}

QueryApiV3Client::QueryApiV3Client(HttpTransport &transport_p, QueryResponseCodec &codec_p, RuntimeHooks &runtime_p,
                                   QueryOptions options_p)
    : transport(transport_p), codec(codec_p), runtime(runtime_p), options(options_p) {
	if (options.request_timeout_ms == 0 || options.overall_timeout_ms == 0 || options.poll_interval_ms == 0 ||
	    options.max_chunks == 0 || options.cleanup_timeout_ms == 0 || options.cleanup_timeout_ms > 1000 ||
	    options.max_rows == 0 || options.max_rows > 100000 || options.max_columns == 0 || options.max_cells == 0 ||
	    options.max_total_response_bytes == 0 || options.poll_interval_ms > options.overall_timeout_ms)
		throw std::invalid_argument("Data 360 query options are invalid");
}

PreparedQuery QueryApiV3Client::Prepare(const std::string &sql, const QueryCredentials &credentials) {
	return PrepareInternal(sql, credentials, false);
}

PreparedQuery QueryApiV3Client::PrepareInternal(const std::string &sql, const QueryCredentials &credentials,
                                                bool metadata_only) {
	if (runtime.IsCancelled()) throw std::runtime_error("Data 360 query cancelled");
	if (sql.empty()) throw std::invalid_argument("Data 360 query SQL must not be empty");
	if (credentials.instance_url.empty() || credentials.access_token.empty())
		throw std::invalid_argument("Data 360 credentials are incomplete");
	if (!IsTrustedTenantUrl(credentials.instance_url))
		throw std::invalid_argument("Data 360 tenant URL is not trusted");

	auto session = std::make_unique<Session>();
	session->transport = &transport;
	session->codec = &codec;
	session->runtime = &runtime;
	session->options = options;
	session->credentials = credentials;
	session->started_at_ms = runtime.NowMs();
	session->request.method = "POST";
	session->request.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query";
	session->request.headers["Authorization"] = "Bearer " + credentials.access_token;
	session->request.headers["Content-Type"] = "application/json";
	session->request.headers["Accept"] = "application/json";
	session->request.body = "{\"sql\":\"" + JsonEscape(sql) +
	                        "\",\"transferMode\":\"ASYNC\",\"settings\":{\"timezone\":\"Etc/UTC\",\"language\":\"en_US\"},"
	                        "\"queryRowLimit\":" + std::to_string(metadata_only ? 1 : options.max_rows) + "}";
	session->request.timeout_ms = options.request_timeout_ms;

	try {
		auto decoded = session->Decode(session->Send(session->request));
		session->RememberQueryId(decoded);
		session->CheckActive();
		while (decoded.state == QueryState::RUNNING) {
			if (!IsSafeQueryId(session->query_id))
				throw std::runtime_error("Data 360 Query API returned an invalid async response");
			runtime.SleepMs(options.poll_interval_ms);
			session->CheckActive();
			session->request.method = "GET";
			session->request.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query/" + session->query_id;
			session->request.body.clear();
			decoded = session->Decode(session->Send(session->request));
			session->RememberQueryId(decoded);
			session->CheckActive();
		}
		if (decoded.state != QueryState::COMPLETE)
			throw std::runtime_error("Data 360 Query API did not complete");
		if (decoded.has_chunk_count || decoded.chunk_count > 0) {
			if (!IsSafeQueryId(session->query_id))
				throw std::runtime_error("Data 360 Query API returned an invalid completed response");
			session->mode = QueryMode::NUMBERED_V3;
			session->has_expected_chunks = true;
			session->expected_chunks = decoded.chunk_count;
			session->has_expected_rows = decoded.has_row_count;
			session->expected_rows = decoded.row_count;
			if (session->expected_chunks > options.max_chunks)
				throw std::runtime_error("Data 360 Query API returned too many chunks");
			if (session->has_expected_rows && session->expected_rows > options.max_rows)
				throw std::runtime_error("Data 360 Query API materialization limit exceeded");
			session->request.method = "GET";
			session->request.body.clear();
			session->request.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query/" + session->query_id +
			                       "/metadata";
			auto metadata_response = session->Decode(session->Send(session->request));
			if (metadata_response.state != QueryState::COMPLETE || metadata_response.metadata.empty())
				throw std::runtime_error("Data 360 Query API metadata retrieval failed");
			session->metadata = std::move(metadata_response.metadata);
		} else {
			session->mode = QueryMode::DIRECT_LEGACY;
			session->metadata = decoded.metadata;
			session->has_expected_rows = decoded.has_row_count;
			session->expected_rows = decoded.row_count;
			session->buffered_direct = std::move(decoded);
		}
		if (session->metadata.size() > options.max_columns)
			throw std::runtime_error("Data 360 Query API returned too many columns");
		return PreparedQuery(std::make_unique<PreparedQuery::State>(std::move(session)));
	} catch (...) {
		session->Cancel();
		throw;
	}
}

QueryResult QueryApiV3Client::Execute(const std::string &sql, const QueryCredentials &credentials) {
	auto prepared = Prepare(sql, credentials);
	QueryResult result;
	result.metadata = prepared.Metadata();
	auto cursor = std::move(prepared).OpenCursor();
	ResultChunk chunk;
	while (cursor.NextChunk(chunk)) result.chunks.push_back(std::move(chunk));
	return result;
}

QueryResult QueryApiV3Client::ExecuteMetadata(const std::string &sql, const QueryCredentials &credentials) {
	auto prepared = PrepareInternal(sql, credentials, true);
	QueryResult result;
	result.metadata = prepared.Metadata();
	return result;
}

} // namespace data360
