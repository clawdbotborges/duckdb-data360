#include "data360/query_api.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <unordered_set>

namespace data360 {
namespace {

std::string TrimTrailingSlash(std::string value) {
	while (!value.empty() && value.back() == '/') {
		value.pop_back();
	}
	return value;
}

bool IsTrustedTenantUrl(const std::string &value) {
	constexpr const char *scheme = "https://";
	constexpr const char *suffix = ".c360a.salesforce.com";
	if (value.rfind(scheme, 0) != 0) {
		return false;
	}
	auto host = value.substr(std::char_traits<char>::length(scheme));
	if (!host.empty() && host.back() == '/') {
		host.pop_back();
	}
	if (host.empty() || host.find_first_of("/?#@:\\%") != std::string::npos) {
		return false;
	}
	for (const unsigned char character : host) {
		if (character > 0x7f || std::iscntrl(character) || std::isupper(character)) {
			return false;
		}
	}
	const std::string expected_suffix(suffix);
	if (host.size() <= expected_suffix.size() ||
	    host.compare(host.size() - expected_suffix.size(), expected_suffix.size(), expected_suffix) != 0) {
		return false;
	}
	size_t label_start = 0;
	while (label_start < host.size()) {
		const auto label_end = host.find('.', label_start);
		const auto length = (label_end == std::string::npos ? host.size() : label_end) - label_start;
		if (length == 0 || length > 63 || !std::isalnum(static_cast<unsigned char>(host[label_start])) ||
		    !std::isalnum(static_cast<unsigned char>(host[label_start + length - 1]))) {
			return false;
		}
		for (size_t index = label_start; index < label_start + length; index++) {
			const auto character = static_cast<unsigned char>(host[index]);
			if (!std::isalnum(character) && character != '-') {
				return false;
			}
		}
		if (label_end == std::string::npos) {
			break;
		}
		label_start = label_end + 1;
	}
	return true;
}

bool IsSafeQueryId(const std::string &value) {
	if (value.empty() || value.size() > 128) {
		return false;
	}
	for (const unsigned char character : value) {
		if (!std::isalnum(character) && character != '-' && character != '_') {
			return false;
		}
	}
	return true;
}

bool IsSafeChunkPath(const std::string &value) {
	constexpr const char *prefix = "/api/v3/query/";
	constexpr const char *separator = "/chunks/";
	if (value.rfind(prefix, 0) != 0 || value.size() > 256 || value.find_first_of("\\?#%") != std::string::npos ||
	    value.find("..") != std::string::npos) {
		return false;
	}
	const auto rest = value.substr(std::char_traits<char>::length(prefix));
	const auto separator_at = rest.find(separator);
	if (separator_at == std::string::npos || rest.find(separator, separator_at + 1) != std::string::npos ||
	    !IsSafeQueryId(rest.substr(0, separator_at))) {
		return false;
	}
	const auto chunk_id = rest.substr(separator_at + std::char_traits<char>::length(separator));
	if (chunk_id.empty() || chunk_id.size() > 20) {
		return false;
	}
	for (const unsigned char character : chunk_id) {
		if (!std::isdigit(character)) {
			return false;
		}
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
		case '\\':
			escaped += "\\\\";
			break;
		case '"':
			escaped += "\\\"";
			break;
		case '\b':
			escaped += "\\b";
			break;
		case '\f':
			escaped += "\\f";
			break;
		case '\n':
			escaped += "\\n";
			break;
		case '\r':
			escaped += "\\r";
			break;
		case '	':
			escaped.push_back('\\');
			escaped.push_back('t');
			break;
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

} // namespace

QueryApiV3Client::QueryApiV3Client(HttpTransport &transport_p, QueryResponseCodec &codec_p, RuntimeHooks &runtime_p,
                                   QueryOptions options_p)
    : transport(transport_p), codec(codec_p), runtime(runtime_p), options(options_p) {
	if (options.request_timeout_ms == 0 || options.overall_timeout_ms == 0 || options.poll_interval_ms == 0 ||
	    options.max_chunks == 0 || options.cleanup_timeout_ms == 0 || options.cleanup_timeout_ms > 1000 ||
	    options.poll_interval_ms > options.overall_timeout_ms) {
		throw std::invalid_argument("Data 360 query options are invalid");
	}
}

QueryResult QueryApiV3Client::Execute(const std::string &sql, const QueryCredentials &credentials) {
	if (runtime.IsCancelled()) {
		throw std::runtime_error("Data 360 query cancelled");
	}
	if (sql.empty()) {
		throw std::invalid_argument("Data 360 query SQL must not be empty");
	}
	if (credentials.instance_url.empty() || credentials.access_token.empty()) {
		throw std::invalid_argument("Data 360 credentials are incomplete");
	}
	if (!IsTrustedTenantUrl(credentials.instance_url)) {
		throw std::invalid_argument("Data 360 tenant URL is not trusted");
	}
	HttpRequest request;
	request.method = "POST";
	request.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query";
	request.headers["Authorization"] = "Bearer " + credentials.access_token;
	request.headers["Content-Type"] = "application/json";
	request.body = "{\"sql\":\"" + JsonEscape(sql) + "\"}";
	request.timeout_ms = options.request_timeout_ms;

	const auto started_at_ms = runtime.NowMs();
	auto send = [&](HttpRequest &outbound) {
		const auto elapsed = runtime.NowMs() - started_at_ms;
		if (elapsed >= options.overall_timeout_ms) {
			throw std::runtime_error("Data 360 query timed out");
		}
		if (runtime.IsCancelled()) {
			throw std::runtime_error("Data 360 query cancelled");
		}
		outbound.timeout_ms = std::min(options.request_timeout_ms, options.overall_timeout_ms - elapsed);
		HttpResponse response;
		try {
			response = transport.Send(outbound);
		} catch (...) {
			throw std::runtime_error("Data 360 transport failed");
		}
		return response;
	};
	auto decode = [&](const HttpResponse &response) {
		try {
			return codec.Decode(response);
		} catch (...) {
			throw std::runtime_error("Data 360 response decoding failed");
		}
	};
	auto decoded = decode(send(request));
	std::string last_remote_query_id;
	auto remember_response_query_id = [&]() {
		if (!decoded.query_id.empty()) {
			if (!IsSafeQueryId(decoded.query_id)) {
				throw std::runtime_error("Data 360 Query API returned an invalid query ID");
			}
			last_remote_query_id = decoded.query_id;
		} else if (IsSafeChunkPath(decoded.chunk.next_url)) {
			last_remote_query_id = QueryIdFromChunkPath(decoded.chunk.next_url);
		}
	};
	remember_response_query_id();
	auto best_effort_cancel = [&](const std::string &query_id) {
		if (!IsSafeQueryId(query_id)) {
			return;
		}
		HttpRequest cancellation = request;
		cancellation.method = "DELETE";
		cancellation.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query/" + query_id;
		cancellation.body.clear();
		cancellation.timeout_ms = options.cleanup_timeout_ms;
		cancellation.max_response_bytes = 64 * 1024;
		try {
			transport.Send(cancellation);
		} catch (...) {
			// Best effort: preserve the local cancellation or timeout result.
		}
	};
	if (runtime.NowMs() - started_at_ms >= options.overall_timeout_ms || runtime.IsCancelled()) {
		best_effort_cancel(last_remote_query_id);
		if (runtime.IsCancelled()) {
			throw std::runtime_error("Data 360 query cancelled");
		}
		throw std::runtime_error("Data 360 query timed out");
	}
	while (decoded.state == QueryState::RUNNING) {
		if (!IsSafeQueryId(last_remote_query_id)) {
			throw std::runtime_error("Data 360 Query API returned an invalid async response");
		}
		runtime.SleepMs(options.poll_interval_ms);
		const bool timed_out = runtime.NowMs() - started_at_ms >= options.overall_timeout_ms;
		if (runtime.IsCancelled() || timed_out) {
			best_effort_cancel(last_remote_query_id);
			if (timed_out) {
				throw std::runtime_error("Data 360 query timed out");
			}
			throw std::runtime_error("Data 360 query cancelled");
		}
		request.method = "GET";
		request.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query/" + last_remote_query_id;
		request.body.clear();
		try {
			decoded = decode(send(request));
		} catch (...) {
			const bool failed_timed_out = runtime.NowMs() - started_at_ms >= options.overall_timeout_ms;
			if (runtime.IsCancelled() || failed_timed_out) {
				best_effort_cancel(last_remote_query_id);
				if (runtime.IsCancelled()) {
					throw std::runtime_error("Data 360 query cancelled");
				}
				throw std::runtime_error("Data 360 query timed out");
			}
			throw;
		}
		remember_response_query_id();
		if (runtime.NowMs() - started_at_ms >= options.overall_timeout_ms || runtime.IsCancelled()) {
			best_effort_cancel(last_remote_query_id);
			if (runtime.IsCancelled()) {
				throw std::runtime_error("Data 360 query cancelled");
			}
			throw std::runtime_error("Data 360 query timed out");
		}
	}
	if (decoded.state != QueryState::COMPLETE) {
		throw std::runtime_error("Data 360 Query API did not complete");
	}
	QueryResult result;
	result.metadata = std::move(decoded.metadata);
	result.chunks.push_back(std::move(decoded.chunk));
	std::unordered_set<std::string> visited_chunk_urls;
	while (!result.chunks.back().next_url.empty()) {
		const auto next_url = result.chunks.back().next_url;
		if (!IsSafeChunkPath(next_url) || !visited_chunk_urls.insert(next_url).second) {
			throw std::runtime_error("Data 360 Query API returned an unsafe chunk URL");
		}
		const auto remote_query_id = QueryIdFromChunkPath(next_url);
		auto cancel_remote = [&]() {
			HttpRequest cancellation = request;
			cancellation.method = "DELETE";
			cancellation.url = TrimTrailingSlash(credentials.instance_url) + "/api/v3/query/" + remote_query_id;
			cancellation.body.clear();
			cancellation.timeout_ms = options.cleanup_timeout_ms;
			cancellation.max_response_bytes = 64 * 1024;
			try {
				transport.Send(cancellation);
			} catch (...) {
				// Best effort: preserve the local cancellation or timeout result.
			}
		};
		if (runtime.IsCancelled()) {
			cancel_remote();
			throw std::runtime_error("Data 360 query cancelled");
		}
		if (runtime.NowMs() - started_at_ms >= options.overall_timeout_ms) {
			cancel_remote();
			throw std::runtime_error("Data 360 query timed out");
		}
		if (result.chunks.size() >= options.max_chunks) {
			cancel_remote();
			throw std::runtime_error("Data 360 Query API returned too many chunks");
		}
		request.method = "GET";
		request.url = TrimTrailingSlash(credentials.instance_url) + next_url;
		request.body.clear();
		QueryResponse chunk_response;
		try {
			chunk_response = decode(send(request));
		} catch (...) {
			const bool failed_timed_out = runtime.NowMs() - started_at_ms >= options.overall_timeout_ms;
			if (runtime.IsCancelled() || failed_timed_out) {
				cancel_remote();
				if (runtime.IsCancelled()) {
					throw std::runtime_error("Data 360 query cancelled");
				}
				throw std::runtime_error("Data 360 query timed out");
			}
			throw;
		}
		if (chunk_response.state != QueryState::COMPLETE) {
			throw std::runtime_error("Data 360 Query API chunk retrieval failed");
		}
		if (runtime.IsCancelled()) {
			cancel_remote();
			throw std::runtime_error("Data 360 query cancelled");
		}
		if (runtime.NowMs() - started_at_ms >= options.overall_timeout_ms) {
			cancel_remote();
			throw std::runtime_error("Data 360 query timed out");
		}
		result.chunks.push_back(std::move(chunk_response.chunk));
	}
	return result;
}

} // namespace data360
