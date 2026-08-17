#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace data360 {

class ReauthRequiredException final : public std::runtime_error {
public:
	ReauthRequiredException()
	    : std::runtime_error("D360-AUTH-017 REAUTH_REQUIRED: Authorization is required") {
	}
};

using Cell = std::optional<std::string>;

struct HttpRequest {
	std::string method;
	std::string url;
	std::map<std::string, std::string> headers;
	std::string body;
	uint64_t timeout_ms;
	bool follow_redirects = false;
	uint64_t max_response_bytes = 64ULL * 1024ULL * 1024ULL;
	bool cleanup_request = false;
};

struct HttpResponse {
	int status;
	std::string body;
	std::map<std::string, std::string> headers = {};
};

class HttpTransport {
public:
	virtual ~HttpTransport() = default;
	virtual HttpResponse Send(const HttpRequest &request) = 0;
};

struct ColumnMetadata {
	std::string name;
	std::string type;
	bool nullable;
	bool has_precision = false;
	bool has_scale = false;
	uint8_t precision = 0;
	uint8_t scale = 0;
};

struct ResultChunk {
	std::vector<std::vector<Cell>> rows;
	std::string next_url;
};

enum class QueryState { RUNNING, COMPLETE, FAILED };

struct QueryResponse {
	QueryState state = QueryState::RUNNING;
	std::string query_id;
	std::string safe_error_code;
	uint64_t chunk_count = 0;
	uint64_t row_count = 0;
	bool has_chunk_count = false;
	bool has_row_count = false;
	uint64_t returned_rows = 0;
	bool has_returned_rows = false;
	std::vector<ColumnMetadata> metadata;
	ResultChunk chunk;
};

class QueryResponseCodec {
public:
	virtual ~QueryResponseCodec() = default;
	virtual QueryResponse Decode(const HttpResponse &response) = 0;
};

class RuntimeHooks {
public:
	virtual ~RuntimeHooks() = default;
	virtual bool IsCancelled() = 0;
	virtual uint64_t NowMs() = 0;
	virtual void SleepMs(uint64_t milliseconds) = 0;
};

struct QueryCredentials {
	std::string instance_url;
	std::string access_token;
};

struct QueryOptions {
	uint64_t request_timeout_ms = 30000;
	uint64_t overall_timeout_ms = 120000;
	uint64_t poll_interval_ms = 250;
	uint64_t max_chunks = 1024;
	uint64_t cleanup_timeout_ms = 250;
	uint64_t max_rows = 100000;
	uint64_t max_columns = 4096;
	uint64_t max_cells = 10000000;
	uint64_t max_total_response_bytes = 256ULL * 1024ULL * 1024ULL;
};

struct QueryResult {
	std::vector<ColumnMetadata> metadata;
	std::vector<ResultChunk> chunks;
};

class QueryCursor;

class PreparedQuery {
public:
	PreparedQuery(PreparedQuery &&) noexcept;
	PreparedQuery &operator=(PreparedQuery &&) noexcept;
	~PreparedQuery() noexcept;

	PreparedQuery(const PreparedQuery &) = delete;
	PreparedQuery &operator=(const PreparedQuery &) = delete;

	const std::vector<ColumnMetadata> &Metadata() const;
	QueryCursor OpenCursor() &&;

private:
	friend class QueryApiV3Client;
	struct State;
	explicit PreparedQuery(std::unique_ptr<State> state_p);
	std::unique_ptr<State> state;
};

class QueryCursor {
public:
	QueryCursor(QueryCursor &&) noexcept;
	QueryCursor &operator=(QueryCursor &&) noexcept;
	~QueryCursor() noexcept;

	QueryCursor(const QueryCursor &) = delete;
	QueryCursor &operator=(const QueryCursor &) = delete;

	bool NextChunk(ResultChunk &result);
	bool IsNumberedV3() const;
	bool NextArrowChunk(HttpResponse &response);
	void ReportArrowChunk(uint64_t decoded_rows);

private:
	friend class PreparedQuery;
	struct State;
	explicit QueryCursor(std::unique_ptr<State> state_p);
	std::unique_ptr<State> state;
};

class QueryApiV3Client {
public:
	QueryApiV3Client(HttpTransport &transport, QueryResponseCodec &codec, RuntimeHooks &runtime,
	                 QueryOptions options = {});
	PreparedQuery Prepare(const std::string &sql, const QueryCredentials &credentials);
	QueryResult Execute(const std::string &sql, const QueryCredentials &credentials);
	QueryResult ExecuteMetadata(const std::string &sql, const QueryCredentials &credentials);

private:
	PreparedQuery PrepareInternal(const std::string &sql, const QueryCredentials &credentials, bool metadata_only);
	HttpTransport &transport;
	QueryResponseCodec &codec;
	RuntimeHooks &runtime;
	QueryOptions options;
};

} // namespace data360
