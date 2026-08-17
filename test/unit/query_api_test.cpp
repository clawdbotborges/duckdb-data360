#include "data360/query_api.hpp"
#include "data360/native_runtime.hpp"
#include "data360/type_mapping.hpp"

#include <cstdlib>
#include <deque>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <stdexcept>

using namespace data360;

namespace {

void Require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

std::string ReadSourceFile(const std::string &relative_path) {
	std::string test_path = __FILE__;
	for (auto &character : test_path) {
		if (character == '\\') character = '/';
	}
	const auto marker = test_path.rfind("test/unit/query_api_test.cpp");
	Require(marker != std::string::npos, "test source path did not identify the repository root");
	std::ifstream input(test_path.substr(0, marker) + relative_path, std::ios::binary);
	Require(input.good(), "community runtime source could not be opened");
	return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void RequireDoesNotContain(const std::string &source, const std::string &needle, const char *message) {
	Require(source.find(needle) == std::string::npos, message);
}

class RecordingTransport final : public HttpTransport {
public:
	std::deque<HttpResponse> responses;
	std::vector<HttpRequest> requests;
	std::function<void(size_t)> on_request;
	std::function<void(size_t)> after_send;

	HttpResponse Send(const HttpRequest &request) override {
		requests.push_back(request);
		if (on_request) {
			on_request(requests.size());
		}
		if (responses.empty()) {
			throw std::runtime_error("unexpected request");
		}
		auto response = responses.front();
		responses.pop_front();
		if (after_send) {
			after_send(requests.size());
		}
		return response;
	}
};

class ScriptedCodec final : public QueryResponseCodec {
public:
	std::deque<QueryResponse> responses;

	QueryResponse Decode(const HttpResponse &) override {
		auto response = responses.front();
		responses.pop_front();
		return response;
	}
};

class ThrowingCodec final : public QueryResponseCodec {
public:
	QueryResponse Decode(const HttpResponse &) override {
		throw std::runtime_error("provider body included a sensitive value");
	}
};

class CancellingSecondCodec final : public QueryResponseCodec {
public:
	std::function<void()> cancel;
	size_t calls = 0;

	explicit CancellingSecondCodec(std::function<void()> cancel_p) : cancel(std::move(cancel_p)) {
	}

	QueryResponse Decode(const HttpResponse &) override {
		calls++;
		if (calls == 1) {
			QueryResponse running;
			running.state = QueryState::RUNNING;
			running.query_id = "query-poll-failure";
			return running;
		}
		cancel();
		throw std::runtime_error("provider response detail");
	}
};

class FakeRuntime final : public RuntimeHooks {
public:
	bool cancelled = false;
	bool cancel_on_sleep = false;
	uint64_t now_ms = 0;
	std::vector<uint64_t> sleeps;

	bool IsCancelled() override {
		return cancelled;
	}
	uint64_t NowMs() override {
		return now_ms;
	}
	void SleepMs(uint64_t milliseconds) override {
		sleeps.push_back(milliseconds);
		now_ms += milliseconds;
		if (cancel_on_sleep) {
			cancelled = true;
		}
	}
};

constexpr const char *REAUTH_MESSAGE = "D360-AUTH-017 REAUTH_REQUIRED: Authorization is required";

void RequireReauth(const std::function<void()> &operation, const char *message) {
	std::string error;
	bool typed = false;
	try {
		operation();
	} catch (const ReauthRequiredException &exception) {
		typed = true;
		error = exception.what();
	}
	Require(typed, message);
	Require(error == REAUTH_MESSAGE, "reauth failure must use the exact stable error");
	Require(error.find("SENSITIVE_PROVIDER_BODY") == std::string::npos,
	        "reauth failure must not expose the provider response body");
}

void TestMapsQueryApi401AtEveryRemoteStageToStableReauth() {
	const HttpResponse unauthorized {401, "SENSITIVE_PROVIDER_BODY token=https://attacker.example/secret"};
	const QueryCredentials credentials {"https://tenant.c360a.salesforce.com", "token"};

	{
		RecordingTransport transport;
		transport.responses.push_back(unauthorized);
		JsonQueryResponseCodec codec;
		FakeRuntime runtime;
		QueryApiV3Client client(transport, codec, runtime);
		RequireReauth([&]() { (void)client.Prepare("select 1", credentials); },
		              "submit 401 must require reauthorization");
	}
	for (const auto &stage : {std::string("status"), std::string("metadata"), std::string("chunk")}) {
		RecordingTransport transport;
		transport.responses.push_back({202, R"({"queryId":"query-auth"})"});
		transport.responses.push_back(stage == "status"
		                                  ? unauthorized
		                                  : HttpResponse {200, R"({"completionStatus":"FINISHED","chunkCount":1,"rowCount":1})"});
		if (stage != "status") {
			transport.responses.push_back(stage == "metadata"
			                                  ? unauthorized
			                                  : HttpResponse {200, R"({"metadata":{"columns":[{"name":"id","type":"varchar","nullable":false}]}})"});
		}
		if (stage == "chunk") transport.responses.push_back(unauthorized);
		JsonQueryResponseCodec codec;
		FakeRuntime runtime;
		QueryApiV3Client client(transport, codec, runtime);
		if (stage == "chunk") {
			auto cursor = std::move(client.Prepare("select id from fixture", credentials)).OpenCursor();
			ResultChunk chunk;
			RequireReauth([&]() { (void)cursor.NextChunk(chunk); }, "chunk 401 must require reauthorization");
		} else {
			RequireReauth([&]() { (void)client.Prepare("select id from fixture", credentials); },
			              stage == "status" ? "status 401 must require reauthorization"
			                                : "metadata 401 must require reauthorization");
		}
	}
	{
		RecordingTransport transport;
		transport.responses.push_back({202, R"({"queryId":"query-arrow-auth"})"});
		transport.responses.push_back({200, R"({"completionStatus":"FINISHED","chunkCount":1,"rowCount":1})"});
		transport.responses.push_back({200, R"({"metadata":{"columns":[{"name":"id","type":"varchar","nullable":false}]}})"});
		transport.responses.push_back(unauthorized);
		JsonQueryResponseCodec codec;
		FakeRuntime runtime;
		QueryApiV3Client client(transport, codec, runtime);
		auto cursor = std::move(client.Prepare("select id from fixture", credentials)).OpenCursor();
		HttpResponse response;
		RequireReauth([&]() { (void)cursor.NextArrowChunk(response); },
		              "Arrow chunk 401 must require reauthorization");
	}
}

void TestMapsOnlyExplicitAuthInvalid403ToStableReauth() {
	JsonQueryResponseCodec codec;
	RequireReauth([&]() {
		(void)codec.Decode({403, R"({"errorCode":"INVALID_SESSION_ID","message":"SENSITIVE_PROVIDER_BODY"})"});
	}, "explicit invalid-session 403 must require reauthorization");
	RequireReauth([&]() {
		(void)codec.Decode({403, R"([{"errorCode":"INVALID_SESSION_ID","message":"SENSITIVE_PROVIDER_BODY"}])"});
	}, "single provider invalid-session array must require reauthorization");

	for (const auto &response : {
	         HttpResponse {403, R"({"errorCode":"INSUFFICIENT_ACCESS","message":"SENSITIVE_PROVIDER_BODY"})"},
	         HttpResponse {403, "SENSITIVE_PROVIDER_BODY"},
	         HttpResponse {500, R"({"errorCode":"INVALID_SESSION_ID"})"},
	     }) {
		std::string error;
		try {
			(void)codec.Decode(response);
		} catch (const ReauthRequiredException &) {
			throw std::runtime_error("non-auth Query API failure was incorrectly classified as reauth");
		} catch (const std::runtime_error &exception) {
			error = exception.what();
		}
		Require(error == "Data 360 Query API request failed", "non-auth status behavior must remain generic");
		Require(error.find("SENSITIVE_PROVIDER_BODY") == std::string::npos,
		        "generic Query API failure must redact provider response bodies");
	}
}

void TestPostsQueryWithoutCredentialsInBody() {
	RecordingTransport transport;
	transport.responses.push_back({200, "complete"});
	ScriptedCodec codec;
	QueryResponse complete;
	complete.state = QueryState::COMPLETE;
	complete.metadata.push_back({"account_id", "VARCHAR", false});
	complete.chunk.rows.push_back({Cell("A-1")});
	codec.responses.push_back(complete);
	FakeRuntime runtime;
	QueryOptions options;
	options.request_timeout_ms = 5000;
	options.overall_timeout_ms = 30000;
	options.poll_interval_ms = 10;
	QueryApiV3Client client(transport, codec, runtime, options);

	auto result = client.Execute("select account_id from accounts", {"https://tenant.c360a.salesforce.com/", "test-token"});

	Require(transport.requests.size() == 1, "expected one request");
	const auto &request = transport.requests[0];
	Require(request.method == "POST", "query must use POST");
	Require(!request.follow_redirects, "authenticated requests must never follow redirects");
	Require(request.url == "https://tenant.c360a.salesforce.com/api/v3/query", "unexpected Query API URL");
	Require(request.headers.at("Authorization") == "Bearer test-token", "missing bearer authorization");
	Require(request.body.find("test-token") == std::string::npos, "credential leaked into request body");
	Require(request.body.find("select account_id from accounts") != std::string::npos, "SQL missing from request body");
	Require(request.body.find("\"transferMode\":\"ASYNC\"") != std::string::npos,
	        "live Query API submission must request asynchronous transfer");
	Require(request.body.find("\"queryRowLimit\":100000") != std::string::npos,
	        "live Query API submission must request a bounded positive row limit");
	Require(result.metadata.size() == 1 && result.chunks.size() == 1, "result metadata/chunk missing");
}

void TestEscapesEveryJsonControlCharacterInSql() {
	RecordingTransport transport;
	transport.responses.push_back({200, "complete"});
	ScriptedCodec codec;
	QueryResponse complete;
	complete.state = QueryState::COMPLETE;
	codec.responses.push_back(complete);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);
	client.Execute(std::string("select '") + '\b' + '\f' + '\0' + "'", {"https://tenant.c360a.salesforce.com", "token"});
	const auto &body = transport.requests[0].body;
	Require(body.find("\\b") != std::string::npos, "backspace must be JSON escaped");
	Require(body.find("\\f") != std::string::npos, "form feed must be JSON escaped");
	Require(body.find("\\u0000") != std::string::npos, "NUL must be JSON escaped");
	Require(body.find('\0') == std::string::npos, "raw NUL must not appear in JSON");
}

void TestNumberedCursorFetchesOneChunkAtATime() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "submitted"});
	transport.responses.push_back({200, "finished"});
	transport.responses.push_back({200, "metadata"});
	transport.responses.push_back({200, "chunk-zero"});
	transport.responses.push_back({200, "chunk-one"});
	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-lazy";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.query_id = "query-lazy";
	finished.chunk_count = 2;
	finished.has_chunk_count = true;
	finished.row_count = 2;
	finished.has_row_count = true;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"id", "varchar", false});
	codec.responses.push_back(metadata);
	for (const auto *value : {"A", "B"}) {
		QueryResponse chunk;
		chunk.state = QueryState::COMPLETE;
		chunk.has_returned_rows = true;
		chunk.returned_rows = 1;
		chunk.chunk.rows.push_back({Cell(value)});
		codec.responses.push_back(chunk);
	}

	QueryApiV3Client client(transport, codec, runtime);
	auto prepared = client.Prepare("select id from fixture",
	                               {"https://tenant.c360a.salesforce.com", "token"});
	Require(prepared.Metadata().size() == 1, "prepare must retain execution metadata");
	Require(transport.requests.size() == 3, "prepare must not fetch numbered chunks");
	auto cursor = std::move(prepared).OpenCursor();
	ResultChunk chunk;
	Require(cursor.NextChunk(chunk), "first numbered chunk must be available");
	Require(transport.requests.size() == 4 && chunk.rows[0][0].value() == "A",
	        "one cursor call must fetch only chunk zero");
	Require(cursor.NextChunk(chunk), "second numbered chunk must be available");
	Require(transport.requests.size() == 5 && chunk.rows[0][0].value() == "B",
	        "second cursor call must fetch only chunk one");
	Require(!cursor.NextChunk(chunk), "cursor must reconcile and finish after advertised chunks");
	Require(transport.requests.size() == 5, "final reconciliation must not issue another GET");
}

void TestRealV3LifecycleFetchesMetadataAndNumberedChunks() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, R"({"queryId":"query-live"})"});
	transport.responses.push_back({200, R"({"completionStatus":"FINISHED","chunkCount":1,"rowCount":1})"});
	transport.responses.push_back({200, R"({"metadata":{"columns":[]}})"});
	transport.responses.push_back({200, R"({"data":[["A-1"]],"returnedRows":1})"});

	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-live";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.chunk_count = 1;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"account_id", "varchar", false});
	codec.responses.push_back(metadata);
	QueryResponse rows;
	rows.state = QueryState::COMPLETE;
	rows.chunk.rows.push_back({Cell("A-1")});
	codec.responses.push_back(rows);

	QueryApiV3Client client(transport, codec, runtime);
	auto result = client.Execute("select account_id from accounts",
	                             {"https://tenant.c360a.salesforce.com", "test-token"});

	Require(transport.requests.size() == 4, "real V3 lifecycle must fetch status, metadata, and chunk zero");
	Require(transport.requests[2].url == "https://tenant.c360a.salesforce.com/api/v3/query/query-live/metadata",
	        "metadata endpoint missing");
	Require(transport.requests[3].url == "https://tenant.c360a.salesforce.com/api/v3/query/query-live/chunks/0",
	        "numbered chunk endpoint missing");
	Require(result.metadata.size() == 1 && result.chunks.size() == 1, "real V3 result was incomplete");
	Require(result.chunks[0].rows[0][0].value() == "A-1", "real V3 row missing");
}

void TestZeroRowV3StillFetchesSchema() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "submitted"});
	transport.responses.push_back({200, "finished"});
	transport.responses.push_back({200, "metadata"});
	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-empty";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.query_id = "query-empty";
	finished.has_chunk_count = true;
	finished.has_row_count = true;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"account_id", "varchar", true});
	codec.responses.push_back(metadata);
	QueryApiV3Client client(transport, codec, runtime);
	auto result = client.Execute("select account_id from empty_table",
	                             {"https://tenant.c360a.salesforce.com", "token"});
	Require(transport.requests.size() == 3 &&
	            transport.requests[2].url == "https://tenant.c360a.salesforce.com/api/v3/query/query-empty/metadata",
	        "zero-row V3 result must fetch metadata");
	Require(result.metadata.size() == 1 && result.chunks.empty(), "zero-row V3 schema must be preserved without rows");
}

void TestMetadataOnlyExecutionDoesNotFetchChunks() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "submitted"});
	transport.responses.push_back({200, "finished"});
	transport.responses.push_back({200, "metadata"});
	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-schema";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.query_id = "query-schema";
	finished.chunk_count = 2;
	finished.has_chunk_count = true;
	finished.row_count = 32;
	finished.has_row_count = true;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"account_id", "varchar", true});
	codec.responses.push_back(metadata);
	QueryApiV3Client client(transport, codec, runtime);
	auto result = client.ExecuteMetadata("select account_id from accounts",
	                                     {"https://tenant.c360a.salesforce.com", "token"});
	Require(transport.requests.size() == 4 && transport.requests[3].method == "DELETE",
	        "metadata-only execution must fetch no chunks and clean up the unopened query");
	Require(transport.requests[0].body.find("\"queryRowLimit\":1") != std::string::npos,
	        "metadata-only execution must request the minimum positive row limit");
	Require(result.metadata.size() == 1 && result.chunks.empty(),
	        "metadata-only execution must preserve schema without materializing rows");
}

void TestPollsAsyncQueryUntilComplete() {
	RecordingTransport transport;
	transport.responses.push_back({202, "accepted"});
	transport.responses.push_back({200, "complete"});
	ScriptedCodec codec;
	QueryResponse running;
	running.state = QueryState::RUNNING;
	running.query_id = "query-123";
	codec.responses.push_back(running);
	QueryResponse complete;
	complete.state = QueryState::COMPLETE;
	complete.metadata.push_back({"count", "BIGINT", false});
	complete.chunk.rows.push_back({Cell("32")});
	codec.responses.push_back(complete);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime, {5000, 30000, 10});

	auto result = client.Execute("select count(*) from fixture", {"https://tenant.c360a.salesforce.com", "token"});

	Require(transport.requests.size() == 2, "expected POST followed by poll");
	Require(transport.requests[1].method == "GET", "poll must use GET");
	Require(transport.requests[1].url == "https://tenant.c360a.salesforce.com/api/v3/query/query-123",
	        "unexpected poll URL");
	Require(runtime.sleeps == std::vector<uint64_t>({10}), "expected configured polling delay");
	Require(result.chunks[0].rows[0][0].value() == "32", "poll result missing");
}

void TestRejectsAdvertisedRowCountMismatch() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "submitted"});
	transport.responses.push_back({200, "finished"});
	transport.responses.push_back({200, "metadata"});
	transport.responses.push_back({200, "chunk"});
	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-count";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.chunk_count = 1;
	finished.row_count = 2;
	finished.has_chunk_count = true;
	finished.has_row_count = true;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"id", "varchar", false});
	codec.responses.push_back(metadata);
	QueryResponse chunk;
	chunk.state = QueryState::COMPLETE;
	chunk.has_returned_rows = true;
	chunk.returned_rows = 1;
	chunk.chunk.rows.push_back({Cell("only-row")});
	codec.responses.push_back(chunk);
	QueryApiV3Client client(transport, codec, runtime);
	bool rejected = false;
	try {
		client.Execute("select id from fixture", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &) {
		rejected = true;
	}
	Require(rejected, "advertised total row count mismatch must be rejected");
}

void TestFetchesAllResultChunks() {
	RecordingTransport transport;
	transport.responses.push_back({200, "first"});
	transport.responses.push_back({200, "second"});
	ScriptedCodec codec;
	QueryResponse first;
	first.state = QueryState::COMPLETE;
	first.metadata.push_back({"id", "VARCHAR", false});
	first.chunk.rows.push_back({Cell("A")});
	first.chunk.next_url = "/api/v3/query/query-123/chunks/1";
	codec.responses.push_back(first);
	QueryResponse second;
	second.state = QueryState::COMPLETE;
	second.chunk.rows.push_back({Cell("B")});
	codec.responses.push_back(second);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);

	auto result = client.Execute("select id from fixture", {"https://tenant.c360a.salesforce.com", "token"});

	Require(transport.requests.size() == 2, "expected chunk request");
	Require(transport.requests[1].url == "https://tenant.c360a.salesforce.com/api/v3/query/query-123/chunks/1",
	        "unexpected chunk URL");
	Require(result.chunks.size() == 2, "all chunks must be retained");
	Require(result.chunks[1].rows[0][0].value() == "B", "second chunk missing");
}

void TestDirectResultsEnforceAggregateBoundsAndCounts() {
	{
		RecordingTransport transport;
		transport.responses.push_back({200, "complete"});
		ScriptedCodec codec;
		QueryResponse complete;
		complete.state = QueryState::COMPLETE;
		complete.metadata.push_back({"id", "VARCHAR", false});
		complete.chunk.rows.push_back({Cell("A")});
		complete.chunk.rows.push_back({Cell("B")});
		codec.responses.push_back(complete);
		FakeRuntime runtime;
		QueryOptions options;
		options.max_rows = 1;
		QueryApiV3Client client(transport, codec, runtime, options);
		bool rejected = false;
		try {
			client.Execute("select id from fixture", {"https://tenant.c360a.salesforce.com", "token"});
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Require(rejected, "direct results must enforce aggregate row limits");
	}
	{
		RecordingTransport transport;
		transport.responses.push_back({200, "complete"});
		ScriptedCodec codec;
		QueryResponse complete;
		complete.state = QueryState::COMPLETE;
		complete.metadata.push_back({"id", "VARCHAR", false});
		complete.chunk.rows.push_back({Cell("A")});
		complete.has_returned_rows = true;
		complete.returned_rows = 2;
		codec.responses.push_back(complete);
		FakeRuntime runtime;
		QueryApiV3Client client(transport, codec, runtime);
		bool rejected = false;
		try {
			client.Execute("select id from fixture", {"https://tenant.c360a.salesforce.com", "token"});
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Require(rejected, "direct results must reconcile returnedRows");
	}
}

void TestRejectsUnsafeResponseDerivedUrls() {
	for (const auto &query_id : {"../escape", "query?leak", "query\nheader"}) {
		RecordingTransport transport;
		transport.responses.push_back({202, "accepted"});
		ScriptedCodec codec;
		QueryResponse running;
		running.state = QueryState::RUNNING;
		running.query_id = query_id;
		codec.responses.push_back(running);
		FakeRuntime runtime;
		QueryApiV3Client client(transport, codec, runtime);
		bool rejected = false;
		try {
			client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Require(rejected && transport.requests.size() == 1, "unsafe query ID must be rejected before reuse");
	}

	RecordingTransport transport;
	transport.responses.push_back({200, "complete"});
	ScriptedCodec codec;
	QueryResponse complete;
	complete.state = QueryState::COMPLETE;
	complete.chunk.next_url = "//attacker.example/chunk";
	codec.responses.push_back(complete);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);
	bool rejected = false;
	try {
		client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &) {
		rejected = true;
	}
	Require(rejected && transport.requests.size() == 1, "unsafe next URL must be rejected before reuse");
}

void TestRejectsFailedChunkAndPaginationCycle() {
	RecordingTransport failed_transport;
	failed_transport.responses.push_back({200, "first"});
	failed_transport.responses.push_back({500, "failed"});
	ScriptedCodec failed_codec;
	QueryResponse first;
	first.state = QueryState::COMPLETE;
	first.chunk.next_url = "/api/v3/query/query-123/chunks/1";
	failed_codec.responses.push_back(first);
	QueryResponse failed;
	failed.state = QueryState::FAILED;
	failed_codec.responses.push_back(failed);
	FakeRuntime failed_runtime;
	QueryApiV3Client failed_client(failed_transport, failed_codec, failed_runtime);
	bool rejected_failed = false;
	try {
		failed_client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &) {
		rejected_failed = true;
	}
	Require(rejected_failed, "failed chunk response must not be appended");

	RecordingTransport cycle_transport;
	cycle_transport.responses.push_back({200, "first"});
	cycle_transport.responses.push_back({200, "cycle"});
	ScriptedCodec cycle_codec;
	cycle_codec.responses.push_back(first);
	QueryResponse cycle;
	cycle.state = QueryState::COMPLETE;
	cycle.chunk.next_url = first.chunk.next_url;
	cycle_codec.responses.push_back(cycle);
	FakeRuntime cycle_runtime;
	QueryApiV3Client cycle_client(cycle_transport, cycle_codec, cycle_runtime);
	bool rejected_cycle = false;
	try {
		cycle_client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &) {
		rejected_cycle = true;
	}
	Require(rejected_cycle && cycle_transport.requests.size() == 3 && cycle_transport.requests[2].method == "DELETE",
	        "pagination cycle must be bounded and cancel remotely");
}

void TestCancellationStopsChunkTraversalBeforeNextRequest() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "first"});
	transport.after_send = [&](size_t sends) {
		if (sends == 1) {
			runtime.cancelled = true;
		}
	};
	ScriptedCodec codec;
	QueryResponse first;
	first.state = QueryState::COMPLETE;
	first.chunk.next_url = "/api/v3/query/query-123/chunks/1";
	codec.responses.push_back(first);
	QueryApiV3Client client(transport, codec, runtime);
	bool cancelled = false;
	try {
		client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &) {
		cancelled = true;
	}
	Require(cancelled && transport.requests.size() == 2, "cancellation must stop chunk traversal and cancel remotely");
	Require(transport.requests[1].method == "DELETE", "chunk traversal cancellation must use DELETE");
}

void TestCancellationBetweenCursorCallsDeletesWithoutNextGet() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "first"});
	transport.responses.push_back({204, ""});
	ScriptedCodec codec;
	QueryResponse first;
	first.state = QueryState::COMPLETE;
	first.query_id = "query-between-calls";
	first.metadata.push_back({"id", "varchar", false});
	first.chunk.rows.push_back({Cell("A")});
	first.chunk.next_url = "/api/v3/query/query-between-calls/chunks/1";
	codec.responses.push_back(first);
	QueryApiV3Client client(transport, codec, runtime);
	auto cursor = std::move(client.Prepare("select id from fixture",
	                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
	ResultChunk chunk;
	Require(cursor.NextChunk(chunk) && transport.requests.size() == 1,
	        "first cursor call must return the buffered chunk");
	runtime.cancelled = true;
	bool cancelled = false;
	try { cursor.NextChunk(chunk); } catch (const std::runtime_error &) { cancelled = true; }
	Require(cancelled && transport.requests.size() == 2,
	        "cancellation between cursor calls must issue cleanup but no next chunk GET");
	Require(transport.requests[1].method == "DELETE" && transport.requests[1].cleanup_request &&
	            transport.requests[1].timeout_ms == 250,
	        "between-call cancellation cleanup must be an independently bounded DELETE");
}

void TestZeroChunkCursorFinalizesWithoutChunkGetOrDelete() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "submitted"});
	transport.responses.push_back({200, "finished"});
	transport.responses.push_back({200, "metadata"});
	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-zero";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.has_chunk_count = true;
	finished.has_row_count = true;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"id", "varchar", true});
	codec.responses.push_back(metadata);
	QueryApiV3Client client(transport, codec, runtime);
	auto prepared = client.Prepare("select id from empty_fixture",
	                               {"https://tenant.c360a.salesforce.com", "token"});
	auto cursor = std::move(prepared).OpenCursor();
	ResultChunk chunk;
	Require(!cursor.NextChunk(chunk), "zero-chunk query must finalize immediately");
	Require(transport.requests.size() == 3, "zero-chunk query must issue no chunk GET or cleanup DELETE");
}

void TestDirectCursorBuffersFirstChunkAndFetchesOneNextUrl() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "first"});
	transport.responses.push_back({200, "second"});
	ScriptedCodec codec;
	QueryResponse first;
	first.state = QueryState::COMPLETE;
	first.metadata.push_back({"id", "varchar", false});
	first.chunk.rows.push_back({Cell("A")});
	first.chunk.next_url = "/api/v3/query/query-direct/chunks/1";
	first.has_row_count = true;
	first.row_count = 2;
	codec.responses.push_back(first);
	QueryResponse second;
	second.state = QueryState::COMPLETE;
	second.chunk.rows.push_back({Cell("B")});
	codec.responses.push_back(second);
	QueryApiV3Client client(transport, codec, runtime);
	auto prepared = client.Prepare("select id from fixture",
	                               {"https://tenant.c360a.salesforce.com", "token"});
	Require(transport.requests.size() == 1, "direct prepare must buffer only the returned first chunk");
	auto cursor = std::move(prepared).OpenCursor();
	ResultChunk chunk;
	Require(cursor.NextChunk(chunk) && chunk.rows[0][0].value() == "A" && transport.requests.size() == 1,
	        "first direct cursor call must consume the buffered chunk without a GET");
	Require(cursor.NextChunk(chunk) && chunk.rows[0][0].value() == "B" && transport.requests.size() == 2,
	        "second direct cursor call must fetch exactly one validated next URL");
	Require(!cursor.NextChunk(chunk) && transport.requests.size() == 2,
	        "direct cursor must reconcile without cleanup after successful exhaustion");
}

void TestConcreteCodecDirectCursorFetchesOneNextUrlPerCall() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({
	    200,
	    R"({"metadata":{"columns":[{"name":"id","type":"varchar","nullable":false}]},"data":[["A"]],"returnedRows":1,"next":"/api/v3/query/query-concrete/chunks/1"})"});
	transport.responses.push_back({200, R"({"data":[["B"]],"returnedRows":1})"});
	JsonQueryResponseCodec codec;
	QueryApiV3Client client(transport, codec, runtime);
	auto prepared = client.Prepare("select id from fixture",
	                               {"https://tenant.c360a.salesforce.com", "token"});
	Require(transport.requests.size() == 1, "concrete direct prepare must buffer its first response");
	auto cursor = std::move(prepared).OpenCursor();
	ResultChunk chunk;
	Require(cursor.NextChunk(chunk) && chunk.rows[0][0].value() == "A" && transport.requests.size() == 1,
	        "concrete direct first cursor call must not fetch its next URL");
	Require(cursor.NextChunk(chunk) && chunk.rows[0][0].value() == "B" && transport.requests.size() == 2,
	        "concrete direct second cursor call must fetch exactly one next URL");
	Require(!cursor.NextChunk(chunk) && transport.requests.size() == 2,
	        "concrete direct cursor must finish without an extra GET");
}

void TestRejectsQueryIdentityDriftAcrossLifecycle() {
	const QueryCredentials credentials {"https://tenant.c360a.salesforce.com", "token"};
	const auto require_rejected = [&](std::deque<QueryResponse> responses, const char *message) {
		FakeRuntime runtime;
		RecordingTransport transport;
		for (size_t index = 0; index < responses.size() + 1; index++) transport.responses.push_back({200, "response"});
		ScriptedCodec codec;
		codec.responses = std::move(responses);
		bool rejected = false;
		try {
			QueryApiV3Client client(transport, codec, runtime);
			auto prepared = client.Prepare("select id from fixture", credentials);
			auto cursor = std::move(prepared).OpenCursor();
			ResultChunk chunk;
			while (cursor.NextChunk(chunk)) {
			}
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Require(rejected, message);
	};

	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-a";
	QueryResponse mismatched_poll;
	mismatched_poll.state = QueryState::COMPLETE;
	mismatched_poll.query_id = "query-b";
	mismatched_poll.has_chunk_count = true;
	mismatched_poll.has_row_count = true;
	require_rejected({submitted, mismatched_poll, QueryResponse {QueryState::COMPLETE, "", "", 0, 0, false,
	                                                            false, 0, false, {{"id", "varchar", false}}, {}}},
	                 "poll response must not change query identity");

	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.query_id = "query-a";
	finished.has_chunk_count = true;
	finished.chunk_count = 1;
	finished.has_row_count = true;
	finished.row_count = 0;
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"id", "varchar", false});
	QueryResponse mismatched_chunk;
	mismatched_chunk.state = QueryState::COMPLETE;
	mismatched_chunk.query_id = "query-b";
	mismatched_chunk.has_returned_rows = true;
	require_rejected({submitted, finished, metadata, mismatched_chunk},
	                 "numbered chunk response must not change query identity");

	QueryResponse direct;
	direct.state = QueryState::COMPLETE;
	direct.query_id = "query-a";
	direct.metadata.push_back({"id", "varchar", false});
	direct.chunk.rows.push_back({Cell("A")});
	direct.chunk.next_url = "/api/v3/query/query-b/chunks/1";
	direct.has_returned_rows = true;
	direct.returned_rows = 1;
	QueryResponse direct_terminal;
	direct_terminal.state = QueryState::COMPLETE;
	direct_terminal.chunk.rows.push_back({Cell("terminal")});
	direct_terminal.has_returned_rows = true;
	direct_terminal.returned_rows = 1;
	require_rejected({direct, direct_terminal}, "initial direct pagination path must match query identity");

	QueryResponse direct_first;
	direct_first.state = QueryState::COMPLETE;
	direct_first.query_id = "query-a";
	direct_first.metadata.push_back({"id", "varchar", false});
	direct_first.chunk.rows.push_back({Cell("A")});
	direct_first.chunk.next_url = "/api/v3/query/query-a/chunks/1";
	direct_first.has_returned_rows = true;
	direct_first.returned_rows = 1;
	QueryResponse direct_second;
	direct_second.state = QueryState::COMPLETE;
	direct_second.chunk.rows.push_back({Cell("B")});
	direct_second.chunk.next_url = "/api/v3/query/query-b/chunks/2";
	direct_second.has_returned_rows = true;
	direct_second.returned_rows = 1;
	QueryResponse direct_third;
	direct_third.state = QueryState::COMPLETE;
	direct_third.chunk.rows.push_back({Cell("C")});
	direct_third.has_returned_rows = true;
	direct_third.returned_rows = 1;
	require_rejected({direct_first, direct_second, direct_third},
	                 "subsequent direct pagination path must match query identity");
}

void TestConcreteCodecRejectsMalformedAdvertisedCounts() {
	JsonQueryResponseCodec codec;
	for (const auto *body : {
	         R"({"completionStatus":"FINISHED","chunkCount":-1,"rowCount":0})",
	         R"({"completionStatus":"FINISHED","chunkCount":1.5,"rowCount":0})",
	         R"({"completionStatus":"FINISHED","chunkCount":18446744073709551616,"rowCount":0})",
	         R"({"completionStatus":"FINISHED","chunkCount":"1","rowCount":0})",
	         R"({"completionStatus":"FINISHED","chunkCount":1,"rowCount":-1})",
	         R"({"completionStatus":"FINISHED","chunkCount":1,"rowCount":1.5})",
	         R"({"completionStatus":"FINISHED","chunkCount":1,"rowCount":18446744073709551616})",
	         R"({"completionStatus":"FINISHED","chunkCount":1,"rowCount":"1"})",
	         R"({"data":[],"returnedRows":-1})",
	         R"({"data":[],"returnedRows":1.5})",
	         R"({"data":[],"returnedRows":18446744073709551616})",
	         R"({"data":[],"returnedRows":"0"})"}) {
		bool rejected = false;
		try {
			(void)codec.Decode({200, body});
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		Require(rejected, "present malformed count fields must fail closed");
	}
}

void TestConcreteCodecRequiresValidNumericShape() {
	JsonQueryResponseCodec codec;
	auto decoded = codec.Decode({200, R"({"metadata":{"columns":[{"name":"amount","type":"numeric","nullable":true,"precision":18,"scale":4}]}})"});
	Require(decoded.metadata.size() == 1 && decoded.metadata[0].has_precision && decoded.metadata[0].precision == 18 &&
	            decoded.metadata[0].has_scale && decoded.metadata[0].scale == 4,
	        "numeric precision and scale must be preserved authoritatively");
	for (const auto *body : {
	         R"({"metadata":{"columns":[{"name":"amount","type":"numeric","nullable":true,"precision":18}]}})",
	         R"({"metadata":{"columns":[{"name":"amount","type":"numeric","nullable":true,"precision":"18","scale":4}]}})",
	         R"({"metadata":{"columns":[{"name":"amount","type":"numeric","nullable":true,"precision":39,"scale":4}]}})",
	         R"({"metadata":{"columns":[{"name":"amount","type":"numeric","nullable":true,"precision":18,"scale":19}]}})",
	         R"({"metadata":{"columns":[{"name":"id","type":"bigint","nullable":false,"precision":18,"scale":0}]}})"}) {
		bool rejected = false;
		try { (void)codec.Decode({200, body}); } catch (const std::runtime_error &) { rejected = true; }
		Require(rejected, "malformed or unexpected decimal shape must fail closed");
	}
}

void TestArrowCursorScopesAcceptAndRequiresOneReport() {
	FakeRuntime runtime;
	RecordingTransport transport;
	for (const auto *body : {"submitted", "finished", "metadata", "arrow-zero", "arrow-one"})
		transport.responses.push_back({200, body, {{"Content-Type", "application/vnd.apache.arrow.stream"}}});
	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-arrow";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.has_chunk_count = true;
	finished.chunk_count = 2;
	finished.has_row_count = true;
	finished.row_count = 1;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"amount", "numeric", true, true, true, 18, 4});
	codec.responses.push_back(metadata);
	QueryApiV3Client client(transport, codec, runtime);
	auto cursor = std::move(client.Prepare("select amount from fixture",
	                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
	Require(cursor.IsNumberedV3(), "completed numbered query must expose Arrow mode");
	HttpResponse response;
	Require(cursor.NextArrowChunk(response) && response.body == "arrow-zero",
	        "first raw Arrow response must remain process-local");
	Require(transport.requests.size() == 4 &&
	            transport.requests.back().headers.at("Accept") == "application/vnd.apache.arrow.stream",
	        "only numbered chunk GET must request Arrow");
	for (size_t index = 0; index < 3; index++) {
		Require(transport.requests[index].headers.at("Accept") == "application/json",
		        "submit, poll, and metadata must remain JSON");
	}
	bool outstanding_rejected = false;
	try { cursor.NextArrowChunk(response); } catch (const std::logic_error &) { outstanding_rejected = true; }
	Require(outstanding_rejected && transport.requests.size() == 4,
	        "next GET must not occur before the prior response is reported");
	bool mixed_cursor_rejected = false;
	ResultChunk json_chunk;
	try { cursor.NextChunk(json_chunk); } catch (const std::logic_error &) { mixed_cursor_rejected = true; }
	Require(mixed_cursor_rejected && transport.requests.size() == 4,
	        "JSON cursor path must not bypass an outstanding Arrow response");
	cursor.ReportArrowChunk(0);
	Require(cursor.NextArrowChunk(response) && transport.requests.size() == 5,
	        "empty Arrow chunk must reconcile exactly once before next GET");
	cursor.ReportArrowChunk(1);
	Require(!cursor.NextArrowChunk(response), "reported rows and chunks must reconcile at EOS");
}

void TestCursorReturnsAtMostOneNumberedChunkPerCall() {
	FakeRuntime runtime;
	RecordingTransport transport;
	for (const auto *body : {"submitted", "finished", "metadata", "empty", "rows"})
		transport.responses.push_back({200, body});
	ScriptedCodec codec;
	QueryResponse submitted;
	submitted.state = QueryState::RUNNING;
	submitted.query_id = "query-empty-middle";
	codec.responses.push_back(submitted);
	QueryResponse finished;
	finished.state = QueryState::COMPLETE;
	finished.has_chunk_count = true;
	finished.chunk_count = 2;
	finished.has_row_count = true;
	finished.row_count = 1;
	codec.responses.push_back(finished);
	QueryResponse metadata;
	metadata.state = QueryState::COMPLETE;
	metadata.metadata.push_back({"id", "varchar", false});
	codec.responses.push_back(metadata);
	QueryResponse empty;
	empty.state = QueryState::COMPLETE;
	empty.has_returned_rows = true;
	codec.responses.push_back(empty);
	QueryResponse rows;
	rows.state = QueryState::COMPLETE;
	rows.chunk.rows.push_back({Cell("after-empty")});
	codec.responses.push_back(rows);
	QueryApiV3Client client(transport, codec, runtime);
	auto cursor = std::move(client.Prepare("select id from fixture",
	                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
	ResultChunk chunk;
	Require(cursor.NextChunk(chunk) && chunk.rows.empty(),
	        "an empty numbered chunk must be returned without fetching the following chunk");
	Require(transport.requests.size() == 4,
	        "one cursor call must issue at most one numbered chunk GET");
	Require(cursor.NextChunk(chunk) && chunk.rows[0][0].value() == "after-empty",
	        "the next cursor call must fetch the following numbered chunk");
	Require(transport.requests.size() == 5,
	        "the second cursor call must issue exactly one additional numbered chunk GET");
	Require(!cursor.NextChunk(chunk), "cursor must finalize after empty and non-empty chunks reconcile");
}

void TestCursorAppliesIncrementalBoundsAndCountChecks() {
	{
		FakeRuntime runtime;
		RecordingTransport transport;
		for (const auto *body : {"submitted", "finished", "metadata", "one", "two", "delete"})
			transport.responses.push_back({200, body});
		ScriptedCodec codec;
		QueryResponse submitted;
		submitted.state = QueryState::RUNNING;
		submitted.query_id = "query-rows";
		codec.responses.push_back(submitted);
		QueryResponse finished;
		finished.state = QueryState::COMPLETE;
		finished.has_chunk_count = true;
		finished.chunk_count = 2;
		codec.responses.push_back(finished);
		QueryResponse metadata;
		metadata.state = QueryState::COMPLETE;
		metadata.metadata.push_back({"id", "varchar", false});
		codec.responses.push_back(metadata);
		for (const auto *value : {"A", "B"}) {
			QueryResponse rows;
			rows.state = QueryState::COMPLETE;
			rows.chunk.rows.push_back({Cell(value)});
			codec.responses.push_back(rows);
		}
		QueryOptions options;
		options.max_rows = 1;
		QueryApiV3Client client(transport, codec, runtime, options);
		auto cursor = std::move(client.Prepare("select id from fixture",
		                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
		ResultChunk chunk;
		Require(cursor.NextChunk(chunk), "first row within cumulative limit must be returned");
		bool rejected = false;
		try { cursor.NextChunk(chunk); } catch (const std::runtime_error &) { rejected = true; }
		Require(rejected && transport.requests.back().method == "DELETE",
		        "cumulative row overflow must fail incrementally and cancel");
	}
	{
		FakeRuntime runtime;
		RecordingTransport transport;
		for (const auto *body : {"submitted", "finished", "metadata", "chunk", "delete"})
			transport.responses.push_back({200, body});
		ScriptedCodec codec;
		QueryResponse submitted;
		submitted.state = QueryState::RUNNING;
		submitted.query_id = "query-width";
		codec.responses.push_back(submitted);
		QueryResponse finished;
		finished.state = QueryState::COMPLETE;
		finished.has_chunk_count = true;
		finished.chunk_count = 1;
		codec.responses.push_back(finished);
		QueryResponse metadata;
		metadata.state = QueryState::COMPLETE;
		metadata.metadata.push_back({"id", "varchar", false});
		codec.responses.push_back(metadata);
		QueryResponse bad;
		bad.state = QueryState::COMPLETE;
		bad.has_returned_rows = true;
		bad.returned_rows = 1;
		bad.chunk.rows.push_back({Cell("A"), Cell("extra")});
		codec.responses.push_back(bad);
		QueryApiV3Client client(transport, codec, runtime);
		auto cursor = std::move(client.Prepare("select id from fixture",
		                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
		ResultChunk chunk;
		bool rejected = false;
		try { cursor.NextChunk(chunk); } catch (const std::runtime_error &) { rejected = true; }
		Require(rejected && transport.requests.back().method == "DELETE",
		        "row-width mismatch with matching returnedRows must reject before yielding and cancel");
	}
	{
		FakeRuntime runtime;
		RecordingTransport transport;
		for (const auto *body : {"submitted", "finished", "metadata", "chunk", "delete"})
			transport.responses.push_back({200, body});
		ScriptedCodec codec;
		QueryResponse submitted;
		submitted.state = QueryState::RUNNING;
		submitted.query_id = "query-total";
		codec.responses.push_back(submitted);
		QueryResponse finished;
		finished.state = QueryState::COMPLETE;
		finished.has_chunk_count = true;
		finished.chunk_count = 1;
		finished.has_row_count = true;
		finished.row_count = 2;
		codec.responses.push_back(finished);
		QueryResponse metadata;
		metadata.state = QueryState::COMPLETE;
		metadata.metadata.push_back({"id", "varchar", false});
		codec.responses.push_back(metadata);
		QueryResponse rows;
		rows.state = QueryState::COMPLETE;
		rows.chunk.rows.push_back({Cell("A")});
		codec.responses.push_back(rows);
		QueryApiV3Client client(transport, codec, runtime);
		auto cursor = std::move(client.Prepare("select id from fixture",
		                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
		ResultChunk chunk;
		Require(cursor.NextChunk(chunk), "last nonempty chunk must be returned before final reconciliation");
		bool rejected = false;
		try { cursor.NextChunk(chunk); } catch (const std::runtime_error &) { rejected = true; }
		Require(rejected && transport.requests.back().method == "DELETE",
		        "advertised total mismatch must fail on finalization and cancel");
	}
}

void TestCursorEnforcesCumulativeResponseBytesAndSchemaDrift() {
	{
		FakeRuntime runtime;
		RecordingTransport transport;
		for (const auto *body : {"aaaa", "bbbb", "cccc", "123456789", "delete"})
			transport.responses.push_back({200, body});
		ScriptedCodec codec;
		QueryResponse submitted;
		submitted.state = QueryState::RUNNING;
		submitted.query_id = "query-bytes";
		codec.responses.push_back(submitted);
		QueryResponse finished;
		finished.state = QueryState::COMPLETE;
		finished.has_chunk_count = true;
		finished.chunk_count = 1;
		codec.responses.push_back(finished);
		QueryResponse metadata;
		metadata.state = QueryState::COMPLETE;
		metadata.metadata.push_back({"id", "varchar", false});
		codec.responses.push_back(metadata);
		QueryResponse rows;
		rows.state = QueryState::COMPLETE;
		rows.chunk.rows.push_back({Cell("A")});
		codec.responses.push_back(rows);
		QueryOptions options;
		options.max_total_response_bytes = 20;
		QueryApiV3Client client(transport, codec, runtime, options);
		auto cursor = std::move(client.Prepare("select id from fixture",
		                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
		ResultChunk chunk;
		bool rejected = false;
		try { cursor.NextChunk(chunk); } catch (const std::runtime_error &) { rejected = true; }
		Require(rejected && transport.requests[3].max_response_bytes == 8 && transport.requests.back().method == "DELETE",
		        "cumulative byte budget must shrink each chunk request and cancel on overflow");
	}
	{
		FakeRuntime runtime;
		RecordingTransport transport;
		for (const auto *body : {"submitted", "finished", "metadata", "chunk", "delete"})
			transport.responses.push_back({200, body});
		ScriptedCodec codec;
		QueryResponse submitted;
		submitted.state = QueryState::RUNNING;
		submitted.query_id = "query-drift";
		codec.responses.push_back(submitted);
		QueryResponse finished;
		finished.state = QueryState::COMPLETE;
		finished.has_chunk_count = true;
		finished.chunk_count = 1;
		codec.responses.push_back(finished);
		QueryResponse metadata;
		metadata.state = QueryState::COMPLETE;
		metadata.metadata.push_back({"id", "varchar", false});
		codec.responses.push_back(metadata);
		QueryResponse drift;
		drift.state = QueryState::COMPLETE;
		drift.metadata.push_back({"renamed", "varchar", false});
		drift.chunk.rows.push_back({Cell("A")});
		codec.responses.push_back(drift);
		QueryApiV3Client client(transport, codec, runtime);
		auto cursor = std::move(client.Prepare("select id from fixture",
		                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
		ResultChunk chunk;
		bool rejected = false;
		try { cursor.NextChunk(chunk); } catch (const std::runtime_error &) { rejected = true; }
		Require(rejected && transport.requests.back().method == "DELETE",
		        "repeated metadata drift must reject before yielding and cancel");
	}
}

void TestPrepareRejectsAdvertisedChunkLimitAndCursorRejectsCellLimit() {
	{
		FakeRuntime runtime;
		RecordingTransport transport;
		transport.responses.push_back({200, "submitted"});
		transport.responses.push_back({200, "finished"});
		transport.responses.push_back({204, ""});
		ScriptedCodec codec;
		QueryResponse submitted;
		submitted.state = QueryState::RUNNING;
		submitted.query_id = "query-too-many";
		codec.responses.push_back(submitted);
		QueryResponse finished;
		finished.state = QueryState::COMPLETE;
		finished.has_chunk_count = true;
		finished.chunk_count = 2;
		codec.responses.push_back(finished);
		QueryOptions options;
		options.max_chunks = 1;
		QueryApiV3Client client(transport, codec, runtime, options);
		bool rejected = false;
		try { client.Prepare("select id from fixture", {"https://tenant.c360a.salesforce.com", "token"}); }
		catch (const std::runtime_error &) { rejected = true; }
		Require(rejected && transport.requests.size() == 3 && transport.requests[2].method == "DELETE",
		        "advertised chunk limit must fail before metadata/chunk fetch and cancel");
	}
	{
		FakeRuntime runtime;
		RecordingTransport transport;
		for (const auto *body : {"submitted", "finished", "metadata", "chunk", "delete"})
			transport.responses.push_back({200, body});
		ScriptedCodec codec;
		QueryResponse submitted;
		submitted.state = QueryState::RUNNING;
		submitted.query_id = "query-cells";
		codec.responses.push_back(submitted);
		QueryResponse finished;
		finished.state = QueryState::COMPLETE;
		finished.has_chunk_count = true;
		finished.chunk_count = 1;
		codec.responses.push_back(finished);
		QueryResponse metadata;
		metadata.state = QueryState::COMPLETE;
		metadata.metadata.push_back({"left", "varchar", false});
		metadata.metadata.push_back({"right", "varchar", false});
		codec.responses.push_back(metadata);
		QueryResponse rows;
		rows.state = QueryState::COMPLETE;
		rows.chunk.rows.push_back({Cell("A"), Cell("B")});
		codec.responses.push_back(rows);
		QueryOptions options;
		options.max_cells = 1;
		QueryApiV3Client client(transport, codec, runtime, options);
		auto cursor = std::move(client.Prepare("select left, right from fixture",
		                                      {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor();
		ResultChunk chunk;
		bool rejected = false;
		try { cursor.NextChunk(chunk); } catch (const std::runtime_error &) { rejected = true; }
		Require(rejected && transport.requests.back().method == "DELETE",
		        "incremental cell overflow must reject before yielding and cancel");
	}
}

void TestPreparedAndCursorDestructorsCancelExactlyOnce() {
	for (const bool open_cursor : {false, true}) {
		FakeRuntime runtime;
		RecordingTransport transport;
		transport.responses.push_back({200, "complete"});
		transport.responses.push_back({204, ""});
		ScriptedCodec codec;
		QueryResponse complete;
		complete.state = QueryState::COMPLETE;
		complete.query_id = "query-abandon";
		complete.metadata.push_back({"id", "varchar", false});
		codec.responses.push_back(complete);
		QueryApiV3Client client(transport, codec, runtime);
		{
			auto prepared = client.Prepare("select id from fixture",
			                               {"https://tenant.c360a.salesforce.com", "token"});
			if (open_cursor) {
				auto cursor = std::move(prepared).OpenCursor();
			}
		}
		Require(transport.requests.size() == 2 && transport.requests[1].method == "DELETE" &&
		            transport.requests[1].cleanup_request && transport.requests[1].timeout_ms == 250,
		        "abandoned prepared query or cursor must issue exactly one independently bounded DELETE");
	}
}

void TestDefinesArrowReadyScalarMappings() {
	const auto decimal = MapData360Type("DECIMAL(18,2)");
	Require(decimal.duckdb_type == "DECIMAL(18,2)", "decimal precision/scale must be preserved");
	Require(decimal.arrow_format == "d:18,2", "decimal Arrow C format missing");
	const auto timestamp = MapData360Type("TIMESTAMP_WITH_TIME_ZONE");
	Require(timestamp.duckdb_type == "TIMESTAMPTZ", "timestamp must map to DuckDB TIMESTAMPTZ");
	Require(timestamp.arrow_format == "tsu:UTC", "timestamp Arrow C format missing");
	const auto unknown = MapData360Type("FUTURE_TYPE");
	Require(unknown.duckdb_type == "VARCHAR" && unknown.lossy, "unknown types must safely fall back to VARCHAR");
	Require(MapData360Type("bool").duckdb_type == "BOOLEAN", "live bool metadata must bind BOOLEAN");
	Require(MapData360Type("numeric").duckdb_type == "DECIMAL(38,18)",
	        "live numeric metadata must bind its fixture decimal shape");
	Require(MapData360Type("timestamptz").duckdb_type == "TIMESTAMPTZ",
	        "live timestamptz metadata must retain timezone semantics");
}

void TestRejectsDecimalMappingsOutsideDuckDbBounds() {
	Require(!MapData360Type("DECIMAL(38,38)").lossy, "DuckDB precision 38 boundary must be supported");
	Require(MapData360Type("DECIMAL(39,2)").lossy, "precision above 38 must fall back safely");
	Require(MapData360Type("DECIMAL(10,11)").lossy, "scale above precision must fall back safely");
	Require(MapData360Type("DECIMAL(0,0)").lossy, "zero precision must fall back safely");
}

void TestRejectsUntrustedTenantUrlBeforeSendingToken() {
	RecordingTransport transport;
	ScriptedCodec codec;
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);
	bool rejected = false;
	try {
		client.Execute("select 1", {"https://attacker.example", "test-token"});
	} catch (const std::invalid_argument &) {
		rejected = true;
	}
	Require(rejected, "untrusted tenant URL must be rejected");
	Require(transport.requests.empty(), "token must not be sent to an untrusted tenant URL");
}

void TestRejectsAmbiguousTenantOriginsBeforeSendingToken() {
	const std::vector<std::string> unsafe_origins = {
	    "https://tenant.c360a.salesforce.com\\attacker.example",
	    "https://tenant%2ec360a.salesforce.com",
	    "https://tenant.c360a.salesforce.com\nattacker.example",
	    "https://tenant..c360a.salesforce.com",
	    "https://-tenant.c360a.salesforce.com",
	};
	for (const auto &origin : unsafe_origins) {
		RecordingTransport transport;
		ScriptedCodec codec;
		FakeRuntime runtime;
		QueryApiV3Client client(transport, codec, runtime);
		bool rejected = false;
		try {
			client.Execute("select 1", {origin, "test-token"});
		} catch (const std::invalid_argument &) {
			rejected = true;
		}
		Require(rejected, "ambiguous tenant origin must be rejected");
		Require(transport.requests.empty(), "token must not be sent to an ambiguous tenant origin");
	}
}

void TestCancelsRemoteJobWhenLocalQueryIsCancelled() {
	RecordingTransport transport;
	transport.responses.push_back({202, "accepted"});
	transport.responses.push_back({204, ""});
	ScriptedCodec codec;
	QueryResponse running;
	running.state = QueryState::RUNNING;
	running.query_id = "query-123";
	codec.responses.push_back(running);
	FakeRuntime runtime;
	runtime.cancel_on_sleep = true;
	QueryApiV3Client client(transport, codec, runtime, {5000, 30000, 10});
	bool cancelled = false;
	try {
		client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &) {
		cancelled = true;
	}
	Require(cancelled, "local cancellation must stop the query");
	Require(transport.requests.size() == 2, "remote query cancellation request missing");
	Require(transport.requests[1].method == "DELETE", "remote cancellation must use DELETE");
	Require(transport.requests[1].url == "https://tenant.c360a.salesforce.com/api/v3/query/query-123",
	        "unexpected remote cancellation URL");
	Require(transport.requests[1].cleanup_request && transport.requests[1].timeout_ms == 250,
	        "remote cancellation must use an independent exact cleanup budget");
}

void TestCancelsRemoteJobAtOverallTimeout() {
	RecordingTransport transport;
	transport.responses.push_back({202, "accepted"});
	transport.responses.push_back({204, ""});
	ScriptedCodec codec;
	QueryResponse running;
	running.state = QueryState::RUNNING;
	running.query_id = "query-timeout";
	codec.responses.push_back(running);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime, {5000, 10, 10});
	bool timed_out = false;
	try {
		client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &error) {
		timed_out = std::string(error.what()).find("timed out") != std::string::npos;
	}
	Require(timed_out, "overall timeout must stop the query with a sanitized error");
	Require(transport.requests.size() == 2, "timed-out remote query cancellation request missing");
	Require(transport.requests[1].method == "DELETE", "timed-out remote query must use DELETE");
}

void TestEnforcesDeadlineAfterInitialRequest() {
	FakeRuntime runtime;
	RecordingTransport transport;
	transport.responses.push_back({200, "complete"});
	transport.after_send = [&](size_t) { runtime.now_ms = 11; };
	ScriptedCodec codec;
	QueryResponse complete;
	complete.state = QueryState::COMPLETE;
	codec.responses.push_back(complete);
	QueryApiV3Client client(transport, codec, runtime, {5, 10, 1});
	bool timed_out = false;
	try {
		client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &error) {
		timed_out = std::string(error.what()).find("timed out") != std::string::npos;
	}
	Require(timed_out, "initial request completion after deadline must fail");
}

void TestSanitizesTransportAndCodecFailures() {
	RecordingTransport transport;
	ScriptedCodec codec;
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);
	std::string transport_error;
	try {
		client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &error) {
		transport_error = error.what();
	}
	Require(transport_error == "Data 360 transport failed", "transport exception details must be redacted");

	RecordingTransport codec_transport;
	codec_transport.responses.push_back({200, "sensitive-provider-body"});
	ThrowingCodec throwing_codec;
	QueryApiV3Client codec_client(codec_transport, throwing_codec, runtime);
	std::string codec_error;
	try {
		codec_client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &error) {
		codec_error = error.what();
	}
	Require(codec_error == "Data 360 response decoding failed", "codec exception details must be redacted");
}

void TestPollingFailuresPreserveCancellationAndBoundCleanup() {
	FakeRuntime transport_runtime;
	RecordingTransport transport;
	transport.responses.push_back({202, "accepted"});
	transport.on_request = [&](size_t sends) {
		if (sends == 2) {
			transport_runtime.cancelled = true;
		}
	};
	ScriptedCodec codec;
	QueryResponse running;
	running.state = QueryState::RUNNING;
	running.query_id = "query-poll-failure";
	codec.responses.push_back(running);
	QueryApiV3Client transport_client(transport, codec, transport_runtime);
	std::string transport_error;
	try {
		transport_client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &error) {
		transport_error = error.what();
	}
	Require(transport_error == "Data 360 query cancelled", "poll transport failure must preserve cancellation");
	Require(transport.requests.size() == 3 && transport.requests[2].method == "DELETE",
	        "poll transport failure must cancel the known remote query");
	Require(transport.requests[2].timeout_ms <= 250, "cleanup request must use a small bounded timeout");

	FakeRuntime codec_runtime;
	RecordingTransport codec_transport;
	codec_transport.responses.push_back({202, "accepted"});
	codec_transport.responses.push_back({200, "poll"});
	CancellingSecondCodec cancelling_codec([&]() { codec_runtime.cancelled = true; });
	QueryApiV3Client codec_client(codec_transport, cancelling_codec, codec_runtime);
	std::string codec_error;
	try {
		codec_client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &error) {
		codec_error = error.what();
	}
	Require(codec_error == "Data 360 query cancelled", "poll codec failure must preserve cancellation");
	Require(codec_transport.requests.size() == 3 && codec_transport.requests[2].method == "DELETE",
	        "poll codec failure must cancel the known remote query");
	Require(codec_transport.requests[2].timeout_ms <= 250, "codec cleanup request must be bounded");

	FakeRuntime successful_poll_runtime;
	RecordingTransport successful_poll_transport;
	successful_poll_transport.responses.push_back({202, "accepted"});
	successful_poll_transport.responses.push_back({200, "complete"});
	successful_poll_transport.after_send = [&](size_t sends) {
		if (sends == 2) {
			successful_poll_runtime.cancelled = true;
		}
	};
	ScriptedCodec successful_poll_codec;
	successful_poll_codec.responses.push_back(running);
	QueryResponse complete_without_id;
	complete_without_id.state = QueryState::COMPLETE;
	successful_poll_codec.responses.push_back(complete_without_id);
	QueryApiV3Client successful_poll_client(successful_poll_transport, successful_poll_codec, successful_poll_runtime);
	std::string successful_poll_error;
	try {
		successful_poll_client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	} catch (const std::runtime_error &error) {
		successful_poll_error = error.what();
	}
	Require(successful_poll_error == "Data 360 query cancelled", "successful poll must preserve cancellation");
	Require(successful_poll_transport.requests.size() == 3 && successful_poll_transport.requests[2].method == "DELETE",
	        "successful poll without a repeated ID must cancel the retained remote query ID");
	Require(successful_poll_transport.requests[2].url ==
	            "https://tenant.c360a.salesforce.com/api/v3/query/query-poll-failure",
	        "cleanup DELETE must target the retained remote query ID");
}

void TestRejectsInvalidQueryOptions() {
	RecordingTransport transport;
	ScriptedCodec codec;
	FakeRuntime runtime;
	bool rejected_zero = false;
	try {
		QueryApiV3Client client(transport, codec, runtime, {0, 100, 10});
	} catch (const std::invalid_argument &) {
		rejected_zero = true;
	}
	Require(rejected_zero, "zero request timeout must be rejected");
	bool rejected_poll = false;
	try {
		QueryApiV3Client client(transport, codec, runtime, {10, 10, 11});
	} catch (const std::invalid_argument &) {
		rejected_poll = true;
	}
	Require(rejected_poll, "poll interval above overall timeout must be rejected");
}

void TestPreservesExactUnquotedDecimalLexeme() {
	JsonQueryResponseCodec codec;
	HttpResponse response {200, R"({"data":[[12345678901234567890.123456789012345678]]})"};
	auto decoded = codec.Decode(response);
	Require(decoded.chunk.rows.size() == 1 && decoded.chunk.rows[0].size() == 1,
	        "exact decimal row must decode");
	Require(decoded.chunk.rows[0][0] &&
	            *decoded.chunk.rows[0][0] == "12345678901234567890.123456789012345678",
	        "unquoted decimal lexeme must be preserved exactly");
}

void TestDecodesLiveV3HeaderStatusAndCombinedChunks() {
	JsonQueryResponseCodec codec;
	HttpResponse submitted {200, "{}", {{"x-hyperdb-status", R"({"queryId":"query-header"})"}}};
	auto submission = codec.Decode(submitted);
	Require(submission.state == QueryState::RUNNING && submission.query_id == "query-header",
	        "live submission query ID must be decoded from x-hyperdb-status");

	HttpResponse finished {200,
	                       R"({"queryId":"query-header","completionStatus":"FINISHED","chunkCount":1,"rowCount":2})"};
	auto completion = codec.Decode(finished);
	Require(completion.state == QueryState::COMPLETE && completion.chunk_count == 1 && completion.row_count == 2,
	        "queryId in a finished poll must not mask completionStatus");

	HttpResponse combined_chunk {
	    200,
	    R"({"metadata":{"columns":[{"name":"flag","type":"bool","nullable":true}]},"data":[[true],[null]],"returnedRows":2})"};
	auto chunk = codec.Decode(combined_chunk);
	Require(chunk.state == QueryState::COMPLETE && chunk.chunk.rows.size() == 2,
	        "row data must decode when a live chunk repeats metadata");
	Require(chunk.metadata.size() == 1 && chunk.metadata[0].name == "flag" && chunk.metadata[0].nullable,
	        "live chunk must preserve repeated metadata for drift validation");
	Require(chunk.chunk.rows[0][0] && *chunk.chunk.rows[0][0] == "true" && !chunk.chunk.rows[1][0],
	        "live chunk scalars and nulls must decode exactly");

	HttpResponse non_string_next {200, R"({"data":[],"next":123,"nextUrl":"/api/v3/query/ignored/chunks/1"})"};
	auto bounded = codec.Decode(non_string_next);
	Require(bounded.chunk.next_url.empty(),
	        "direct pagination must accept only a string from the bounded provider 'next' field");
}

void TestCommunityRuntimeHasNoExecutableCredentialPath() {
	const auto header = ReadSourceFile("src/include/data360/native_runtime.hpp");
	const auto implementation = ReadSourceFile("src/native_runtime.cpp");
	const auto extension = ReadSourceFile("src/data360_extension.cpp");
	const auto runtime_source = header + implementation + extension;
	for (const auto &symbol : {std::string("Resolve") + "ProcessCapability", std::string("Run") + "Process(",
	                          std::string("Kill") + "AndReap", std::string("Minimal") + "Environment"}) {
		RequireDoesNotContain(runtime_source, symbol, "community runtime retained a process credential symbol");
	}
	for (const auto &dependency : {std::string("/usr/bin/") + "python3", std::string("/usr/bin/") + "curl",
	                              std::string("SOWVI_DATA360_") + "BROKER_PATH"}) {
		RequireDoesNotContain(runtime_source, dependency, "community runtime retained an executable credential dependency");
	}
	for (const auto &header_name : {"<poll.h>", "<spawn.h>", "<sys/socket.h>", "<sys/wait.h>", "<unistd.h>"}) {
		RequireDoesNotContain(implementation, header_name, "native runtime retained a POSIX process header");
	}

	RecordingTransport transport;
	transport.responses.push_back({200, "complete"});
	ScriptedCodec codec;
	QueryResponse complete;
	complete.state = QueryState::COMPLETE;
	codec.responses.push_back(complete);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);
	client.Execute("select 1", {"https://tenant.c360a.salesforce.com", "token"});
	Require(transport.requests.size() == 1,
	        "query execution unexpectedly depended on an external credential executable");
}

} // namespace

int main() {
	try {
		TestMapsQueryApi401AtEveryRemoteStageToStableReauth();
		TestMapsOnlyExplicitAuthInvalid403ToStableReauth();
		TestPostsQueryWithoutCredentialsInBody();
		TestEscapesEveryJsonControlCharacterInSql();
		TestNumberedCursorFetchesOneChunkAtATime();
		TestRealV3LifecycleFetchesMetadataAndNumberedChunks();
		TestZeroRowV3StillFetchesSchema();
		TestMetadataOnlyExecutionDoesNotFetchChunks();
		TestPollsAsyncQueryUntilComplete();
		TestRejectsAdvertisedRowCountMismatch();
		TestFetchesAllResultChunks();
		TestDirectResultsEnforceAggregateBoundsAndCounts();
		TestRejectsUnsafeResponseDerivedUrls();
		TestRejectsFailedChunkAndPaginationCycle();
		TestCancellationStopsChunkTraversalBeforeNextRequest();
		TestCancellationBetweenCursorCallsDeletesWithoutNextGet();
		TestZeroChunkCursorFinalizesWithoutChunkGetOrDelete();
		TestDirectCursorBuffersFirstChunkAndFetchesOneNextUrl();
		TestConcreteCodecDirectCursorFetchesOneNextUrlPerCall();
		TestRejectsQueryIdentityDriftAcrossLifecycle();
		TestConcreteCodecRejectsMalformedAdvertisedCounts();
		TestConcreteCodecRequiresValidNumericShape();
		TestArrowCursorScopesAcceptAndRequiresOneReport();
		TestCursorReturnsAtMostOneNumberedChunkPerCall();
		TestCursorAppliesIncrementalBoundsAndCountChecks();
		TestCursorEnforcesCumulativeResponseBytesAndSchemaDrift();
		TestPrepareRejectsAdvertisedChunkLimitAndCursorRejectsCellLimit();
		TestPreparedAndCursorDestructorsCancelExactlyOnce();
		TestDefinesArrowReadyScalarMappings();
		TestRejectsDecimalMappingsOutsideDuckDbBounds();
		TestRejectsUntrustedTenantUrlBeforeSendingToken();
		TestRejectsAmbiguousTenantOriginsBeforeSendingToken();
		TestCancelsRemoteJobWhenLocalQueryIsCancelled();
		TestCancelsRemoteJobAtOverallTimeout();
		TestEnforcesDeadlineAfterInitialRequest();
		TestSanitizesTransportAndCodecFailures();
		TestPollingFailuresPreserveCancellationAndBoundCleanup();
		TestRejectsInvalidQueryOptions();
		TestPreservesExactUnquotedDecimalLexeme();
		TestDecodesLiveV3HeaderStatusAndCombinedChunks();
		TestCommunityRuntimeHasNoExecutableCredentialPath();
		std::cout << "query_api_test: PASS\n";
		return EXIT_SUCCESS;
	} catch (const std::exception &error) {
		std::cerr << "query_api_test: FAIL: " << error.what() << '\n';
		return EXIT_FAILURE;
	}
}
