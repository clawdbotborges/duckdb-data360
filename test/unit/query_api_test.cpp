#include "data360/query_api.hpp"
#include "data360/native_runtime.hpp"
#include "data360/type_mapping.hpp"

#include <chrono>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace data360;

namespace {

void Require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
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
	QueryApiV3Client client(transport, codec, runtime, {.request_timeout_ms = 5000, .overall_timeout_ms = 30000, .poll_interval_ms = 10});

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
	Require(transport.requests.size() == 3, "metadata-only execution must not fetch result chunks");
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
	Require(rejected_cycle && cycle_transport.requests.size() == 2, "pagination cycle must be bounded");
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
	        "row data must take precedence when a live chunk repeats metadata");
	Require(chunk.chunk.rows[0][0] && *chunk.chunk.rows[0][0] == "true" && !chunk.chunk.rows[1][0],
	        "live chunk scalars and nulls must decode exactly");
}

void TestBrokerSubprocessObservesCancellation() {
	char path[] = "/tmp/data360-cancel-broker-XXXXXX";
	const auto fd = mkstemp(path);
	Require(fd >= 0, "temporary cancellation broker creation failed");
	const std::string script = "import time\ntime.sleep(30)\n";
	Require(write(fd, script.data(), script.size()) == static_cast<ssize_t>(script.size()),
	        "temporary cancellation broker write failed");
	Require(fchmod(fd, 0700) == 0, "temporary cancellation broker permissions failed");
	close(fd);
	std::atomic<bool> cancelled {false};
	SteadyRuntime runtime(&cancelled);
	std::thread canceller([&]() {
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		cancelled.store(true);
	});
	const auto started = std::chrono::steady_clock::now();
	bool rejected = false;
	try {
		ResolveProcessCapability(path, "https://org.my.salesforce.com", &runtime);
	} catch (const std::exception &) {
		rejected = true;
	}
	canceller.join();
	unlink(path);
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
	                         std::chrono::steady_clock::now() - started).count();
	Require(rejected, "cancelled broker subprocess must fail closed");
	Require(elapsed < 2000, "broker subprocess cancellation must be bounded");
}

} // namespace

int main() {
	try {
		TestPostsQueryWithoutCredentialsInBody();
		TestEscapesEveryJsonControlCharacterInSql();
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
		TestBrokerSubprocessObservesCancellation();
		std::cout << "query_api_test: PASS\n";
		return EXIT_SUCCESS;
	} catch (const std::exception &error) {
		std::cerr << "query_api_test: FAIL: " << error.what() << '\n';
		return EXIT_FAILURE;
	}
}
