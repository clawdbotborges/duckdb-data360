#include "data360/scan_runtime.hpp"

#include "duckdb.hpp"

#include <deque>
#include <iostream>
#include <stdexcept>

using namespace data360;
using namespace duckdb;

namespace {

void Require(bool condition, const char *message) {
	if (!condition) throw std::runtime_error(message);
}

ResultChunk Rows(std::initializer_list<std::initializer_list<Cell>> rows) {
	ResultChunk result;
	for (const auto &row : rows) result.rows.emplace_back(row);
	return result;
}

class FakeChunkSource final : public ChunkSource {
public:
	std::deque<ResultChunk> chunks;
	size_t calls = 0;

	bool NextChunk(ResultChunk &result) override {
		calls++;
		if (chunks.empty()) return false;
		result = std::move(chunks.front());
		chunks.pop_front();
		return true;
	}
};

class RecordingTransport final : public HttpTransport {
public:
	std::deque<HttpResponse> responses;
	std::vector<HttpRequest> requests;

	HttpResponse Send(const HttpRequest &request) override {
		requests.push_back(request);
		if (responses.empty()) throw std::runtime_error("unexpected request");
		auto response = responses.front();
		responses.pop_front();
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

class FakeRuntime final : public RuntimeHooks {
public:
	bool IsCancelled() override { return false; }
	uint64_t NowMs() override { return 0; }
	void SleepMs(uint64_t) override {}
};

void InitOutput(DataChunk &output, const vector<LogicalType> &types) {
	output.Initialize(Allocator::DefaultAllocator(), types);
}

void TestLargeRemoteChunkIsRetainedAcrossVectors() {
	FakeChunkSource source;
	ResultChunk large;
	for (idx_t row = 0; row < STANDARD_VECTOR_SIZE + 1; row++) {
		large.rows.push_back({Cell(std::to_string(row))});
	}
	source.chunks.push_back(std::move(large));
	ScanBuffer buffer;
	vector<LogicalType> types {LogicalType::BIGINT};
	vector<string> names {"id"};
	DataChunk first;
	InitOutput(first, types);
	FillDataChunk(source, buffer, types, names, first);
	Require(first.size() == STANDARD_VECTOR_SIZE && source.calls == 1,
	        "one vector must not fetch beyond an unconsumed remote chunk");
	DataChunk second;
	InitOutput(second, types);
	FillDataChunk(source, buffer, types, names, second);
	Require(second.size() == 1 && second.GetValue(0, 0).GetValue<int64_t>() == STANDARD_VECTOR_SIZE,
	        "the retained remote row must fill the next vector");
	Require(source.calls == 2 && buffer.exhausted, "next remote fetch must occur only after chunk exhaustion");
}

void TestSmallAndEmptyChunksFillOneVectorUntilTrueEof() {
	FakeChunkSource source;
	source.chunks.push_back({});
	source.chunks.push_back(Rows({{Cell("1")}, {Cell("2")}}));
	source.chunks.push_back({});
	source.chunks.push_back(Rows({{Cell("3")}}));
	ScanBuffer buffer;
	vector<LogicalType> types {LogicalType::INTEGER};
	vector<string> names {"id"};
	DataChunk output;
	InitOutput(output, types);
	FillDataChunk(source, buffer, types, names, output);
	Require(output.size() == 3 && source.calls == 5 && buffer.exhausted,
	        "small and empty chunks must be consumed until true EOF without premature zero cardinality");
	Require(output.GetValue(0, 2).GetValue<int32_t>() == 3, "rows after empty chunks must be retained");
}

void TestTypedNullAndExactDecimalConversion() {
	FakeChunkSource source;
	source.chunks.push_back(Rows({{Cell(), Cell("12345678901234567890.123456789012345678")}}));
	ScanBuffer buffer;
	vector<LogicalType> types {LogicalType::INTEGER, LogicalType::DECIMAL(38, 18)};
	vector<string> names {"nullable_id", "amount"};
	DataChunk output;
	InitOutput(output, types);
	FillDataChunk(source, buffer, types, names, output);
	Require(output.GetValue(0, 0).IsNull() && output.GetValue(0, 0).type() == LogicalType::INTEGER,
	        "null must retain the bound DuckDB type");
	Require(output.GetValue(1, 0).ToString() == "12345678901234567890.123456789012345678",
	        "decimal conversion must preserve the exact source string");
}

void TestBadConversionFailsWithColumnContext() {
	RecordingTransport transport;
	transport.responses.push_back({200, "direct"});
	transport.responses.push_back({204, ""});
	ScriptedCodec codec;
	QueryResponse direct;
	direct.state = QueryState::COMPLETE;
	direct.query_id = "query-bad-conversion";
	direct.metadata.push_back({"account_count", "integer", false});
	direct.chunk.rows.push_back({Cell("not-an-integer")});
	codec.responses.push_back(direct);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);
	std::string error;
	{
		CursorChunkSource source(std::move(client.Prepare(
		    "select account_count from fixture",
		    {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor());
		ScanBuffer buffer;
		vector<LogicalType> types {LogicalType::INTEGER};
		vector<string> names {"account_count"};
		DataChunk output;
		InitOutput(output, types);
		try {
			FillDataChunk(source, buffer, types, names, output);
		} catch (const InvalidInputException &exception) {
			error = exception.what();
		}
		Require(error.find("account_count") != std::string::npos,
		        "bad conversion must fail with sanitized bound-column context");
	}
	Require(transport.requests.size() == 2 && transport.requests[1].method == "DELETE" &&
	            transport.requests[1].cleanup_request && transport.requests[1].timeout_ms == 250,
	        "bad conversion must destroy the unfinished cursor and issue bounded cleanup");
}

void TestMetadataCompatibilityRejectsBindExecutionDrift() {
	const std::vector<ColumnMetadata> bound {{"amount", "numeric", true, true, true, 18, 4}};
	Require(MetadataCompatible(bound, bound), "identical execution metadata must remain compatible");
	Require(!MetadataCompatible(bound, {{"renamed", "numeric", true}}), "column-name drift must be rejected");
	Require(!MetadataCompatible(bound, {{"amount", "varchar", true}}), "column-type drift must be rejected");
	Require(!MetadataCompatible(bound, {{"amount", "numeric", false}}), "nullability drift must be rejected");
	Require(!MetadataCompatible(bound, {{"amount", "numeric", true, true, true, 19, 4}}),
	        "decimal precision drift must be rejected");
	Require(!MetadataCompatible(bound, {{"amount", "numeric", true, true, true, 18, 5}}),
	        "decimal scale drift must be rejected");
}

void TestSourceDestructionCleansUpAfterEarlyStop() {
	RecordingTransport transport;
	transport.responses.push_back({200, "direct"});
	transport.responses.push_back({204, ""});
	ScriptedCodec codec;
	QueryResponse direct;
	direct.state = QueryState::COMPLETE;
	direct.query_id = "query-early-stop";
	direct.metadata.push_back({"id", "integer", false});
	direct.chunk.rows = {{Cell("1")}, {Cell("2")}};
	codec.responses.push_back(direct);
	FakeRuntime runtime;
	QueryApiV3Client client(transport, codec, runtime);
	{
		CursorChunkSource source(std::move(client.Prepare(
		    "select id from fixture",
		    {"https://tenant.c360a.salesforce.com", "token"})).OpenCursor());
		ScanBuffer buffer;
		vector<LogicalType> types {LogicalType::INTEGER};
		vector<string> names {"id"};
		DataChunk output;
		InitOutput(output, types);
		FillDataChunk(source, buffer, types, names, output, 1);
		Require(output.size() == 1 && !buffer.exhausted,
		        "early consumer stop must leave the cursor unfinished");
	}
	Require(transport.requests.size() == 2 && transport.requests[1].method == "DELETE" &&
	            transport.requests[1].cleanup_request && transport.requests[1].timeout_ms == 250,
	        "destroying unfinished scan state must issue bounded cursor cleanup");
}

} // namespace

int main() {
	try {
		TestLargeRemoteChunkIsRetainedAcrossVectors();
		TestSmallAndEmptyChunksFillOneVectorUntilTrueEof();
		TestTypedNullAndExactDecimalConversion();
		TestBadConversionFailsWithColumnContext();
		TestMetadataCompatibilityRejectsBindExecutionDrift();
		TestSourceDestructionCleansUpAfterEarlyStop();
		std::cout << "data360_scan_test: PASS\n";
		return 0;
	} catch (const std::exception &exception) {
		std::cerr << "data360_scan_test: FAIL: " << exception.what() << '\n';
		return 1;
	}
}
