#include "data360/arrow_ipc_chunk_reader.hpp"

#include "duckdb.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace data360;
using namespace duckdb;

namespace {

void Require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

std::string ReadFixture(const std::string &name) {
	std::ifstream input(std::string(DATA360_ARROW_FIXTURE_DIR) + "/" + name, std::ios::binary);
	Require(input.good(), "fixture open failed");
	return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::vector<ExpectedArrowField> ExpectedSchema() {
	return {{"id", ArrowFieldKind::INT64, false},
	        {"text", ArrowFieldKind::UTF8, true},
	        {"event_time", ArrowFieldKind::TIMESTAMP_US_UTC, false},
	        {"amount", ArrowFieldKind::DECIMAL128, false, 38, 18}};
}

void RequireInvalid(ClientContext &context, const std::string &content_type, const std::string &body,
                    const std::vector<ExpectedArrowField> &schema, uint64_t max_body_bytes,
                    const char *message) {
	try {
		ArrowIpcChunkReader reader(context, content_type, body, schema, max_body_bytes);
		DataChunk chunk;
		while (reader.Next(chunk)) {
		}
		throw std::runtime_error(message);
	} catch (const InvalidInputException &error) {
		const std::string sanitized(error.what());
		Require(sanitized.find("Data 360 Arrow IPC response is invalid") != std::string::npos,
		        "generic sanitized error missing");
		Require(sanitized.size() < 512, "sanitized error is unexpectedly large");
		Require(sanitized.find("provider") == std::string::npos, "provider body leaked");
		Require(sanitized.find("row-8") == std::string::npos, "response body leaked");
		Require(sanitized.find("Compression type") == std::string::npos, "decoder error leaked");
		Require(sanitized.find("Expected to be able to read") == std::string::npos, "decoder detail leaked");
	}
}

void TestSchemaAndVectorSizedOutput() {
	DuckDB database(nullptr);
	Connection connection(database);
	ArrowIpcChunkReader reader(*connection.context, ArrowIpcChunkReader::MediaType(),
	                           ReadFixture("synthetic_multi_batch.arrow"), ExpectedSchema(), 1024 * 1024);
	Require(reader.Names() == duckdb::vector<std::string>({"id", "text", "event_time", "amount"}),
	        "schema names mismatch");
	Require(reader.Types().size() == 4 && reader.Types()[0] == LogicalType::BIGINT &&
	            reader.Types()[1] == LogicalType::VARCHAR && reader.Types()[2] == LogicalType::TIMESTAMP_TZ &&
	            reader.Types()[3] == LogicalType::DECIMAL(38, 18),
	        "schema types mismatch");

	DataChunk first;
	Require(reader.Next(first), "first chunk missing");
	Require(first.size() == STANDARD_VECTOR_SIZE, "first output is not vector-sized");
	Require(first.GetValue(0, 0).GetValue<int64_t>() == 0, "first id mismatch");
	Require(first.GetValue(1, 7).IsNull(), "nullable UTF-8 mismatch");
	Require(first.GetValue(1, 8).ToString() == "row-8-λ", "Unicode mismatch");
	Require(first.GetValue(2, 0).ToString() == "2026-01-01 00:00:00+00", "timestamp mismatch");
	Require(first.GetValue(3, 1).ToString() == "0.000000000000000001", "decimal mismatch");

	idx_t rows = first.size();
	bool crossed_batch = false;
	DataChunk chunk;
	while (reader.Next(chunk)) {
		Require(chunk.size() <= STANDARD_VECTOR_SIZE, "oversized output chunk");
		if (rows < 3000 && rows + chunk.size() > 3000) {
			crossed_batch = true;
		}
		for (idx_t row = 0; row < chunk.size(); row++) {
			Require(chunk.GetValue(0, row).GetValue<int64_t>() == static_cast<int64_t>(rows + row),
			        "row order mismatch");
		}
		rows += chunk.size();
	}
	Require(rows == 5000, "row count mismatch");
	Require(crossed_batch, "vector output did not cross record-batch boundary");
	Require(!reader.Next(chunk), "EOS is not stable");
}

void TestEmptySchemaPreservingStream() {
	DuckDB database(nullptr);
	Connection connection(database);
	ArrowIpcChunkReader reader(*connection.context, ArrowIpcChunkReader::MediaType(),
	                           ReadFixture("synthetic_empty.arrow"), ExpectedSchema(), 1024);
	Require(reader.Names().size() == 4 && reader.Types()[3] == LogicalType::DECIMAL(38, 18),
	        "empty stream lost schema");
	DataChunk chunk;
	Require(!reader.Next(chunk), "empty stream emitted rows");
	Require(!reader.Next(chunk), "empty stream EOS is not stable");
}

void TestIndependentStreamsAndValidation() {
	DuckDB database(nullptr);
	Connection connection(database);
	auto body = ReadFixture("synthetic_multi_batch.arrow");
	ArrowIpcChunkReader first(*connection.context, ArrowIpcChunkReader::MediaType(), body, ExpectedSchema(), body.size());
	ArrowIpcChunkReader second(*connection.context, ArrowIpcChunkReader::MediaType(), body, ExpectedSchema(), body.size());
	DataChunk a, b;
	Require(first.Next(a) && second.Next(b), "independent stream read failed");
	Require(a.GetValue(0, 0) == b.GetValue(0, 0), "independent streams interfered");

	RequireInvalid(*connection.context, "application/json", body, ExpectedSchema(), body.size(), "media type accepted");
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body, ExpectedSchema(), body.size() - 1,
	               "oversized body accepted");
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), "not-arrow-provider-secret", ExpectedSchema(), 100,
	               "wrong bytes accepted");
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body.substr(0, 10000), ExpectedSchema(), body.size(),
	               "truncation accepted");
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), ReadFixture("synthetic_zstd.arrow"),
	               ExpectedSchema(), body.size(), "compressed stream accepted");

	auto trailing = body;
	trailing += "malformed-trailing-data";
	trailing.append("\xff\xff\xff\xff\x00\x00\x00\x00", 8);
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), trailing, ExpectedSchema(), trailing.size(),
	               "trailing data accepted");

	auto drift = ExpectedSchema();
	drift[0].name = "wrong";
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body, drift, body.size(), "name drift accepted");
	drift = ExpectedSchema();
	std::swap(drift[0], drift[1]);
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body, drift, body.size(), "order drift accepted");
	drift = ExpectedSchema();
	drift[0].kind = ArrowFieldKind::UTF8;
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body, drift, body.size(), "type drift accepted");
	drift = ExpectedSchema();
	drift[0].nullable = true;
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body, drift, body.size(), "nullability drift accepted");
	drift = ExpectedSchema();
	drift[3].precision = 37;
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body, drift, body.size(), "precision drift accepted");
	drift = ExpectedSchema();
	drift[3].scale = 17;
	RequireInvalid(*connection.context, ArrowIpcChunkReader::MediaType(), body, drift, body.size(), "scale drift accepted");
}

} // namespace

int main() {
	try {
		TestSchemaAndVectorSizedOutput();
		TestEmptySchemaPreservingStream();
		TestIndependentStreamsAndValidation();
		std::cout << "Arrow IPC chunk reader tests passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "Arrow IPC chunk reader test failed: " << error.what() << "\n";
		return 1;
	}
}
