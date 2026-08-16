#pragma once

#include "duckdb.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace data360 {

enum class ArrowFieldKind { BOOL, INT32, INT64, DOUBLE, UTF8, DATE32, DATE64, TIMESTAMP_US_UTC, DECIMAL128 };

struct ExpectedArrowField {
	std::string name;
	ArrowFieldKind kind;
	bool nullable;
	uint8_t precision = 0;
	uint8_t scale = 0;
};

class ArrowIpcChunkReader {
public:
	ArrowIpcChunkReader(duckdb::ClientContext &context, const std::string &content_type, const std::string &body,
	                    std::vector<ExpectedArrowField> expected_schema, uint64_t max_body_bytes);
	~ArrowIpcChunkReader();

	ArrowIpcChunkReader(const ArrowIpcChunkReader &) = delete;
	ArrowIpcChunkReader &operator=(const ArrowIpcChunkReader &) = delete;
	ArrowIpcChunkReader(ArrowIpcChunkReader &&) noexcept;
	ArrowIpcChunkReader &operator=(ArrowIpcChunkReader &&) noexcept;

	static const char *MediaType();
	const duckdb::vector<std::string> &Names() const;
	const duckdb::vector<duckdb::LogicalType> &Types() const;
	bool Next(duckdb::DataChunk &output);

private:
	struct Impl;
	std::unique_ptr<Impl> impl;
};

} // namespace data360
