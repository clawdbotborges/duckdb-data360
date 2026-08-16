#pragma once

#include "data360/query_api.hpp"
#include "duckdb.hpp"

namespace data360 {

class ChunkSource {
public:
	virtual ~ChunkSource() = default;
	virtual bool NextChunk(ResultChunk &result) = 0;
};

class CursorChunkSource final : public ChunkSource {
public:
	explicit CursorChunkSource(QueryCursor cursor_p);
	bool NextChunk(ResultChunk &result) override;

private:
	QueryCursor cursor;
};

struct ScanBuffer {
	ResultChunk current_chunk;
	duckdb::idx_t current_row = 0;
	bool exhausted = false;
};

bool MetadataCompatible(const std::vector<ColumnMetadata> &bound,
                        const std::vector<ColumnMetadata> &execution);

void FillDataChunk(ChunkSource &source, ScanBuffer &buffer,
                   const duckdb::vector<duckdb::LogicalType> &types,
                   const duckdb::vector<duckdb::string> &names,
                   duckdb::DataChunk &output,
                   duckdb::idx_t capacity = STANDARD_VECTOR_SIZE);

} // namespace data360
