#include "data360/scan_runtime.hpp"

#include "duckdb/common/exception.hpp"

#include <utility>

namespace data360 {

CursorChunkSource::CursorChunkSource(QueryCursor cursor_p) : cursor(std::move(cursor_p)) {
}

bool CursorChunkSource::NextChunk(ResultChunk &result) {
	return cursor.NextChunk(result);
}

bool MetadataCompatible(const std::vector<ColumnMetadata> &bound,
                        const std::vector<ColumnMetadata> &execution) {
	if (bound.size() != execution.size()) return false;
	for (size_t column = 0; column < bound.size(); column++) {
		if (bound[column].name != execution[column].name ||
		    bound[column].type != execution[column].type ||
		    bound[column].nullable != execution[column].nullable) {
			return false;
		}
	}
	return true;
}

void FillDataChunk(ChunkSource &source, ScanBuffer &buffer,
                   const duckdb::vector<duckdb::LogicalType> &types,
                   const duckdb::vector<duckdb::string> &names,
                   duckdb::DataChunk &output, duckdb::idx_t capacity) {
	duckdb::idx_t count = 0;
	while (count < capacity && !buffer.exhausted) {
		if (buffer.current_row >= buffer.current_chunk.rows.size()) {
			buffer.current_chunk = {};
			buffer.current_row = 0;
			if (!source.NextChunk(buffer.current_chunk)) {
				buffer.exhausted = true;
				break;
			}
			continue;
		}
		const auto &source_row = buffer.current_chunk.rows[buffer.current_row++];
		for (duckdb::idx_t column = 0; column < types.size(); column++) {
			if (!source_row[column]) {
				output.SetValue(column, count, duckdb::Value(types[column]));
				continue;
			}
			try {
				output.SetValue(column, count,
				                duckdb::Value(*source_row[column]).DefaultCastAs(types[column]));
			} catch (...) {
				throw duckdb::InvalidInputException("Data 360 value conversion failed for column '%s'",
				                                    names[column]);
			}
		}
		count++;
	}
	output.SetCardinality(count);
}

} // namespace data360
