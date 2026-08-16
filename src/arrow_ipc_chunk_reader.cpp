#include "data360/arrow_ipc_chunk_reader.hpp"

#include "duckdb/common/arrow/arrow_wrapper.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/function/table/arrow.hpp"
#include "nanoarrow/nanoarrow.h"
#include "nanoarrow/nanoarrow_ipc.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <utility>

namespace data360 {
namespace {

constexpr const char *ARROW_MEDIA_TYPE = "application/vnd.apache.arrow.stream";
constexpr const char *INVALID_ARROW_ERROR = "Data 360 Arrow IPC response is invalid";
constexpr std::array<unsigned char, 8> STREAM_EOS = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00};

[[noreturn]] void InvalidArrow() {
	throw duckdb::InvalidInputException(INVALID_ARROW_ERROR);
}

std::string ExpectedFormat(const ExpectedArrowField &field) {
	switch (field.kind) {
	case ArrowFieldKind::INT64:
		return "l";
	case ArrowFieldKind::UTF8:
		return "u";
	case ArrowFieldKind::TIMESTAMP_US_UTC:
		return "tsu:UTC";
	case ArrowFieldKind::DECIMAL128:
		return "d:" + std::to_string(field.precision) + "," + std::to_string(field.scale);
	}
	return "";
}

bool HasTerminalStreamEos(const std::string &body) {
	return body.size() >= STREAM_EOS.size() &&
	       std::equal(STREAM_EOS.begin(), STREAM_EOS.end(),
	                  reinterpret_cast<const unsigned char *>(body.data() + body.size() - STREAM_EOS.size()));
}

struct BodyInputState {
	std::string body;
	size_t offset = 0;
};

ArrowErrorCode ReadBody(ArrowIpcInputStream *input, uint8_t *buffer, int64_t requested, int64_t *read_out,
	                    ArrowError *) {
	if (!input || !input->private_data || !buffer || requested < 0 || !read_out) {
		return EINVAL;
	}
	auto &state = *static_cast<BodyInputState *>(input->private_data);
	const auto count = std::min<size_t>(static_cast<size_t>(requested), state.body.size() - state.offset);
	if (count != 0) {
		std::memcpy(buffer, state.body.data() + state.offset, count);
	}
	state.offset += count;
	*read_out = static_cast<int64_t>(count);
	return NANOARROW_OK;
}

void ReleaseBody(ArrowIpcInputStream *input) {
	delete static_cast<BodyInputState *>(input->private_data);
	input->private_data = nullptr;
	input->read = nullptr;
	input->release = nullptr;
}

BodyInputState *InitBodyInput(ArrowIpcInputStream &input, const std::string &body) {
	auto state = std::make_unique<BodyInputState>();
	state->body = body;
	auto *result = state.release();
	input.read = ReadBody;
	input.release = ReleaseBody;
	input.private_data = result;
	return result;
}

} // namespace

struct ArrowIpcChunkReader::Impl {
	duckdb::ClientContext &context;
	std::vector<ExpectedArrowField> expected;
	duckdb::vector<std::string> names;
	duckdb::vector<duckdb::LogicalType> types;
	ArrowArrayStream stream {};
	ArrowSchema schema {};
	duckdb::ArrowTableSchema duck_schema;
	duckdb::shared_ptr<duckdb::ArrowArrayWrapper> current;
	BodyInputState *input_state = nullptr;
	duckdb::idx_t current_offset = 0;
	bool eos = false;

	Impl(duckdb::ClientContext &context_p, const std::string &content_type, const std::string &body,
	     std::vector<ExpectedArrowField> expected_p, uint64_t max_body_bytes)
	    : context(context_p), expected(std::move(expected_p)) {
		if (content_type != ARROW_MEDIA_TYPE || body.size() > max_body_bytes ||
		    body.size() > static_cast<size_t>(std::numeric_limits<int64_t>::max()) || !HasTerminalStreamEos(body)) {
			InvalidArrow();
		}

		ArrowIpcInputStream input {};
		try {
			auto *created_input_state = InitBodyInput(input, body);
			if (ArrowIpcArrayStreamReaderInit(&stream, &input, nullptr) != NANOARROW_OK) {
				if (input.release) {
					input.release(&input);
				}
				InvalidArrow();
			}
			input_state = created_input_state;
			ArrowError error;
			std::memset(&error, 0, sizeof(error));
			if (ArrowArrayStreamGetSchema(&stream, &schema, &error) != NANOARROW_OK) {
				InvalidArrow();
			}
			ValidateSchema();
			duckdb::ArrowTableFunction::PopulateArrowTableSchema(context, duck_schema, schema);
			names = duck_schema.GetNames();
			types = duck_schema.GetTypes();
		} catch (...) {
			Cleanup();
			InvalidArrow();
		}
	}

	~Impl() {
		Cleanup();
	}

	void Cleanup() noexcept {
		current.reset();
		if (schema.release) {
			ArrowSchemaRelease(&schema);
		}
		if (stream.release) {
			ArrowArrayStreamRelease(&stream);
		}
		input_state = nullptr;
	}

	void ValidateSchema() {
		if (!schema.format || std::strcmp(schema.format, "+s") != 0 || schema.n_children < 0 ||
		    static_cast<size_t>(schema.n_children) != expected.size()) {
			InvalidArrow();
		}
		for (size_t index = 0; index < expected.size(); index++) {
			auto *child = schema.children[index];
			const auto &field = expected[index];
			if (!child || !child->name || !child->format || field.name != child->name ||
			    ExpectedFormat(field) != child->format ||
			    ((child->flags & ARROW_FLAG_NULLABLE) != 0) != field.nullable) {
				InvalidArrow();
			}
			if (field.kind == ArrowFieldKind::DECIMAL128 &&
			    (field.precision == 0 || field.precision > 38 || field.scale > field.precision)) {
				InvalidArrow();
			}
		}
	}

	bool LoadBatch() {
		current.reset();
		// Allocate the RAII owner before asking the C stream to populate an
		// owning ArrowArray. If decoding or any later validation throws, the
		// wrapper releases the partially/fully populated array.
		auto next = duckdb::make_shared_ptr<duckdb::ArrowArrayWrapper>();
		ArrowError error;
		std::memset(&error, 0, sizeof(error));
		if (ArrowArrayStreamGetNext(&stream, &next->arrow_array, &error) != NANOARROW_OK) {
			InvalidArrow();
		}
		if (!next->arrow_array.release) {
			if (!input_state || input_state->offset != input_state->body.size()) {
				InvalidArrow();
			}
			eos = true;
			return false;
		}
		if (next->arrow_array.length < 0 || next->arrow_array.n_children < 0 ||
		    static_cast<size_t>(next->arrow_array.n_children) != expected.size()) {
			InvalidArrow();
		}
		current = std::move(next);
		current_offset = 0;
		return true;
	}

	void ConvertSlice(duckdb::DataChunk &target, duckdb::idx_t target_offset, duckdb::idx_t count) {
		duckdb::DataChunk converted;
		converted.Initialize(duckdb::Allocator::DefaultAllocator(), types);
		converted.SetCardinality(count);
		auto &parent = current->arrow_array;
		const auto &arrow_types = duck_schema.GetColumns();
		for (duckdb::idx_t column = 0; column < converted.ColumnCount(); column++) {
			auto state = duckdb::make_uniq<duckdb::ArrowArrayScanState>(context);
			state->owned_data = current;
			auto &array = *parent.children[column];
			duckdb::ArrowToDuckDBConversion::SetValidityMask(converted.data[column], array, current_offset, count,
			                                                     parent.offset, -1);
			duckdb::ArrowToDuckDBConversion::ColumnArrowToDuckDB(converted.data[column], array, current_offset, *state,
			                                                       count, *arrow_types.at(column));
			duckdb::VectorOperations::Copy(converted.data[column], target.data[column], count, 0, target_offset);
		}
	}

	bool Next(duckdb::DataChunk &output) {
		try {
			if (output.ColumnCount() == 0) {
				output.Initialize(duckdb::Allocator::DefaultAllocator(), types);
			} else {
				output.Reset();
			}
			if (eos) {
				return false;
			}

			duckdb::idx_t output_count = 0;
			while (output_count < STANDARD_VECTOR_SIZE) {
				if (!current || current_offset >= static_cast<duckdb::idx_t>(current->arrow_array.length)) {
					if (!LoadBatch()) {
						break;
					}
				}
				auto remaining = static_cast<duckdb::idx_t>(current->arrow_array.length) - current_offset;
				auto count = std::min<duckdb::idx_t>(remaining, STANDARD_VECTOR_SIZE - output_count);
				ConvertSlice(output, output_count, count);
				current_offset += count;
				output_count += count;
			}
			output.SetCardinality(output_count);
			return output_count != 0;
		} catch (...) {
			InvalidArrow();
		}
	}
};

ArrowIpcChunkReader::ArrowIpcChunkReader(duckdb::ClientContext &context, const std::string &content_type,
                                         const std::string &body, std::vector<ExpectedArrowField> expected_schema,
                                         uint64_t max_body_bytes)
    : impl(std::make_unique<Impl>(context, content_type, body, std::move(expected_schema), max_body_bytes)) {
}

ArrowIpcChunkReader::~ArrowIpcChunkReader() = default;
ArrowIpcChunkReader::ArrowIpcChunkReader(ArrowIpcChunkReader &&) noexcept = default;
ArrowIpcChunkReader &ArrowIpcChunkReader::operator=(ArrowIpcChunkReader &&) noexcept = default;

const char *ArrowIpcChunkReader::MediaType() {
	return ARROW_MEDIA_TYPE;
}

const duckdb::vector<std::string> &ArrowIpcChunkReader::Names() const {
	return impl->names;
}

const duckdb::vector<duckdb::LogicalType> &ArrowIpcChunkReader::Types() const {
	return impl->types;
}

bool ArrowIpcChunkReader::Next(duckdb::DataChunk &output) {
	return impl->Next(output);
}

} // namespace data360
