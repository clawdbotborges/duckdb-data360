#include "data360/native_runtime.hpp"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#include "yyjson.hpp"
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <thread>

namespace data360 {
namespace {
using namespace duckdb_yyjson;

struct JsonDocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
using JsonDoc = std::unique_ptr<yyjson_doc, JsonDocDeleter>;

JsonDoc Parse(const std::string &body) {
	JsonDoc doc(yyjson_read(body.data(), body.size(), YYJSON_READ_NUMBER_AS_RAW));
	if (!doc || !yyjson_is_obj(yyjson_doc_get_root(doc.get()))) {
		throw std::runtime_error("Data 360 response was invalid JSON");
	}
	return doc;
}

bool HasInvalidSessionCode(const std::string &body) {
	JsonDoc doc(yyjson_read(body.data(), body.size(), YYJSON_READ_NOFLAG));
	if (!doc) return false;
	auto root = yyjson_doc_get_root(doc.get());
	auto error = root;
	if (yyjson_is_arr(root) && yyjson_arr_size(root) == 1) error = yyjson_arr_get_first(root);
	if (!yyjson_is_obj(error)) return false;
	auto code = yyjson_obj_get(error, "errorCode");
	return yyjson_is_str(code) && yyjson_equals_str(code, "INVALID_SESSION_ID");
}

bool TryUnsigned(yyjson_val *value, uint64_t &result) {
	if (yyjson_is_uint(value)) {
		result = yyjson_get_uint(value);
		return true;
	}
	if (!yyjson_is_raw(value)) {
		return false;
	}
	const std::string raw(yyjson_get_raw(value), yyjson_get_len(value));
	if (raw.empty() || raw.find_first_not_of("0123456789") != std::string::npos) {
		return false;
	}
	try {
		size_t consumed = 0;
		result = std::stoull(raw, &consumed);
		return consumed == raw.size();
	} catch (...) {
		return false;
	}
}

bool OptionalUnsigned(yyjson_val *object, const char *key, uint64_t &result) {
	auto value = yyjson_obj_get(object, key);
	if (!value) return false;
	if (!TryUnsigned(value, result)) {
		throw std::runtime_error("Data 360 response contained an invalid count");
	}
	return true;
}

std::string JsonScalar(yyjson_val *value) {
	if (yyjson_is_str(value)) return std::string(yyjson_get_str(value), yyjson_get_len(value));
	if (yyjson_is_bool(value)) return yyjson_get_bool(value) ? "true" : "false";
	if (yyjson_is_raw(value)) return std::string(yyjson_get_raw(value), yyjson_get_len(value));
	if (yyjson_is_num(value)) {
		if (yyjson_is_uint(value)) return std::to_string(yyjson_get_uint(value));
		if (yyjson_is_sint(value)) return std::to_string(yyjson_get_sint(value));
		char number[32];
		const auto length = std::snprintf(number, sizeof(number), "%.17g", yyjson_get_real(value));
		if (length <= 0 || static_cast<size_t>(length) >= sizeof(number)) {
			throw std::runtime_error("Data 360 numeric value was invalid");
		}
		return std::string(number, static_cast<size_t>(length));
	}
	throw std::runtime_error("Data 360 result contained a non-scalar value");
}

} // namespace

QueryResponse JsonQueryResponseCodec::Decode(const HttpResponse &response) {
	if (response.status == 401 || (response.status == 403 && HasInvalidSessionCode(response.body)))
		throw ReauthRequiredException();
	if (response.status < 200 || response.status >= 300) throw std::runtime_error("Data 360 Query API request failed");
	for (const auto *status_header : {"x-hyperdb-status", "status"}) {
		if (const auto header = response.headers.find(status_header); header != response.headers.end()) {
			try {
				auto status_doc = Parse(header->second);
				auto query_id = yyjson_obj_get(yyjson_doc_get_root(status_doc.get()), "queryId");
				if (yyjson_is_str(query_id) && yyjson_get_len(query_id) > 0) {
					QueryResponse submitted;
					submitted.state = QueryState::RUNNING;
					submitted.query_id = std::string(yyjson_get_str(query_id), yyjson_get_len(query_id));
					return submitted;
				}
			} catch (...) {
				// Continue to the bounded response body shapes below.
			}
		}
	}
	if (const auto location = response.headers.find("location"); location != response.headers.end()) {
		const std::string marker = "/api/v3/query/";
		const auto marker_pos = location->second.find(marker);
		if (marker_pos != std::string::npos) {
			const auto id_start = marker_pos + marker.size();
			const auto id_end = location->second.find_first_of("/?#", id_start);
			const auto query_id = location->second.substr(id_start, id_end - id_start);
			if (!query_id.empty()) {
				QueryResponse submitted;
				submitted.state = QueryState::RUNNING;
				submitted.query_id = query_id;
				return submitted;
			}
		}
	}
	auto doc = Parse(response.body);
	auto root = yyjson_doc_get_root(doc.get());
	QueryResponse result;
	if (auto query_id = yyjson_obj_get(root, "queryId"); yyjson_is_str(query_id)) {
		result.query_id = std::string(yyjson_get_str(query_id), yyjson_get_len(query_id));
	}
	if (auto completion = yyjson_obj_get(root, "completionStatus"); yyjson_is_str(completion)) {
		const std::string state(yyjson_get_str(completion), yyjson_get_len(completion));
		result.state = (state == "FINISHED" || state == "RESULTS_PRODUCED") ? QueryState::COMPLETE
		                                                                  : (state == "RUNNING" ? QueryState::RUNNING : QueryState::FAILED);
		result.has_chunk_count = OptionalUnsigned(root, "chunkCount", result.chunk_count);
		result.has_row_count = OptionalUnsigned(root, "rowCount", result.row_count);
		return result;
	}
	if (!result.query_id.empty()) {
		result.state = QueryState::RUNNING;
		return result;
	}
	// Chunk responses can repeat metadata alongside the row payload. Decode both
	// so the cursor can reject execution-time schema drift before yielding rows.
	auto metadata_object = yyjson_obj_get(root, "metadata");
	if (!yyjson_is_obj(metadata_object)) metadata_object = root;
	if (auto columns = yyjson_obj_get(metadata_object, "columns"); yyjson_is_arr(columns)) {
		size_t index, maximum;
		yyjson_val *column;
		yyjson_arr_foreach(columns, index, maximum, column) {
			if (!yyjson_is_obj(column)) throw std::runtime_error("Data 360 metadata column was invalid");
			auto name = yyjson_obj_get(column, "name");
			if (!yyjson_is_str(name)) name = yyjson_obj_get(column, "columnName");
			auto type = yyjson_obj_get(column, "type");
			if (!yyjson_is_str(type)) type = yyjson_obj_get(column, "typeName");
			auto nullable = yyjson_obj_get(column, "nullable");
			if (!yyjson_is_str(name) || !yyjson_is_str(type) || !yyjson_is_bool(nullable))
				throw std::runtime_error("Data 360 metadata column was incomplete");
			ColumnMetadata decoded {std::string(yyjson_get_str(name), yyjson_get_len(name)),
			                        std::string(yyjson_get_str(type), yyjson_get_len(type)), yyjson_get_bool(nullable)};
			auto precision_value = yyjson_obj_get(column, "precision");
			auto scale_value = yyjson_obj_get(column, "scale");
			const bool precision_present = precision_value != nullptr;
			const bool scale_present = scale_value != nullptr;
			std::string normalized_type = decoded.type;
			std::transform(normalized_type.begin(), normalized_type.end(), normalized_type.begin(),
			               [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
			if (normalized_type != "numeric" && (precision_present || scale_present))
				throw std::runtime_error("Data 360 metadata column shape was unexpected");
			if (precision_present != scale_present)
				throw std::runtime_error("Data 360 numeric metadata shape was incomplete");
			if (precision_present) {
				uint64_t precision = 0;
				uint64_t scale = 0;
				if (!OptionalUnsigned(column, "precision", precision) || !OptionalUnsigned(column, "scale", scale) ||
				    precision == 0 || precision > 38 || scale > precision)
					throw std::runtime_error("Data 360 numeric metadata shape was invalid");
				decoded.has_precision = true;
				decoded.has_scale = true;
				decoded.precision = static_cast<uint8_t>(precision);
				decoded.scale = static_cast<uint8_t>(scale);
			}
			result.metadata.push_back(std::move(decoded));
		}
	}
	if (auto data = yyjson_obj_get(root, "data"); yyjson_is_arr(data)) {
		if (auto next = yyjson_obj_get(root, "next"); yyjson_is_str(next)) {
			result.chunk.next_url = std::string(yyjson_get_str(next), yyjson_get_len(next));
		}
		size_t row_index, row_maximum;
		yyjson_val *row;
		yyjson_arr_foreach(data, row_index, row_maximum, row) {
			if (!yyjson_is_arr(row)) throw std::runtime_error("Data 360 result row was invalid");
			std::vector<Cell> cells;
			size_t cell_index, cell_maximum;
			yyjson_val *cell;
			yyjson_arr_foreach(row, cell_index, cell_maximum, cell) {
				cells.push_back(yyjson_is_null(cell) ? Cell() : Cell(JsonScalar(cell)));
			}
			result.chunk.rows.push_back(std::move(cells));
		}
		result.state = QueryState::COMPLETE;
		result.has_returned_rows = OptionalUnsigned(root, "returnedRows", result.returned_rows);
		return result;
	}
	if (!result.metadata.empty()) {
		result.state = QueryState::COMPLETE;
		return result;
	}
	throw std::runtime_error("Data 360 response shape was not recognized");
}

SteadyRuntime::SteadyRuntime(const std::atomic<bool> *cancelled_p) : cancelled(cancelled_p) {
}
bool SteadyRuntime::IsCancelled() {
	return cancelled && cancelled->load();
}
uint64_t SteadyRuntime::NowMs() {
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
	                                 std::chrono::steady_clock::now().time_since_epoch()).count());
}
void SteadyRuntime::SleepMs(uint64_t milliseconds) {
	std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

} // namespace data360
