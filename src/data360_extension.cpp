#define DUCKDB_EXTENSION_MAIN

#include "data360_extension.hpp"
#include "data360/arrow_ipc_chunk_reader.hpp"
#include "data360/auth_functions.hpp"
#include "data360/auth_session_registry.hpp"
#include "data360/native_runtime.hpp"
#include "data360/scan_runtime.hpp"
#include "data360/session_credentials.hpp"
#include "data360/type_mapping.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/main/client_context.hpp"

#include <chrono>

#include <cstdio>
#include <thread>
#include <algorithm>
#include <cctype>
#include <limits>

namespace duckdb {
namespace {

class Data360BindData final : public TableFunctionData {
public:
	vector<LogicalType> types;
	vector<string> names;
	std::vector<data360::ColumnMetadata> metadata;
	string sql;
	string credential_id;

	bool SupportStatementCache() const override {
		return false;
	}
};

class DuckDBRuntime final : public data360::RuntimeHooks {
public:
	explicit DuckDBRuntime(ClientContext &context_p) : context(context_p) {
	}
	bool IsCancelled() override {
		return context.IsInterrupted();
	}
	uint64_t NowMs() override {
		return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
		                                 std::chrono::steady_clock::now().time_since_epoch()).count());
	}
	void SleepMs(uint64_t milliseconds) override {
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
		while (!IsCancelled() && std::chrono::steady_clock::now() < deadline) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	}

private:
	ClientContext &context;
};

std::string Lower(std::string value) {
	std::transform(value.begin(), value.end(), value.begin(),
	               [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
	return value;
}

std::vector<data360::ExpectedArrowField> ExpectedArrowSchema(
    const std::vector<data360::ColumnMetadata> &metadata) {
	std::vector<data360::ExpectedArrowField> expected;
	for (const auto &column : metadata) {
		data360::ExpectedArrowField field {column.name, data360::ArrowFieldKind::UTF8, column.nullable};
		const auto type = Lower(column.type);
		if (type == "bool" || type == "boolean") field.kind = data360::ArrowFieldKind::BOOL;
		else if (type == "integer" || type == "int") field.kind = data360::ArrowFieldKind::INT32;
		else if (type == "bigint") field.kind = data360::ArrowFieldKind::INT64;
		else if (type == "double") field.kind = data360::ArrowFieldKind::DOUBLE;
		else if (type == "varchar" || type == "string") field.kind = data360::ArrowFieldKind::UTF8;
		else if (type == "date") field.kind = data360::ArrowFieldKind::DATE64;
		else if (type == "timestamp" || type == "timestamptz" || type == "timestamp_with_time_zone")
			field.kind = data360::ArrowFieldKind::TIMESTAMP_US_UTC;
		else if (type == "numeric") {
			if (!column.has_precision || !column.has_scale)
				throw InvalidInputException("Data 360 numeric metadata was incomplete");
			field.kind = data360::ArrowFieldKind::DECIMAL128;
			field.precision = column.precision;
			field.scale = column.scale;
		} else {
			throw InvalidInputException("Data 360 Arrow metadata contained an unsupported type");
		}
		expected.push_back(std::move(field));
	}
	return expected;
}

std::string ArrowContentType(const data360::HttpResponse &response) {
	std::string result;
	for (const auto &header : response.headers) {
		if (Lower(header.first) != "content-type") continue;
		if (!result.empty()) throw InvalidInputException("Data 360 Arrow response headers were invalid");
		result = header.second;
	}
	if (result.empty()) throw InvalidInputException("Data 360 Arrow response headers were invalid");
	return result;
}

class ArrowScanSource final {
public:
	ArrowScanSource(ClientContext &context_p, data360::QueryCursor cursor_p,
	                const std::vector<data360::ColumnMetadata> &metadata,
	                const vector<LogicalType> &bound_types)
	    : context(context_p), cursor(std::move(cursor_p)), expected(ExpectedArrowSchema(metadata)), types(bound_types) {
	}

	bool Next(DataChunk &output) {
		while (true) {
			if (reader) {
				if (reader->Next(output)) return true;
				reader.reset();
			}
			if (!cursor.NextArrowChunk(response)) {
				output.SetCardinality(0);
				return false;
			}

			const auto content_type = ArrowContentType(response);
			uint64_t validated_rows = 0;
			{
				data360::ArrowIpcChunkReader validator(context, content_type, response.body, expected,
				                                              64ULL * 1024ULL * 1024ULL);
				if (validator.Types() != types)
					throw InvalidInputException("Data 360 Arrow result schema changed");
				DataChunk discarded;
				while (validator.Next(discarded)) {
					if (validated_rows > std::numeric_limits<uint64_t>::max() - discarded.size())
						throw InvalidInputException("Data 360 Arrow response exceeded configured limits");
					validated_rows += discarded.size();
				}
			}

			auto validated_reader = std::make_unique<data360::ArrowIpcChunkReader>(
			    context, content_type, response.body, expected, 64ULL * 1024ULL * 1024ULL);
			if (validated_reader->Types() != types)
				throw InvalidInputException("Data 360 Arrow result schema changed");
			cursor.ReportArrowChunk(validated_rows);
			reader = std::move(validated_reader);
			response = {};
		}
	}

private:
	ClientContext &context;
	data360::QueryCursor cursor;
	std::vector<data360::ExpectedArrowField> expected;
	vector<LogicalType> types;
	data360::HttpResponse response {};
	std::unique_ptr<data360::ArrowIpcChunkReader> reader;
};

class Data360GlobalState final : public GlobalTableFunctionState {
public:
	explicit Data360GlobalState(ClientContext &context)
	    : runtime(context), transport(&runtime), codec(), client(transport, codec, runtime) {
	}

	DuckDBRuntime runtime;
	data360::LibcurlTransport transport;
	data360::JsonQueryResponseCodec codec;
	data360::QueryApiV3Client client;
	std::unique_ptr<data360::ChunkSource> source;
	std::unique_ptr<ArrowScanSource> arrow_source;
	data360::ScanBuffer scan_buffer;
};

LogicalType BindLogicalType(const data360::TypeMapping &mapping) {
	if (mapping.duckdb_type == "VARCHAR") return LogicalType::VARCHAR;
	if (mapping.duckdb_type == "BOOLEAN") return LogicalType::BOOLEAN;
	if (mapping.duckdb_type == "DATE") return LogicalType::DATE;
	if (mapping.duckdb_type == "TIMESTAMP") return LogicalType::TIMESTAMP;
	if (mapping.duckdb_type == "TIMESTAMPTZ") return LogicalType::TIMESTAMP_TZ;
	if (mapping.duckdb_type == "INTEGER") return LogicalType::INTEGER;
	if (mapping.duckdb_type == "BIGINT") return LogicalType::BIGINT;
	if (mapping.duckdb_type == "DOUBLE") return LogicalType::DOUBLE;
	unsigned int width = 0;
	unsigned int scale = 0;
	if (std::sscanf(mapping.duckdb_type.c_str(), "DECIMAL(%u,%u)", &width, &scale) == 2 && width <= 38 &&
	    scale <= width) {
		return LogicalType::DECIMAL(static_cast<uint8_t>(width), static_cast<uint8_t>(scale));
	}
	throw BinderException("Data 360 metadata contained an unsupported type");
};

unique_ptr<FunctionData> Data360QueryBind(ClientContext &context, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<string> &names) {
	const auto secret_name = input.inputs[1].GetValue<string>();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto secret = SecretManager::Get(context).GetSecretByName(transaction, secret_name);
	if (!secret) {
		throw BinderException("Data 360 secret '%s' was not found", secret_name);
	}
	if (secret->secret->GetType() != "data360") {
		throw BinderException("Secret '%s' is not a Data 360 secret", secret_name);
	}
	if (secret->secret->GetProvider() != "oauth_pkce") {
		throw BinderException("Data 360 secret '%s' uses an unsupported provider", secret_name);
	}
	const auto &key_value = dynamic_cast<const KeyValueSecret &>(*secret->secret);
	Value session_value;
	if (!key_value.TryGetValue("session_id", session_value) || session_value.IsNull()) {
		throw BinderException("Data 360 OAuth secret is invalid");
	}
	const auto credential_id = session_value.GetValue<string>();
	DuckDBRuntime runtime(context);
	data360::QueryCredentials credentials;
	try {
		credentials = Data360AuthState::Get(context).Registry().ResolveCredential(credential_id);
	} catch (...) {
		if (context.IsInterrupted()) throw InterruptException();
		throw BinderException(data360::FormatSafeFault(data360::AuthFault::REAUTH_REQUIRED));
	}
	try {
		data360::LibcurlTransport transport(&runtime);
		data360::JsonQueryResponseCodec codec;
		data360::QueryApiV3Client client(transport, codec, runtime);
		const auto sql = input.inputs[0].GetValue<string>();
		auto result = client.ExecuteMetadata(sql, credentials);
		if (result.metadata.empty()) {
			throw BinderException("Data 360 query returned no metadata");
		}
		auto bind = make_uniq<Data360BindData>();
		bind->sql = sql;
		bind->credential_id = credential_id;
		for (const auto &column : result.metadata) {
			if (column.name.empty()) {
				throw BinderException("Data 360 query returned an unnamed column");
			}
			const auto mapping = (Lower(column.type) == "numeric" && column.has_precision && column.has_scale)
			                         ? data360::MapData360Type("DECIMAL(" + std::to_string(column.precision) + "," +
			                                                   std::to_string(column.scale) + ")")
			                         : data360::MapData360Type(column.type);
			auto logical_type = BindLogicalType(mapping);
			names.push_back(column.name);
			return_types.push_back(logical_type);
			bind->types.push_back(std::move(logical_type));
			bind->names.push_back(column.name);
			bind->metadata.push_back(column);
		}
		return std::move(bind);
	} catch (const data360::ReauthRequiredException &) {
		throw BinderException(data360::FormatSafeFault(data360::AuthFault::REAUTH_REQUIRED));
	} catch (const BinderException &) {
		throw;
	} catch (...) {
		if (context.IsInterrupted()) throw InterruptException();
		throw BinderException("Data 360 query execution failed");
	}
}

unique_ptr<GlobalTableFunctionState> Data360QueryInit(ClientContext &context, TableFunctionInitInput &input) {
	const auto &bind = input.bind_data->Cast<Data360BindData>();
	auto state = make_uniq<Data360GlobalState>(context);
	data360::QueryCredentials credentials;
	try {
		credentials = Data360AuthState::Get(context).Registry().ResolveCredential(bind.credential_id);
	} catch (...) {
		if (context.IsInterrupted()) throw InterruptException();
		throw InvalidInputException(data360::FormatSafeFault(data360::AuthFault::REAUTH_REQUIRED));
	}
	try {
		auto prepared = state->client.Prepare(bind.sql, credentials);
		const auto &metadata = prepared.Metadata();
		if (!data360::MetadataCompatible(bind.metadata, metadata)) {
			throw InvalidInputException("Data 360 result schema changed after binding");
		}
		auto cursor = std::move(prepared).OpenCursor();
		if (cursor.IsNumberedV3()) {
			state->arrow_source = std::make_unique<ArrowScanSource>(context, std::move(cursor), metadata, bind.types);
		} else {
			state->source = std::make_unique<data360::CursorChunkSource>(std::move(cursor));
		}
		return std::move(state);
	} catch (const data360::ReauthRequiredException &) {
		throw InvalidInputException(data360::FormatSafeFault(data360::AuthFault::REAUTH_REQUIRED));
	} catch (const InvalidInputException &) {
		throw;
	} catch (...) {
		if (context.IsInterrupted()) throw InterruptException();
		throw InvalidInputException("Data 360 query execution failed");
	}
}

void Data360QueryFunction(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	const auto &bind = input.bind_data->Cast<Data360BindData>();
	auto &state = input.global_state->Cast<Data360GlobalState>();
	try {
		if (state.arrow_source) {
			(void)state.arrow_source->Next(output);
		} else {
			data360::FillDataChunk(*state.source, state.scan_buffer, bind.types, bind.names, output);
		}
	} catch (const data360::ReauthRequiredException &) {
		throw InvalidInputException(data360::FormatSafeFault(data360::AuthFault::REAUTH_REQUIRED));
	} catch (const InvalidInputException &) {
		throw;
	} catch (...) {
		if (context.IsInterrupted()) throw InterruptException();
		throw InvalidInputException("Data 360 query execution failed");
	}
}

void LoadInternal(ExtensionLoader &loader) {
	SecretType secret_type;
	secret_type.name = "data360";
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "oauth_pkce";
	loader.RegisterSecretType(std::move(secret_type));

	CreateSecretFunction secret_function;
	secret_function.secret_type = "data360";
	secret_function.provider = "oauth_pkce";
	secret_function.function = CreateOAuthPkceSecret;
	loader.RegisterFunction(std::move(secret_function));

	TableFunction function("data360_query", {LogicalType::VARCHAR, LogicalType::VARCHAR}, Data360QueryFunction,
	                       Data360QueryBind, Data360QueryInit);
	loader.RegisterFunction(function);
	RegisterData360AuthFunctions(loader);
}

} // namespace

void Data360Extension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string Data360Extension::Name() {
	return "data360";
}

std::string Data360Extension::Version() const {
#ifdef EXT_VERSION_DATA360
	return EXT_VERSION_DATA360;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(data360, loader) {
	duckdb::LoadInternal(loader);
}
}
