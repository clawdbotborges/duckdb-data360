#define DUCKDB_EXTENSION_MAIN

#include "data360_extension.hpp"
#include "data360/native_runtime.hpp"
#include "data360/scan_runtime.hpp"
#include "data360/type_mapping.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/main/client_context.hpp"

#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <thread>

namespace duckdb {
namespace {

class ProcessLocalData360Secret final : public KeyValueSecret {
public:
	ProcessLocalData360Secret(const vector<string> &scope, const string &type, const string &provider, const string &name)
	    : KeyValueSecret(scope, type, provider, name) {
		serializable = false;
	}

	ProcessLocalData360Secret(const ProcessLocalData360Secret &other) : KeyValueSecret(other) {
		serializable = false;
	}

	unique_ptr<const BaseSecret> Clone() const override {
		return make_uniq<ProcessLocalData360Secret>(*this);
	}
};

class Data360BindData final : public TableFunctionData {
public:
	vector<LogicalType> types;
	vector<string> names;
	std::vector<data360::ColumnMetadata> metadata;
	string sql;
	string login_url;
	string broker_path;

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

class Data360GlobalState final : public GlobalTableFunctionState {
public:
	explicit Data360GlobalState(ClientContext &context)
	    : runtime(context), transport(&runtime), codec(), client(transport, codec, runtime) {
	}

	DuckDBRuntime runtime;
	data360::CurlProcessTransport transport;
	data360::JsonQueryResponseCodec codec;
	data360::QueryApiV3Client client;
	std::unique_ptr<data360::ChunkSource> source;
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

unique_ptr<BaseSecret> CreateProcessSecret(ClientContext &, CreateSecretInput &input) {
	if (input.persist_type == SecretPersistType::PERSISTENT) {
		throw InvalidInputException("Data 360 process secrets must be temporary");
	}
	auto secret = make_uniq<ProcessLocalData360Secret>(input.scope, input.type, input.provider, input.name);
	if (!secret->TrySetValue("login_url", input) || secret->TryGetValue("login_url", true).GetValue<string>().empty()) {
		throw InvalidInputException("Data 360 process secret requires login_url");
	}
	return std::move(secret);
}

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
	if (secret->secret->GetProvider() != "process") {
		throw BinderException("Data 360 secret '%s' uses an unsupported provider", secret_name);
	}
	const auto *broker_path = std::getenv("SOWVI_DATA360_BROKER_PATH");
	if (!broker_path || !*broker_path) {
		throw BinderException("SOWVI_DATA360_BROKER_PATH is required for the Data 360 process provider");
	}
	const auto &key_value = dynamic_cast<const KeyValueSecret &>(*secret->secret);
	const auto login_url = key_value.TryGetValue("login_url", true).GetValue<string>();
	DuckDBRuntime runtime(context);
	data360::QueryCredentials credentials;
	try {
		credentials = data360::ResolveProcessCapability(broker_path, login_url, &runtime);
	} catch (...) {
		if (context.IsInterrupted()) throw InterruptException();
		throw BinderException("Data 360 capability resolution failed");
	}
	try {
		data360::CurlProcessTransport transport(&runtime);
		data360::JsonQueryResponseCodec codec;
		data360::QueryApiV3Client client(transport, codec, runtime);
		const auto sql = input.inputs[0].GetValue<string>();
		auto result = client.ExecuteMetadata(sql, credentials);
		if (result.metadata.empty()) {
			throw BinderException("Data 360 query returned no metadata");
		}
		auto bind = make_uniq<Data360BindData>();
		bind->sql = sql;
		bind->login_url = login_url;
		bind->broker_path = broker_path;
		for (const auto &column : result.metadata) {
			if (column.name.empty()) {
				throw BinderException("Data 360 query returned an unnamed column");
			}
			const auto mapping = data360::MapData360Type(column.type);
			auto logical_type = BindLogicalType(mapping);
			names.push_back(column.name);
			return_types.push_back(logical_type);
			bind->types.push_back(std::move(logical_type));
			bind->names.push_back(column.name);
			bind->metadata.push_back(column);
		}
		return std::move(bind);
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
		credentials = data360::ResolveProcessCapability(bind.broker_path, bind.login_url, &state->runtime);
	} catch (...) {
		if (context.IsInterrupted()) throw InterruptException();
		throw InvalidInputException("Data 360 capability resolution failed");
	}
	try {
		auto prepared = state->client.Prepare(bind.sql, credentials);
		const auto &metadata = prepared.Metadata();
		if (!data360::MetadataCompatible(bind.metadata, metadata)) {
			throw InvalidInputException("Data 360 result schema changed after binding");
		}
		state->source = std::make_unique<data360::CursorChunkSource>(std::move(prepared).OpenCursor());
		return std::move(state);
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
		data360::FillDataChunk(*state.source, state.scan_buffer, bind.types, bind.names, output);
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
	secret_type.default_provider = "process";
	loader.RegisterSecretType(std::move(secret_type));

	CreateSecretFunction secret_function;
	secret_function.secret_type = "data360";
	secret_function.provider = "process";
	secret_function.function = CreateProcessSecret;
	secret_function.named_parameters["login_url"] = LogicalType::VARCHAR;
	loader.RegisterFunction(std::move(secret_function));

	TableFunction function("data360_query", {LogicalType::VARCHAR, LogicalType::VARCHAR}, Data360QueryFunction,
	                       Data360QueryBind, Data360QueryInit);
	loader.RegisterFunction(function);
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
