#define DUCKDB_EXTENSION_MAIN

#include "data360_extension.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"

namespace duckdb {
namespace {

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
	throw NotImplementedException(
	    "Live Data 360 HTTP transport is not wired in this slice; use a named Data 360 secret when transport is enabled");
}

void Data360QueryFunction(ClientContext &, TableFunctionInput &, DataChunk &output) {
	output.SetCardinality(0);
}

void LoadInternal(ExtensionLoader &loader) {
	TableFunction function("data360_query", {LogicalType::VARCHAR, LogicalType::VARCHAR}, Data360QueryFunction,
	                       Data360QueryBind);
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
