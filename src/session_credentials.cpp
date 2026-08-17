#include "data360/session_credentials.hpp"

#include "data360/auth_session_registry.hpp"
#include "data360/error_codes.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

SessionData360Secret::SessionData360Secret(const vector<string> &scope, const string &name, const string &session_id)
    : KeyValueSecret(scope, "data360", "oauth_pkce", name) {
	serializable = false;
	secret_map["session_id"] = Value(session_id);
	redact_keys.insert("session_id");
}

SessionData360Secret::SessionData360Secret(const SessionData360Secret &other) : KeyValueSecret(other) {
	serializable = false;
}

unique_ptr<const BaseSecret> SessionData360Secret::Clone() const {
	return make_uniq<SessionData360Secret>(*this);
}

void SessionData360Secret::Serialize(Serializer &) const {
	throw InvalidInputException(data360::FormatSafeFault(data360::AuthFault::PERSISTENCE_FORBIDDEN));
}

void InstallTemporarySessionSecret(ClientContext &context, data360::AuthSessionRegistry &registry,
                                   const string &secret_name, const string &credential_id) {
	// Replacement must outlive the caller's statement transaction. Serialize
	// read/replace/commit/retire per name and use an independent connection so a
	// later caller rollback cannot restore stale catalog metadata.
	auto replacement_lock = registry.LockSecretReplacement(secret_name);
	Connection catalog_connection(*context.db);
	string old_credential_id;
	try {
		catalog_connection.BeginTransaction();
		auto &catalog_context = *catalog_connection.context;
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(catalog_context);
		auto existing = SecretManager::Get(catalog_context).GetSecretByName(
		    transaction, secret_name, SecretManager::TEMPORARY_STORAGE_NAME);
		if (existing && existing->secret && existing->secret->GetType() == "data360" &&
		    existing->secret->GetProvider() == "oauth_pkce") {
			auto key_value = dynamic_cast<const KeyValueSecret *>(existing->secret.get());
			Value old_value;
			if (key_value && key_value->TryGetValue("session_id", old_value) && !old_value.IsNull()) {
				old_credential_id = old_value.GetValue<string>();
			}
		}

		auto secret = make_uniq<SessionData360Secret>(vector<string> {""}, secret_name, credential_id);
		SecretManager::Get(catalog_context).RegisterSecret(
		    transaction, std::move(secret), OnCreateConflict::REPLACE_ON_CONFLICT,
		    SecretPersistType::TEMPORARY, SecretManager::TEMPORARY_STORAGE_NAME);
		catalog_connection.Commit();
	} catch (...) {
		try {
			catalog_connection.Rollback();
		} catch (...) {
		}
		// A failed independent transaction cannot make the new capability
		// catalog-reachable. Preserve the displaced credential and remove only new.
		if (credential_id != old_credential_id) registry.RemoveCredential(credential_id);
		throw;
	}

	// Retirement happens only after the replacement is durably visible.
	if (!old_credential_id.empty() && old_credential_id != credential_id) {
		registry.RemoveCredential(old_credential_id);
	}
}

unique_ptr<BaseSecret> CreateOAuthPkceSecret(ClientContext &, CreateSecretInput &input) {
	if (input.persist_type == SecretPersistType::PERSISTENT) {
		throw InvalidInputException(data360::FormatSafeFault(data360::AuthFault::PERSISTENCE_FORBIDDEN));
	}
	throw InvalidInputException("Data 360 OAuth secrets are created by data360_auth_complete");
}

} // namespace duckdb
