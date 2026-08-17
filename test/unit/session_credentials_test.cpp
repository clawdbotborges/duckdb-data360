#include "data360/session_credentials.hpp"
#include "data360/auth_session_registry.hpp"
#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/serializer/binary_serializer.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

using namespace duckdb;

namespace {
void Require(bool value, const char *message) {
	if (!value) throw std::runtime_error(message);
}
template <class FN> void Throws(FN &&fn, const char *message) {
	try { fn(); } catch (const std::exception &) { return; }
	throw std::runtime_error(message);
}
class Sink final : public WriteStream {
public:
	void WriteData(const_data_ptr_t, idx_t) override {}
};


void TestCloneSerializeAndMetadataOnlyValue() {
	SessionData360Secret secret({""}, "session_secret", "opaque-session-marker");
	Require(!secret.IsSerializable(), "session secret became serializable");
	Require(secret.GetType() == "data360" && secret.GetProvider() == "oauth_pkce", "typed secret metadata is wrong");
	Value value;
	Require(secret.TryGetValue("session_id", value) && value.ToString() == "opaque-session-marker",
	        "session secret omitted opaque handle");
	Require(secret.secret_map.size() == 1 && secret.redact_keys.count("session_id") == 1,
	        "session secret contains more than opaque metadata");
	auto clone = secret.Clone();
	Require(dynamic_cast<const SessionData360Secret *>(clone.get()) != nullptr, "clone sliced derived secret");
	Require(!clone->IsSerializable(), "clone reset serializable marker");
	Sink sink;
	BinarySerializer serializer(sink);
	Throws([&] { secret.Serialize(serializer); }, "session secret serialization was allowed");
	const auto redacted = secret.ToString();
	Require(redacted.find("opaque-session-marker") == std::string::npos, "redacted secret leaked opaque handle");
}

void TestOuterRollbackCannotUndoCommittedInstall() {
	DuckDB db(nullptr);
	Connection caller(db);
	Connection observer(db);
	auto &registry = Data360AuthState::Get(*caller.context).Registry();
	auto now = data360::SteadyAuthClock().NowMs();
	auto credential_id = registry.StoreCredential("https://new.c360a.salesforce.com", "new-token-marker", now + 60000);

	caller.BeginTransaction();
	InstallTemporarySessionSecret(*caller.context, registry, "outer_rollback", credential_id);
	caller.Rollback();

	observer.BeginTransaction();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*observer.context);
	auto entry = SecretManager::Get(*observer.context).GetSecretByName(transaction, "outer_rollback", "memory");
	Require(entry && entry->persist_type == SecretPersistType::TEMPORARY,
	        "outer rollback undid independently committed temporary secret");
	const auto &stored = dynamic_cast<const KeyValueSecret &>(*entry->secret);
	Require(stored.TryGetValue("session_id").ToString() == credential_id,
	        "outer rollback left catalog and credential registry inconsistent");
	Require(registry.ResolveCredential(credential_id).access_token == "new-token-marker",
	        "outer rollback removed independently committed credential");
}

void TestTemporaryInstallAndReplacementCleanup() {
	DuckDB db(nullptr);
	Connection connection(db);
	auto &registry = Data360AuthState::Get(*connection.context).Registry();
	auto now = data360::SteadyAuthClock().NowMs();
	auto old_id = registry.StoreCredential("https://old.c360a.salesforce.com", "old-token-marker", now + 60000);
	InstallTemporarySessionSecret(*connection.context, registry, "replace_me", old_id);
	connection.BeginTransaction();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
	auto old_entry = SecretManager::Get(*connection.context).GetSecretByName(transaction, "replace_me", "memory");
	Require(old_entry && old_entry->persist_type == SecretPersistType::TEMPORARY && old_entry->storage_mode == "memory",
	        "installed secret was not temporary memory metadata");
	Require(old_entry->secret->ToString().find("old-token-marker") == std::string::npos,
	        "catalog secret leaked credential material");
	connection.Commit();

	auto new_id = registry.StoreCredential("https://new.c360a.salesforce.com", "new-token-marker", now + 60000);
	InstallTemporarySessionSecret(*connection.context, registry, "replace_me", new_id);
	Throws([&] { registry.ResolveCredential(old_id); }, "successful replacement retained old credential");
	auto resolved = registry.ResolveCredential(new_id);
	Require(resolved.access_token == "new-token-marker", "replacement removed new credential");
	connection.BeginTransaction();
	auto new_transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
	auto new_entry = SecretManager::Get(*connection.context).GetSecretByName(new_transaction, "replace_me", "memory");
	const auto &stored = dynamic_cast<const KeyValueSecret &>(*new_entry->secret);
	Require(stored.TryGetValue("session_id").ToString() == new_id, "replacement catalog handle is stale");
}

void TestFailedIndependentRegisterPreservesOldAndRemovesNew() {
	DuckDB db(nullptr);
	Connection caller(db);
	Connection blocker(db);
	Connection observer(db);
	auto &registry = Data360AuthState::Get(*caller.context).Registry();
	auto now = data360::SteadyAuthClock().NowMs();
	auto old_id = registry.StoreCredential("https://old.c360a.salesforce.com", "old-token", now + 60000);
	InstallTemporarySessionSecret(*caller.context, registry, "conflicted_replace", old_id);

	// Bypass the extension's per-name lock to deterministically force DuckDB's
	// catalog write-write conflict in the independent replacement transaction.
	blocker.BeginTransaction();
	auto blocker_transaction = CatalogTransaction::GetSystemCatalogTransaction(*blocker.context);
	auto blocker_secret = make_uniq<SessionData360Secret>(vector<string> {""}, "conflicted_replace", "blocker");
	SecretManager::Get(*blocker.context).RegisterSecret(
	    blocker_transaction, std::move(blocker_secret), OnCreateConflict::REPLACE_ON_CONFLICT,
	    SecretPersistType::TEMPORARY, SecretManager::TEMPORARY_STORAGE_NAME);

	auto new_id = registry.StoreCredential("https://new.c360a.salesforce.com", "new-token", now + 60000);
	Throws([&] { InstallTemporarySessionSecret(*caller.context, registry, "conflicted_replace", new_id); },
	       "conflicting independent register unexpectedly committed");
	blocker.Rollback();

	Require(registry.ResolveCredential(old_id).access_token == "old-token",
	        "failed independent register retired the old credential");
	Throws([&] { registry.ResolveCredential(new_id); },
	       "failed independent register retained the new credential");
	observer.BeginTransaction();
	auto observer_transaction = CatalogTransaction::GetSystemCatalogTransaction(*observer.context);
	auto entry = SecretManager::Get(*observer.context).GetSecretByName(observer_transaction, "conflicted_replace", "memory");
	const auto &stored = dynamic_cast<const KeyValueSecret &>(*entry->secret);
	Require(stored.TryGetValue("session_id").ToString() == old_id,
	        "failed independent register changed committed catalog winner");
}

void TestConcurrentSameNameReplacementIsSerializedAndRetiresDisplacedHandles() {
	DuckDB db(nullptr);
	Connection first_connection(db);
	Connection second_connection(db);
	auto &registry = Data360AuthState::Get(*first_connection.context).Registry();

	auto held = registry.LockSecretReplacement("replace_concurrently");
	std::atomic<bool> attempting {false};
	std::atomic<bool> entered {false};
	std::thread waiter([&] {
		attempting.store(true);
		auto acquired = registry.LockSecretReplacement("replace_concurrently");
		entered.store(true);
	});
	while (!attempting.load()) std::this_thread::yield();
	Require(!entered.load(), "same-name replacement ownership was not exclusive");
	held.unlock();
	waiter.join();
	Require(entered.load(), "same-name replacement ownership was not released");

	auto now = data360::SteadyAuthClock().NowMs();
	auto old_id = registry.StoreCredential("https://old.c360a.salesforce.com", "old", now + 60000);
	first_connection.BeginTransaction();
	InstallTemporarySessionSecret(*first_connection.context, registry, "replace_concurrently", old_id);
	first_connection.Commit();
	auto first_id = registry.StoreCredential("https://first.c360a.salesforce.com", "first", now + 60000);
	auto second_id = registry.StoreCredential("https://second.c360a.salesforce.com", "second", now + 60000);
	std::atomic<bool> start {false};
	std::exception_ptr first_error;
	std::exception_ptr second_error;
	std::thread first([&] {
		while (!start.load()) std::this_thread::yield();
		try {
			first_connection.BeginTransaction();
			InstallTemporarySessionSecret(*first_connection.context, registry, "replace_concurrently", first_id);
			first_connection.Commit();
		}
		catch (...) {
			first_error = std::current_exception();
			try { first_connection.Rollback(); } catch (...) {}
		}
	});
	std::thread second([&] {
		while (!start.load()) std::this_thread::yield();
		try {
			second_connection.BeginTransaction();
			InstallTemporarySessionSecret(*second_connection.context, registry, "replace_concurrently", second_id);
			second_connection.Commit();
		}
		catch (...) {
			second_error = std::current_exception();
			try { second_connection.Rollback(); } catch (...) {}
		}
	});
	start.store(true);
	first.join();
	second.join();
	Require(!(first_error && second_error), "both serialized replacements failed");

	first_connection.BeginTransaction();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*first_connection.context);
	auto entry = SecretManager::Get(*first_connection.context).GetSecretByName(transaction, "replace_concurrently", "memory");
	const auto &stored = dynamic_cast<const KeyValueSecret &>(*entry->secret);
	auto winning_id = stored.TryGetValue("session_id").ToString();
	Require(winning_id == first_id || winning_id == second_id, "concurrent replacement installed an unknown handle");
	Require(registry.CredentialCount() == 1, "concurrent replacement orphaned a displaced credential handle");
	Require(registry.ResolveCredential(winning_id).access_token == (winning_id == first_id ? "first" : "second"),
	        "catalog winner did not retain its credential handle");
}

void TestSqlFactoryRejectsForgingAndPersistence() {
	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecretInput input;
	input.type = "data360";
	input.provider = "oauth_pkce";
	input.name = "forged";
	input.persist_type = SecretPersistType::PERSISTENT;
	Throws([&] { CreateOAuthPkceSecret(*connection.context, input); }, "persistent SQL secret was accepted");
	input.persist_type = SecretPersistType::TEMPORARY;
	Throws([&] { CreateOAuthPkceSecret(*connection.context, input); }, "temporary forged SQL secret was accepted");
}
} // namespace

int main() {
	try {
		TestCloneSerializeAndMetadataOnlyValue();
		TestOuterRollbackCannotUndoCommittedInstall();
		TestTemporaryInstallAndReplacementCleanup();
		TestFailedIndependentRegisterPreservesOldAndRemovesNew();
		TestConcurrentSameNameReplacementIsSerializedAndRetiresDisplacedHandles();
		TestSqlFactoryRejectsForgingAndPersistence();
		std::cout << "session_credentials tests passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "session_credentials test failed: " << error.what() << '\n';
		return 1;
	}
}
