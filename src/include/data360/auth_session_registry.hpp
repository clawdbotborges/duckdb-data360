#pragma once

#include "data360/error_codes.hpp"
#include "data360/oauth_pkce.hpp"
#include "data360/query_api.hpp"
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include "duckdb/storage/object_cache.hpp"
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace data360 {

class AuthSessionError : public AuthFaultException {
public:
	explicit AuthSessionError(AuthFault fault) : AuthFaultException(fault) {
	}
};

class AuthClock {
public:
	virtual ~AuthClock() = default;
	virtual uint64_t NowMs() const = 0;
};

class SteadyAuthClock final : public AuthClock {
public:
	uint64_t NowMs() const override;
};

class AuthCallbackOwner {
public:
	virtual ~AuthCallbackOwner() = default;
	virtual void Cancel() noexcept = 0;
	// Background owners override this to cancel and join. The registry invokes it
	// only from a non-callback caller or during database teardown.
	virtual void StopAndJoin() noexcept {
		Cancel();
	}
};

enum class AuthSessionStatus {
	PENDING_USER_ACTION,
	CALLBACK_RECEIVED,
	COMPLETING,
	AUTHORIZED,
	ACCESS_DENIED,
	EXPIRED,
	CANCELLED,
	FAILED
};

struct AuthStartRequest {
	std::string login_origin;
	std::string client_id;
	std::string secret_name;
	std::string expected_state;
	std::string pkce_verifier;
	uint64_t expires_at_monotonic_ms = 0;
	int64_t expires_at_utc_micros = 0;
	std::shared_ptr<AuthCallbackOwner> callback_owner;
};

struct AuthSessionSnapshot {
	AuthSessionStatus status;
	std::string secret_name;
	int64_t expires_at_utc_micros;
	std::optional<AuthFault> fault;
};

struct AuthCompletionMaterial {
	std::string authorization_code;
	std::string pkce_verifier;
	std::string login_origin;
	std::string client_id;
	std::string secret_name;
	AuthCompletionMaterial(std::string code, std::string verifier, std::string login_origin = {},
	                       std::string client_id = {}, std::string secret_name = {});
	~AuthCompletionMaterial();
	AuthCompletionMaterial(const AuthCompletionMaterial &) = delete;
	AuthCompletionMaterial &operator=(const AuthCompletionMaterial &) = delete;
	AuthCompletionMaterial(AuthCompletionMaterial &&) noexcept;
	AuthCompletionMaterial &operator=(AuthCompletionMaterial &&) noexcept;
};

class AuthSessionRegistry {
public:
	AuthSessionRegistry(RandomSource &random, const AuthClock &clock);
	~AuthSessionRegistry();
	AuthSessionRegistry(const AuthSessionRegistry &) = delete;
	AuthSessionRegistry &operator=(const AuthSessionRegistry &) = delete;

	std::string Create(AuthStartRequest request);
	// Compatibility entry point for existing core callers/tests.
	std::string Create(std::string expected_state, std::string pkce_verifier, uint64_t ttl_ms,
	                   std::shared_ptr<AuthCallbackOwner> callback_owner);
	AuthSessionStatus Status(const std::string &auth_id);
	AuthSessionSnapshot Snapshot(const std::string &auth_id);
	void ReceiveCallback(const std::string &auth_id, const std::string &state, std::string authorization_code);
	void ReceiveDenied(const std::string &auth_id, const std::string &state);
	AuthCompletionMaterial BeginCompletion(const std::string &auth_id);
	void FinishAuthorized(const std::string &auth_id);
	void FinishFailed(const std::string &auth_id, AuthFault fault = AuthFault::TOKEN_EXCHANGE_FAILED);
	void Fail(const std::string &auth_id, AuthFault fault);
	void Cancel(const std::string &auth_id);
	// Called by a non-worker owner (SQL execution or teardown) to safely reap a
	// callback task retained after a worker-originated terminal transition.
	void StopCallback(const std::string &auth_id) noexcept;

	std::string StoreCredential(std::string instance_url, std::string access_token, uint64_t expires_at_ms);
	QueryCredentials ResolveCredential(const std::string &credential_id);
	void RemoveCredential(const std::string &credential_id) noexcept;
	// Serializes temporary-secret read/replace/retire sequences per database and
	// secret name without holding the registry mutex during catalog operations.
	std::unique_lock<std::mutex> LockSecretReplacement(const std::string &secret_name);
	size_t SessionCount() const;
	size_t CredentialCount() const;

private:
	struct Session;
	struct Credential;
	Session &FindLocked(const std::string &auth_id);
	void ExpireLocked(Session &session, uint64_t now, std::shared_ptr<AuthCallbackOwner> &owner,
	                  bool release_owner = true);
	void TerminalLocked(Session &session, AuthSessionStatus status, std::optional<AuthFault> fault,
	                    std::shared_ptr<AuthCallbackOwner> &owner, bool release_owner = true);
	bool IsActive(AuthSessionStatus status) const;

	RandomSource &random;
	const AuthClock &clock;
	mutable std::mutex mutex;
	std::map<std::string, std::unique_ptr<Session>> sessions;
	std::map<std::string, std::unique_ptr<Credential>> credentials;
	std::array<std::mutex, 64> secret_replacement_mutexes;
};

const char *AuthStatusName(AuthSessionStatus status);

} // namespace data360

namespace duckdb {

class ClientContext;
class DatabaseInstance;

class Data360AuthState final : public ObjectCacheEntry {
public:
	Data360AuthState();
	~Data360AuthState() override = default;

	static string ObjectType();
	string GetObjectType() override;
	optional_idx GetEstimatedCacheMemory() const override;
	static Data360AuthState &Get(ClientContext &context);
	static Data360AuthState &Get(DatabaseInstance &db);

	data360::AuthSessionRegistry &Registry();
	data360::RandomSource &Random();

private:
	data360::SystemRandomSource random;
	data360::SteadyAuthClock clock;
	data360::AuthSessionRegistry registry;
};

} // namespace duckdb
