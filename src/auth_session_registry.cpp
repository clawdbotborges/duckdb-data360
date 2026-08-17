#include "data360/auth_session_registry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"

#include <algorithm>
#include <chrono>
#include <functional>
#include <limits>
#include <utility>
#include <vector>

namespace data360 {
namespace {

void SecureClear(std::string &value) noexcept {
	volatile char *bytes = value.empty() ? nullptr : &value[0];
	for (size_t i = 0; i < value.size(); i++) {
		bytes[i] = 0;
	}
	value.clear();
	value.shrink_to_fit();
}

bool Terminal(AuthSessionStatus status) {
	return status == AuthSessionStatus::AUTHORIZED || status == AuthSessionStatus::ACCESS_DENIED ||
	       status == AuthSessionStatus::EXPIRED || status == AuthSessionStatus::CANCELLED ||
	       status == AuthSessionStatus::FAILED;
}

void StopOwners(std::vector<std::shared_ptr<AuthCallbackOwner>> &owners) noexcept {
	for (auto &owner : owners) {
		owner->StopAndJoin();
	}
}

} // namespace

struct AuthSessionRegistry::Session {
	AuthSessionStatus status = AuthSessionStatus::PENDING_USER_ACTION;
	std::string expected_state;
	std::string pkce_verifier;
	std::string authorization_code;
	std::string login_origin;
	std::string client_id;
	std::string secret_name;
	uint64_t expires_at_ms = 0;
	int64_t expires_at_utc_micros = 0;
	std::optional<AuthFault> fault;
	std::shared_ptr<AuthCallbackOwner> callback_owner;
	~Session() {
		SecureClear(expected_state);
		SecureClear(pkce_verifier);
		SecureClear(authorization_code);
	}
};

struct AuthSessionRegistry::Credential {
	std::string instance_url;
	std::string access_token;
	uint64_t expires_at_ms = 0;
	~Credential() {
		SecureClear(access_token);
	}
};

uint64_t SteadyAuthClock::NowMs() const {
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
	    std::chrono::steady_clock::now().time_since_epoch()).count());
}

AuthCompletionMaterial::AuthCompletionMaterial(std::string code, std::string verifier, std::string login_origin_p,
                                               std::string client_id_p, std::string secret_name_p)
    : authorization_code(std::move(code)), pkce_verifier(std::move(verifier)),
      login_origin(std::move(login_origin_p)), client_id(std::move(client_id_p)), secret_name(std::move(secret_name_p)) {
}
AuthCompletionMaterial::~AuthCompletionMaterial() {
	SecureClear(authorization_code);
	SecureClear(pkce_verifier);
}
AuthCompletionMaterial::AuthCompletionMaterial(AuthCompletionMaterial &&other) noexcept
    : authorization_code(std::move(other.authorization_code)), pkce_verifier(std::move(other.pkce_verifier)),
      login_origin(std::move(other.login_origin)), client_id(std::move(other.client_id)),
      secret_name(std::move(other.secret_name)) {
}
AuthCompletionMaterial &AuthCompletionMaterial::operator=(AuthCompletionMaterial &&other) noexcept {
	if (this != &other) {
		SecureClear(authorization_code);
		SecureClear(pkce_verifier);
		authorization_code = std::move(other.authorization_code);
		pkce_verifier = std::move(other.pkce_verifier);
		login_origin = std::move(other.login_origin);
		client_id = std::move(other.client_id);
		secret_name = std::move(other.secret_name);
	}
	return *this;
}

AuthSessionRegistry::AuthSessionRegistry(RandomSource &random_p, const AuthClock &clock_p)
    : random(random_p), clock(clock_p) {
}
AuthSessionRegistry::~AuthSessionRegistry() {
	std::map<std::string, std::unique_ptr<Session>> owned;
	{
		std::lock_guard<std::mutex> guard(mutex);
		owned.swap(sessions);
		credentials.clear();
	}
	for (auto &entry : owned) {
		if (entry.second->callback_owner) {
			entry.second->callback_owner->StopAndJoin();
		}
	}
}

bool AuthSessionRegistry::IsActive(AuthSessionStatus status) const {
	return !Terminal(status);
}
AuthSessionRegistry::Session &AuthSessionRegistry::FindLocked(const std::string &auth_id) {
	auto found = sessions.find(auth_id);
	if (found == sessions.end()) {
		throw AuthSessionError(AuthFault::AUTH_SESSION_NOT_FOUND);
	}
	return *found->second;
}
void AuthSessionRegistry::TerminalLocked(Session &session, AuthSessionStatus status, std::optional<AuthFault> fault,
                                         std::shared_ptr<AuthCallbackOwner> &owner, bool release_owner) {
	if (Terminal(session.status)) {
		return;
	}
	session.status = status;
	session.fault = fault;
	SecureClear(session.expected_state);
	SecureClear(session.pkce_verifier);
	SecureClear(session.authorization_code);
	if (release_owner) {
		owner = std::move(session.callback_owner);
	}
}
void AuthSessionRegistry::ExpireLocked(Session &session, uint64_t now, std::shared_ptr<AuthCallbackOwner> &owner,
                                       bool release_owner) {
	// BeginCompletion transfers terminal-transition ownership to the completion
	// path. Observers, expiry sweeps, and cancellation must not invalidate the
	// catalog/credential commit once that hand-off has happened.
	if (session.status != AuthSessionStatus::COMPLETING && IsActive(session.status) && now >= session.expires_at_ms) {
		TerminalLocked(session, AuthSessionStatus::EXPIRED, AuthFault::SESSION_EXPIRED, owner, release_owner);
	}
}

std::string AuthSessionRegistry::Create(AuthStartRequest request) {
	if (request.expected_state.empty() || request.pkce_verifier.empty() || request.expires_at_monotonic_ms == 0) {
		throw AuthSessionError(AuthFault::CALLBACK_PROTOCOL_ERROR);
	}
	std::vector<std::shared_ptr<AuthCallbackOwner>> expired_owners;
	std::unique_lock<std::mutex> guard(mutex);
	const auto now = clock.NowMs();
	if (request.expires_at_monotonic_ms <= now) {
		throw AuthSessionError(AuthFault::SESSION_EXPIRED);
	}
	for (auto &entry : sessions) {
		std::shared_ptr<AuthCallbackOwner> owner;
		ExpireLocked(*entry.second, now, owner);
		if (owner) {
			expired_owners.push_back(std::move(owner));
		}
	}
	while (sessions.size() >= 32) {
		auto old = std::find_if(sessions.begin(), sessions.end(),
		                        [](const auto &entry) { return Terminal(entry.second->status); });
		if (old == sessions.end()) {
			break;
		}
		sessions.erase(old);
	}
	size_t active = 0;
	for (auto &entry : sessions) {
		if (IsActive(entry.second->status)) {
			active++;
		}
	}
	if (active >= 4) {
		guard.unlock();
		StopOwners(expired_owners);
		throw AuthSessionError(AuthFault::AUTH_SESSION_LIMIT_REACHED);
	}
	std::string id;
	for (size_t attempt = 0; attempt < 16; attempt++) {
		id = GenerateOpaqueId(random);
		if (!sessions.count(id) && !credentials.count(id)) {
			break;
		}
		id.clear();
	}
	if (id.empty()) {
		guard.unlock();
		StopOwners(expired_owners);
		throw AuthSessionError(AuthFault::AUTH_SESSION_LIMIT_REACHED);
	}
	auto session = std::make_unique<Session>();
	session->expected_state = std::move(request.expected_state);
	session->pkce_verifier = std::move(request.pkce_verifier);
	session->login_origin = std::move(request.login_origin);
	session->client_id = std::move(request.client_id);
	session->secret_name = std::move(request.secret_name);
	session->expires_at_ms = request.expires_at_monotonic_ms;
	session->expires_at_utc_micros = request.expires_at_utc_micros;
	session->callback_owner = std::move(request.callback_owner);
	sessions.emplace(id, std::move(session));
	guard.unlock();
	StopOwners(expired_owners);
	return id;
}

std::string AuthSessionRegistry::Create(std::string expected_state, std::string pkce_verifier, uint64_t ttl_ms,
                                        std::shared_ptr<AuthCallbackOwner> callback_owner) {
	const auto now = clock.NowMs();
	if (ttl_ms == 0 || ttl_ms > std::numeric_limits<uint64_t>::max() - now) {
		throw AuthSessionError(AuthFault::SESSION_EXPIRED);
	}
	AuthStartRequest request;
	request.expected_state = std::move(expected_state);
	request.pkce_verifier = std::move(pkce_verifier);
	request.expires_at_monotonic_ms = now + ttl_ms;
	request.callback_owner = std::move(callback_owner);
	return Create(std::move(request));
}

AuthSessionSnapshot AuthSessionRegistry::Snapshot(const std::string &auth_id) {
	std::shared_ptr<AuthCallbackOwner> owner;
	AuthSessionSnapshot result;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto &session = FindLocked(auth_id);
		ExpireLocked(session, clock.NowMs(), owner);
		if (Terminal(session.status) && !owner) {
			owner = std::move(session.callback_owner);
		}
		result = {session.status, session.secret_name, session.expires_at_utc_micros, session.fault};
	}
	if (owner) {
		owner->StopAndJoin();
	}
	return result;
}

AuthSessionStatus AuthSessionRegistry::Status(const std::string &auth_id) {
	return Snapshot(auth_id).status;
}

void AuthSessionRegistry::ReceiveCallback(const std::string &auth_id, const std::string &state,
                                          std::string authorization_code) {
	std::shared_ptr<AuthCallbackOwner> expired_owner;
	bool mismatch = false;
	bool unavailable = false;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto &session = FindLocked(auth_id);
		// Callback handlers execute on the callback worker. A terminal transition
		// must retain its owner for a non-worker caller to reap.
		ExpireLocked(session, clock.NowMs(), expired_owner, false);
		if (session.status != AuthSessionStatus::PENDING_USER_ACTION || authorization_code.empty()) {
			unavailable = true;
		} else if (!ConstantTimeEquals(session.expected_state, state)) {
			// This can run on the callback worker. Retain the owner so it cannot
			// destroy or join itself; a SQL caller or database teardown reaps it.
			TerminalLocked(session, AuthSessionStatus::FAILED, AuthFault::STATE_MISMATCH, expired_owner, false);
			mismatch = true;
		} else {
			session.authorization_code = std::move(authorization_code);
			SecureClear(session.expected_state);
			session.status = AuthSessionStatus::CALLBACK_RECEIVED;
		}
	}
	if (expired_owner) {
		expired_owner->StopAndJoin();
	}
	if (unavailable) {
		throw AuthSessionError(AuthFault::CALLBACK_PROTOCOL_ERROR);
	}
	if (mismatch) {
		throw AuthSessionError(AuthFault::STATE_MISMATCH);
	}
}

void AuthSessionRegistry::ReceiveDenied(const std::string &auth_id, const std::string &state) {
	std::shared_ptr<AuthCallbackOwner> unused;
	bool mismatch = false;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto &session = FindLocked(auth_id);
		ExpireLocked(session, clock.NowMs(), unused, false);
		if (session.status != AuthSessionStatus::PENDING_USER_ACTION) {
			throw AuthSessionError(AuthFault::CALLBACK_PROTOCOL_ERROR);
		}
		if (!ConstantTimeEquals(session.expected_state, state)) {
			TerminalLocked(session, AuthSessionStatus::FAILED, AuthFault::STATE_MISMATCH, unused, false);
			mismatch = true;
		} else {
			TerminalLocked(session, AuthSessionStatus::ACCESS_DENIED, AuthFault::USER_DENIED, unused, false);
		}
	}
	if (mismatch) throw AuthSessionError(AuthFault::STATE_MISMATCH);
}

AuthCompletionMaterial AuthSessionRegistry::BeginCompletion(const std::string &auth_id) {
	std::shared_ptr<AuthCallbackOwner> owner;
	std::unique_lock<std::mutex> guard(mutex);
	auto &session = FindLocked(auth_id);
	ExpireLocked(session, clock.NowMs(), owner);
	if (session.status != AuthSessionStatus::CALLBACK_RECEIVED) {
		guard.unlock();
		if (owner) {
			owner->StopAndJoin();
		}
		throw AuthSessionError(AuthFault::CALLBACK_PROTOCOL_ERROR);
	}
	session.status = AuthSessionStatus::COMPLETING;
	AuthCompletionMaterial result(std::move(session.authorization_code), std::move(session.pkce_verifier),
	                              session.login_origin, session.client_id, session.secret_name);
	guard.unlock();
	return result;
}

void AuthSessionRegistry::FinishAuthorized(const std::string &auth_id) {
	std::shared_ptr<AuthCallbackOwner> owner;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto &session = FindLocked(auth_id);
		if (session.status != AuthSessionStatus::COMPLETING) {
			throw AuthSessionError(AuthFault::CALLBACK_PROTOCOL_ERROR);
		}
		TerminalLocked(session, AuthSessionStatus::AUTHORIZED, std::nullopt, owner);
	}
	if (owner) {
		owner->StopAndJoin();
	}
}
void AuthSessionRegistry::FinishFailed(const std::string &auth_id, AuthFault fault) {
	std::shared_ptr<AuthCallbackOwner> owner;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto &session = FindLocked(auth_id);
		if (session.status != AuthSessionStatus::COMPLETING) {
			throw AuthSessionError(AuthFault::CALLBACK_PROTOCOL_ERROR);
		}
		TerminalLocked(session, AuthSessionStatus::FAILED, fault, owner);
	}
	if (owner) {
		owner->StopAndJoin();
	}
}
void AuthSessionRegistry::Fail(const std::string &auth_id, AuthFault fault) {
	std::shared_ptr<AuthCallbackOwner> owner;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto &session = FindLocked(auth_id);
		// Callback/listener faults are stale once BeginCompletion has handed
		// exclusive finalization ownership to the completion path.
		if (session.status == AuthSessionStatus::COMPLETING) return;
		TerminalLocked(session, AuthSessionStatus::FAILED, fault, owner);
	}
	if (owner) {
		owner->StopAndJoin();
	}
}
void AuthSessionRegistry::Cancel(const std::string &auth_id) {
	std::shared_ptr<AuthCallbackOwner> owner;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto &session = FindLocked(auth_id);
		// Once completion owns the session, cancellation must not invalidate the
		// catalog/credential commit between installation and FinishAuthorized.
		// Cancellation before BeginCompletion remains terminal; after it starts,
		// the completion path alone commits or fails the session.
		if (session.status == AuthSessionStatus::COMPLETING) {
			return;
		}
		TerminalLocked(session, AuthSessionStatus::CANCELLED, std::nullopt, owner);
	}
	if (owner) {
		owner->StopAndJoin();
	}
}
void AuthSessionRegistry::StopCallback(const std::string &auth_id) noexcept {
	std::shared_ptr<AuthCallbackOwner> owner;
	{
		std::lock_guard<std::mutex> guard(mutex);
		auto found = sessions.find(auth_id);
		if (found != sessions.end()) {
			owner = std::move(found->second->callback_owner);
		}
	}
	if (owner) {
		owner->StopAndJoin();
	}
}

std::string AuthSessionRegistry::StoreCredential(std::string instance_url, std::string access_token,
                                                 uint64_t expires_at_ms) {
	if (instance_url.empty() || access_token.empty() || expires_at_ms <= clock.NowMs()) {
		throw AuthSessionError(AuthFault::REAUTH_REQUIRED);
	}
	std::lock_guard<std::mutex> guard(mutex);
	const auto now = clock.NowMs();
	for (auto it = credentials.begin(); it != credentials.end();) {
		if (now >= it->second->expires_at_ms) {
			it = credentials.erase(it);
		} else {
			++it;
		}
	}
	if (credentials.size() >= 16) {
		throw AuthSessionError(AuthFault::AUTH_SESSION_LIMIT_REACHED);
	}
	std::string id;
	for (size_t attempt = 0; attempt < 16; attempt++) {
		id = GenerateOpaqueId(random);
		if (!sessions.count(id) && !credentials.count(id)) {
			break;
		}
		id.clear();
	}
	if (id.empty()) {
		throw AuthSessionError(AuthFault::AUTH_SESSION_LIMIT_REACHED);
	}
	auto value = std::make_unique<Credential>();
	value->instance_url = std::move(instance_url);
	value->access_token = std::move(access_token);
	value->expires_at_ms = expires_at_ms;
	credentials.emplace(id, std::move(value));
	return id;
}
QueryCredentials AuthSessionRegistry::ResolveCredential(const std::string &credential_id) {
	std::lock_guard<std::mutex> guard(mutex);
	auto found = credentials.find(credential_id);
	if (found == credentials.end()) {
		throw AuthSessionError(AuthFault::REAUTH_REQUIRED);
	}
	if (clock.NowMs() >= found->second->expires_at_ms) {
		credentials.erase(found);
		throw AuthSessionError(AuthFault::REAUTH_REQUIRED);
	}
	return {found->second->instance_url, found->second->access_token};
}
void AuthSessionRegistry::RemoveCredential(const std::string &credential_id) noexcept {
	std::lock_guard<std::mutex> guard(mutex);
	credentials.erase(credential_id);
}
std::unique_lock<std::mutex> AuthSessionRegistry::LockSecretReplacement(const std::string &secret_name) {
	const auto stripe = std::hash<std::string> {}(secret_name) % secret_replacement_mutexes.size();
	return std::unique_lock<std::mutex>(secret_replacement_mutexes[stripe]);
}
size_t AuthSessionRegistry::SessionCount() const {
	std::lock_guard<std::mutex> guard(mutex);
	return sessions.size();
}
size_t AuthSessionRegistry::CredentialCount() const {
	std::lock_guard<std::mutex> guard(mutex);
	return credentials.size();
}

const char *AuthStatusName(AuthSessionStatus status) {
	switch (status) {
	case AuthSessionStatus::PENDING_USER_ACTION: return "PENDING_USER_ACTION";
	case AuthSessionStatus::CALLBACK_RECEIVED: return "CALLBACK_RECEIVED";
	case AuthSessionStatus::COMPLETING: return "CALLBACK_RECEIVED";
	case AuthSessionStatus::AUTHORIZED: return "AUTHORIZED";
	case AuthSessionStatus::ACCESS_DENIED: return "ACCESS_DENIED";
	case AuthSessionStatus::EXPIRED: return "EXPIRED";
	case AuthSessionStatus::CANCELLED: return "CANCELLED";
	case AuthSessionStatus::FAILED: return "FAILED";
	}
	return "FAILED";
}

} // namespace data360

namespace duckdb {

Data360AuthState::Data360AuthState() : registry(random, clock) {
}
string Data360AuthState::ObjectType() {
	return "data360_auth_state_v1";
}
string Data360AuthState::GetObjectType() {
	return ObjectType();
}
optional_idx Data360AuthState::GetEstimatedCacheMemory() const {
	return optional_idx {};
}
Data360AuthState &Data360AuthState::Get(ClientContext &context) {
	auto &cache = ObjectCache::GetObjectCache(context);
	auto state = cache.GetOrCreate<Data360AuthState>(ObjectType());
	if (!state) {
		throw InternalException("Data 360 auth state cache key collision");
	}
	return *state;
}
Data360AuthState &Data360AuthState::Get(DatabaseInstance &db) {
	auto state = db.GetObjectCache().GetOrCreate<Data360AuthState>(ObjectType());
	if (!state) {
		throw InternalException("Data 360 auth state cache key collision");
	}
	return *state;
}
data360::AuthSessionRegistry &Data360AuthState::Registry() {
	return registry;
}
data360::RandomSource &Data360AuthState::Random() {
	return random;
}

} // namespace duckdb
