#include "data360/auth_session_registry.hpp"
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include "duckdb.hpp"
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace data360;
namespace {
void Require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
template <class FN> void Throws(FN &&fn, const char *message) { try { fn(); } catch (const AuthSessionError &) { return; } throw std::runtime_error(message); }
class FakeClock final : public AuthClock { public: uint64_t now = 1000; uint64_t NowMs() const override { return now; } };
class SequenceRandom final : public RandomSource {
public:
	uint64_t call = 0;
	void Fill(uint8_t *out, size_t length) override {
		for (size_t i = 0; i < length; i++) out[i] = static_cast<uint8_t>((call >> ((i % 8) * 8)) ^ i);
		call++;
	}
};
class RepeatingRandom final : public RandomSource {
public:
	size_t calls = 0;
	void Fill(uint8_t *out, size_t length) override { calls++; std::fill(out, out + length, 7); }
};
class Owner final : public AuthCallbackOwner { public: int cancels = 0; void Cancel() noexcept override { cancels++; } };
class WorkerAwareOwner final : public AuthCallbackOwner {
public:
	std::thread::id worker;
	std::atomic<int> stops {0};
	std::atomic<bool> stopped_from_worker {false};
	void Cancel() noexcept override { StopAndJoin(); }
	void StopAndJoin() noexcept override {
		stops.fetch_add(1);
		if (std::this_thread::get_id() == worker) stopped_from_worker.store(true);
	}
};

void TestOpaqueIdsLimitAndIsolation() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry first(random, clock), second(random, clock);
	std::vector<std::string> ids;
	for (int i = 0; i < 4; i++) ids.push_back(first.Create("state" + std::to_string(i), "verifier", 10000, std::make_shared<Owner>()));
	Require(ids[0].size() == 22 && ids[0] != ids[1], "auth IDs must be opaque random 128-bit handles");
	Throws([&] { first.Create("state5", "verifier", 10000, nullptr); }, "fifth active session was accepted");
	Throws([&] { second.Status(ids[0]); }, "registry instances shared sessions");
}

void TestMismatchReplayCancellationAndTerminalImmutability() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	auto owner = std::make_shared<Owner>();
	auto id = registry.Create("expected", "verifier", 10000, owner);
	Throws([&] { registry.ReceiveCallback(id, "wrong", "secret-code"); }, "state mismatch was accepted");
	Require(registry.Status(id) == AuthSessionStatus::FAILED, "state mismatch must be terminal");
	Require(owner->cancels == 1, "terminal status did not promptly reap mismatched callback owner");
	Throws([&] { registry.ReceiveCallback(id, "expected", "secret-code"); }, "callback replay changed terminal state");
	registry.StopCallback(id);
	Require(owner->cancels == 1, "already-reaped callback owner was stopped twice");

	auto cancel_owner = std::make_shared<Owner>();
	auto cancelled = registry.Create("s", "v", 10000, cancel_owner);
	registry.Cancel(cancelled);
	Require(registry.Status(cancelled) == AuthSessionStatus::CANCELLED && cancel_owner->cancels == 1, "cancellation failed");
	registry.Cancel(cancelled);
	Require(cancel_owner->cancels == 1, "terminal cancellation was not immutable");
}

void TestExpiryAndConcurrentCompletionExclusion() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	auto expiring = registry.Create("s1", "v1", 10, std::make_shared<Owner>());
	clock.now += 11;
	Require(registry.Status(expiring) == AuthSessionStatus::EXPIRED, "expired session remained active");

	auto id = registry.Create("s2", "verifier2", 1000, std::make_shared<Owner>());
	registry.ReceiveCallback(id, "s2", "code2");
	Require(registry.Status(id) == AuthSessionStatus::CALLBACK_RECEIVED, "valid callback not retained");
	auto material = registry.BeginCompletion(id);
	Require(material.authorization_code == "code2" && material.pkce_verifier == "verifier2", "completion material incorrect");
	Throws([&] { registry.BeginCompletion(id); }, "concurrent/replayed completion was accepted");
	registry.FinishAuthorized(id);
	Require(registry.Status(id) == AuthSessionStatus::AUTHORIZED, "authorized completion failed");
	Throws([&] { registry.FinishFailed(id); }, "terminal authorized state was mutable");
}

void TestCredentialRegistryExpiryAndRemoval() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	auto handle = registry.StoreCredential("https://tenant.c360a.salesforce.com", "bearer-marker", clock.now + 50);
	auto credential = registry.ResolveCredential(handle);
	Require(credential.instance_url == "https://tenant.c360a.salesforce.com" && credential.access_token == "bearer-marker",
	        "credential registry did not resolve stored capability");
	registry.RemoveCredential(handle);
	Throws([&] { registry.ResolveCredential(handle); }, "removed credential remained resolvable");
	auto expiring = registry.StoreCredential("https://tenant.c360a.salesforce.com", "other-marker", clock.now + 1);
	clock.now += 2;
	Throws([&] { registry.ResolveCredential(expiring); }, "expired credential remained resolvable");
}

void TestMapsStayBoundedAndExpiredThrowsReleaseOwner() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	for (int i = 0; i < 80; i++) {
		auto id = registry.Create("s", "v", 100, nullptr);
		registry.Cancel(id);
	}
	Require(registry.SessionCount() <= 32, "terminal auth sessions grew without bound");
	for (int i = 0; i < 16; i++) registry.StoreCredential("https://tenant.c360a.salesforce.com", "token", clock.now + 1);
	clock.now += 2;
	registry.StoreCredential("https://tenant.c360a.salesforce.com", "fresh", clock.now + 10);
	Require(registry.CredentialCount() == 1, "expired credentials were not purged before capacity check");

	auto owner = std::make_shared<Owner>();
	auto expired = registry.Create("state", "verifier", 1, owner);
	clock.now += 2;
	Throws([&] { registry.ReceiveCallback(expired, "state", "code"); }, "expired callback was accepted");
	Require(owner->cancels == 0, "expired callback worker was allowed to stop itself");
	registry.StopCallback(expired);
	Require(owner->cancels == 1, "expired callback owner was not reaped by a non-worker");
}

void TestIdCollisionsHaveBoundedRetries() {
	FakeClock clock; RepeatingRandom random; AuthSessionRegistry registry(random, clock);
	registry.Create("s", "v", 100, nullptr);
	Throws([&] { registry.Create("s2", "v2", 100, nullptr); }, "repeated auth ID collision did not fail closed");
	Require(random.calls <= 17, "auth ID collision retries were unbounded");
}

void TestRequestSnapshotAndCompletionMetadata() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	AuthStartRequest request;
	request.login_origin = "https://login.salesforce.com";
	request.client_id = "client-public";
	request.secret_name = "data360_session";
	request.expected_state = "state-marker";
	request.pkce_verifier = "verifier-marker";
	request.expires_at_monotonic_ms = clock.now + 500;
	request.expires_at_utc_micros = 1700000000000000;
	auto id = registry.Create(std::move(request));
	auto snapshot = registry.Snapshot(id);
	Require(snapshot.status == AuthSessionStatus::PENDING_USER_ACTION, "snapshot status was incorrect");
	Require(snapshot.secret_name == "data360_session" && snapshot.expires_at_utc_micros == 1700000000000000,
	        "snapshot omitted safe SQL metadata");
	Require(!snapshot.fault.has_value(), "pending session had a terminal fault");
	registry.ReceiveCallback(id, "state-marker", "code-marker");
	auto material = registry.BeginCompletion(id);
	Require(material.login_origin == "https://login.salesforce.com" && material.client_id == "client-public" &&
	            material.secret_name == "data360_session",
	        "completion omitted non-secret exchange metadata");
}

void TestStableTerminalFaultSnapshots() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	auto denied = registry.Create("state", "verifier", 100, nullptr);
	registry.ReceiveDenied(denied, "state");
	auto denied_snapshot = registry.Snapshot(denied);
	Require(denied_snapshot.fault == AuthFault::USER_DENIED, "denial did not retain stable fault");
	auto mismatched_denial = registry.Create("state-mismatch", "verifier-mismatch", 100, nullptr);
	Throws([&] { registry.ReceiveDenied(mismatched_denial, "wrong"); }, "denial state mismatch was accepted");
	auto mismatch_snapshot = registry.Snapshot(mismatched_denial);
	Require(mismatch_snapshot.status == AuthSessionStatus::FAILED &&
	            mismatch_snapshot.fault == AuthFault::STATE_MISMATCH,
	        "denial state mismatch did not retain the stable mismatch fault");
	auto expired = registry.Create("state2", "verifier2", 1, nullptr);
	clock.now += 2;
	auto expired_snapshot = registry.Snapshot(expired);
	Require(expired_snapshot.fault == AuthFault::SESSION_EXPIRED, "expiry did not retain stable fault");
}

void TestWorkerOriginatedExpiryAndDenialRetainCallbackOwner() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	auto expired_owner = std::make_shared<WorkerAwareOwner>();
	auto expired = registry.Create("state", "verifier", 1, expired_owner);
	clock.now += 2;
	std::thread expiry_worker([&] {
		expired_owner->worker = std::this_thread::get_id();
		Throws([&] { registry.ReceiveCallback(expired, "state", "code"); },
		       "expired worker callback was accepted");
	});
	expiry_worker.join();
	Require(registry.Status(expired) == AuthSessionStatus::EXPIRED,
	        "worker callback expiry did not preserve EXPIRED");
	Require(!expired_owner->stopped_from_worker.load() && expired_owner->stops.load() == 1,
	        "terminal status did not safely reap expired callback owner");
	registry.StopCallback(expired);
	Require(expired_owner->stops.load() == 1, "non-worker did not reap expired callback owner");

	auto denied_owner = std::make_shared<WorkerAwareOwner>();
	auto denied = registry.Create("state2", "verifier2", 1, denied_owner);
	clock.now += 2;
	std::thread denial_worker([&] {
		denied_owner->worker = std::this_thread::get_id();
		Throws([&] { registry.ReceiveDenied(denied, "state2"); }, "expired denial callback was accepted");
	});
	denial_worker.join();
	auto snapshot = registry.Snapshot(denied);
	Require(snapshot.status == AuthSessionStatus::EXPIRED && snapshot.fault == AuthFault::SESSION_EXPIRED,
	        "expired denial overwrote EXPIRED with ACCESS_DENIED");
	Require(!denied_owner->stopped_from_worker.load() && denied_owner->stops.load() == 1,
	        "terminal status did not safely reap expired denial callback owner");
	registry.StopCallback(denied);
	Require(denied_owner->stops.load() == 1, "non-worker did not reap denied callback owner");

	auto active_denial_owner = std::make_shared<WorkerAwareOwner>();
	auto active_denial = registry.Create("state3", "verifier3", 100, active_denial_owner);
	std::thread active_denial_worker([&] {
		active_denial_owner->worker = std::this_thread::get_id();
		registry.ReceiveDenied(active_denial, "state3");
	});
	active_denial_worker.join();
	Require(registry.Status(active_denial) == AuthSessionStatus::ACCESS_DENIED,
	        "active denial did not transition to ACCESS_DENIED");
	Require(active_denial_owner->stops.load() == 1 && !active_denial_owner->stopped_from_worker.load(),
	        "terminal status did not safely reap active denial callback owner");
	registry.StopCallback(active_denial);
	Require(active_denial_owner->stops.load() == 1, "non-worker did not reap active denial callback owner");
}

void TestStatusCreateAndCancelCannotExpireCompletion() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	auto id = registry.Create("state", "verifier", 1, std::make_shared<Owner>());
	registry.ReceiveCallback(id, "state", "code");
	auto material = registry.BeginCompletion(id);
	clock.now += 2;

	std::atomic<bool> start {false};
	std::exception_ptr status_error;
	std::exception_ptr create_error;
	std::thread status([&] {
		while (!start.load()) std::this_thread::yield();
		try {
			for (int i = 0; i < 100; i++) {
				Require(registry.Status(id) == AuthSessionStatus::COMPLETING,
				        "status expired an in-flight completion");
			}
		} catch (...) { status_error = std::current_exception(); }
	});
	std::thread create([&] {
		while (!start.load()) std::this_thread::yield();
		try {
			for (int i = 0; i < 100; i++) {
				auto other = registry.Create("other", "verifier", 1000, nullptr);
				registry.Cancel(other);
			}
		} catch (...) { create_error = std::current_exception(); }
	});
	std::thread cancellation([&] {
		while (!start.load()) std::this_thread::yield();
		for (int i = 0; i < 100; i++) registry.Cancel(id);
	});
	start.store(true);
	status.join();
	create.join();
	cancellation.join();
	if (status_error) std::rethrow_exception(status_error);
	if (create_error) std::rethrow_exception(create_error);
	Require(registry.Status(id) == AuthSessionStatus::COMPLETING,
	        "concurrent status/create/cancel invalidated completion");
	registry.FinishAuthorized(id);
	Require(registry.Status(id) == AuthSessionStatus::AUTHORIZED,
	        "authorized completion could not commit after concurrent observers");
}

void TestStaleCallbackFailureCannotInvalidateCompletionOwner() {
	FakeClock clock; SequenceRandom random; AuthSessionRegistry registry(random, clock);
	auto id = registry.Create("state", "verifier", 1000, nullptr);
	registry.ReceiveCallback(id, "state", "code");
	auto material = registry.BeginCompletion(id);
	registry.Fail(id, AuthFault::CALLBACK_PROTOCOL_ERROR);
	Require(registry.Status(id) == AuthSessionStatus::COMPLETING,
	        "stale callback failure invalidated completion ownership");
	registry.FinishAuthorized(id);
	Require(registry.Status(id) == AuthSessionStatus::AUTHORIZED,
	        "completion finalization failed after stale callback failure");
}

void TestDatabaseInstanceStateSharingAndIsolation() {
	duckdb::DuckDB first_db(nullptr);
	duckdb::Connection first_connection(first_db);
	duckdb::Connection second_connection(first_db);
	auto &first = duckdb::Data360AuthState::Get(*first_connection.context);
	auto &second = duckdb::Data360AuthState::Get(*second_connection.context);
	Require(&first == &second, "connections to one database did not share auth state");
	Require(!first.GetEstimatedCacheMemory().IsValid(), "auth state must be non-evictable");
	duckdb::DuckDB isolated_db(nullptr);
	auto &isolated = duckdb::Data360AuthState::Get(*isolated_db.instance);
	Require(&isolated != &first, "separate databases shared auth state");
}
} // namespace
int main() { try { TestOpaqueIdsLimitAndIsolation(); TestMismatchReplayCancellationAndTerminalImmutability(); TestExpiryAndConcurrentCompletionExclusion(); TestCredentialRegistryExpiryAndRemoval(); TestMapsStayBoundedAndExpiredThrowsReleaseOwner(); TestIdCollisionsHaveBoundedRetries(); TestRequestSnapshotAndCompletionMetadata(); TestStableTerminalFaultSnapshots(); TestWorkerOriginatedExpiryAndDenialRetainCallbackOwner(); TestStatusCreateAndCancelCannotExpireCompletion(); TestStaleCallbackFailureCannotInvalidateCompletionOwner(); TestDatabaseInstanceStateSharingAndIsolation(); std::cout << "auth_session_registry tests passed\n"; return 0; } catch (const std::exception &e) { std::cerr << "auth_session_registry test failed: " << e.what() << '\n'; return 1; } }
