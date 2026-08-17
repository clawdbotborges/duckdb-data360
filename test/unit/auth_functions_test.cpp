#include "data360/auth_functions.hpp"
#include "data360/loopback_listener.hpp"
#include "duckdb/common/exception.hpp"

#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace data360 {
void RecordAuthCompletionFailure(const std::function<bool()> &is_interrupted,
                                 const std::function<void(AuthFault)> &record,
                                 std::exception_ptr failure);
}

namespace {
void Require(bool value, const char *message) {
	if (!value) throw std::runtime_error(message);
}

template <class FN> void Throws(FN &&fn, const char *message) {
	try { fn(); } catch (const std::exception &) { return; }
	throw std::runtime_error(message);
}

class FakeClock final : public data360::AuthClock {
public:
	uint64_t NowMs() const override { return 1000; }
};

class SequenceRandom final : public data360::RandomSource {
public:
	void Fill(uint8_t *out, size_t length) override {
		for (size_t i = 0; i < length; i++) out[i] = static_cast<uint8_t>(i + sequence);
		sequence++;
	}
private:
	uint8_t sequence = 0;
};

class RequestAcceptor final : public data360::LoopbackAcceptor {
public:
	explicit RequestAcceptor(std::string request_p) : request(std::move(request_p)) {}
	void Bind(const std::string &, uint16_t) override {}
	std::string AcceptOne(size_t, uint64_t, const data360::CancellationCheck &) override { return request; }
	void Respond(const std::string &) override {}
	void Close() noexcept override {}
private:
	std::string request;
};

class ThrowingAcceptor final : public data360::LoopbackAcceptor {
public:
	explicit ThrowingAcceptor(bool cancelled_p) : cancelled(cancelled_p) {}
	void Bind(const std::string &, uint16_t) override {}
	std::string AcceptOne(size_t, uint64_t, const data360::CancellationCheck &) override {
		if (cancelled) throw data360::CallbackCancelled();
		throw std::runtime_error("sensitive listener failure");
	}
	void Respond(const std::string &) override {}
	void Close() noexcept override {}
private:
	bool cancelled;
};

void TestSafeInputValidation() {
	data360::ValidateAuthClientId("3MVG9_safe.client-id_123");
	data360::ValidateAuthSecretName("salesforce_session_1");
	Throws([] { data360::ValidateAuthClientId(""); }, "empty client id accepted");
	Throws([] { data360::ValidateAuthClientId("client id"); }, "client id with whitespace accepted");
	Throws([] { data360::ValidateAuthSecretName("bad-name"); }, "unsafe secret name accepted");
	Throws([] { data360::ValidateAuthSecretName("1bad"); }, "digit-leading secret name accepted");
	Throws([] { data360::ValidateAuthSecretName(std::string(129, 'a')); }, "oversized secret name accepted");
}

void TestSafeStatusProjection() {
	data360::AuthSessionSnapshot pending {data360::AuthSessionStatus::PENDING_USER_ACTION, "safe_name", 123, std::nullopt};
	auto row = data360::ProjectAuthStatus("opaque-id", pending);
	Require(row.auth_id == "opaque-id" && row.status == "PENDING_USER_ACTION", "pending projection wrong");
	Require(row.error_code.empty() && row.message.empty(), "pending projection invented an error");

	data360::AuthSessionSnapshot failed {data360::AuthSessionStatus::FAILED, "safe_name", 456,
	                                     data360::AuthFault::TOKEN_EXCHANGE_FAILED};
	row = data360::ProjectAuthStatus("opaque-id", failed);
	Require(row.error_code == "D360-AUTH-010", "failed projection omitted stable code");
	Require(row.message.find("sentinel-code-state-verifier-token-provider-body") == std::string::npos,
	        "projection leaked sensitive marker");
}
void TestAuthCompletionPreservesTypedFaults() {
	for (const auto fault : {data360::AuthFault::DATA360_EXCHANGE_FAILED,
	                         data360::AuthFault::ORG_POLICY_DENIED}) {
		std::optional<data360::AuthFault> recorded;
		std::exception_ptr failure;
		try { throw data360::AuthFaultException(fault); } catch (...) { failure = std::current_exception(); }
		data360::RecordAuthCompletionFailure([] { return false; },
		                                     [&](data360::AuthFault value) { recorded = value; }, failure);
		Require(recorded && *recorded == fault, "auth completion collapsed a typed provider fault");
	}
}

void TestAuthCompletionPreservesInterruption() {
	bool recorded = false;
	std::exception_ptr failure;
	try { throw std::runtime_error("transport failed during interrupt"); } catch (...) { failure = std::current_exception(); }
	try {
		data360::RecordAuthCompletionFailure([] { return true; },
		                                     [&](data360::AuthFault) { recorded = true; }, failure);
	} catch (const duckdb::InterruptException &) {
		Require(!recorded, "interrupted auth completion recorded a stable failure");
		return;
	} catch (...) {
		throw std::runtime_error("auth completion interruption used the wrong exception type");
	}
	throw std::runtime_error("auth completion interruption was swallowed");
}

void TestAuthCompletionMapsUnknownFailureSafely() {
	std::optional<data360::AuthFault> recorded;
	std::exception_ptr failure;
	try { throw std::runtime_error("secret unknown detail"); } catch (...) { failure = std::current_exception(); }
	data360::RecordAuthCompletionFailure([] { return false; },
	                                     [&](data360::AuthFault value) { recorded = value; }, failure);
	Require(recorded && *recorded == data360::AuthFault::TOKEN_EXCHANGE_FAILED,
	        "unknown auth completion failure did not map to safe fallback");
}

void TestListenerThreadReportsStateMismatchAndMalformedCallback() {
	FakeClock clock;
	SequenceRandom random;
	data360::AuthSessionRegistry registry(random, clock);

	auto mismatch_id = registry.Create("expected", "verifier", 10000, nullptr);
	data360::FixedLoopbackListener mismatch_listener(std::make_unique<RequestAcceptor>(
	    "GET /oauth/callback?code=secret-code&state=wrong HTTP/1.1\r\nHost: localhost:8910\r\n\r\n"));
	std::thread mismatch_worker([&] {
		data360::ProcessAuthCallback(mismatch_listener, registry, mismatch_id, 5000, [] { return false; });
	});
	mismatch_worker.join();
	auto mismatch = registry.Snapshot(mismatch_id);
	Require(mismatch.status == data360::AuthSessionStatus::FAILED &&
	            mismatch.fault == data360::AuthFault::STATE_MISMATCH,
	        "listener thread swallowed callback state mismatch");

	auto malformed_id = registry.Create("expected2", "verifier2", 10000, nullptr);
	data360::FixedLoopbackListener malformed_listener(std::make_unique<RequestAcceptor>(
	    "GET /oauth/callback?code=%GG&state=expected2 HTTP/1.1\r\nHost: localhost:8910\r\n\r\n"));
	std::thread malformed_worker([&] {
		data360::ProcessAuthCallback(malformed_listener, registry, malformed_id, 5000, [] { return false; });
	});
	malformed_worker.join();
	auto malformed = registry.Snapshot(malformed_id);
	Require(malformed.status == data360::AuthSessionStatus::FAILED &&
	            malformed.fault == data360::AuthFault::CALLBACK_PROTOCOL_ERROR,
	        "listener thread swallowed malformed callback failure");

	auto unexpected_id = registry.Create("expected3", "verifier3", 10000, nullptr);
	data360::FixedLoopbackListener unexpected_listener(std::make_unique<ThrowingAcceptor>(false));
	data360::ProcessAuthCallback(unexpected_listener, registry, unexpected_id, 5000, [] { return false; });
	auto unexpected = registry.Snapshot(unexpected_id);
	Require(unexpected.status == data360::AuthSessionStatus::FAILED &&
	            unexpected.fault == data360::AuthFault::CALLBACK_PROTOCOL_ERROR,
	        "unexpected listener failure did not map to the safe callback fault");

	auto cancelled_id = registry.Create("expected4", "verifier4", 10000, nullptr);
	data360::FixedLoopbackListener cancelled_listener(std::make_unique<ThrowingAcceptor>(true));
	data360::ProcessAuthCallback(cancelled_listener, registry, cancelled_id, 5000, [] { return true; });
	Require(registry.Snapshot(cancelled_id).status == data360::AuthSessionStatus::PENDING_USER_ACTION,
	        "callback cancellation reported a worker failure");
	registry.Cancel(cancelled_id);
}
} // namespace

int main() {
	try {
		TestSafeInputValidation();
		TestSafeStatusProjection();
		TestAuthCompletionPreservesTypedFaults();
		TestAuthCompletionPreservesInterruption();
		TestAuthCompletionMapsUnknownFailureSafely();
		TestListenerThreadReportsStateMismatchAndMalformedCallback();
		std::cout << "auth_functions tests passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "auth_functions test failed: " << error.what() << '\n';
		return 1;
	}
}
