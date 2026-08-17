#include "data360/salesforce_oauth_provider.hpp"

#include <deque>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <vector>

using namespace data360;

namespace {

void Require(bool condition, const char *message) {
	if (!condition) throw std::runtime_error(message);
}

class RecordingTransport final : public HttpTransport {
public:
	std::deque<HttpResponse> responses;
	std::vector<HttpRequest> requests;
	std::function<void(size_t)> after_send;

	HttpResponse Send(const HttpRequest &request) override {
		requests.push_back(request);
		if (responses.empty()) throw std::runtime_error("unexpected request");
		auto result = responses.front();
		responses.pop_front();
		if (after_send) after_send(requests.size());
		return result;
	}
};

class FakeRuntime final : public RuntimeHooks {
public:
	bool cancelled = false;
	uint64_t now_ms = 100000;
	size_t now_calls = 0;
	bool IsCancelled() override { return cancelled; }
	uint64_t NowMs() override { now_calls++; return now_ms; }
	void SleepMs(uint64_t milliseconds) override { now_ms += milliseconds; }
};

template <class FN>
std::string RequireThrows(FN &&fn, const char *message) {
	try {
		fn();
	} catch (const std::exception &error) {
		return error.what();
	}
	throw std::runtime_error(message);
}

template <class FN>
AuthFault RequireAuthFault(FN &&fn, const char *message) {
	try {
		fn();
	} catch (const AuthFaultException &error) {
		return error.Fault();
	} catch (...) {
		throw std::runtime_error(message);
	}
	throw std::runtime_error(message);
}

OAuthExchangeOptions TestOptions() {
	OAuthExchangeOptions options;
	options.utc_now_micros = [] { return INT64_C(1700000000000000); };
	return options;
}

void QueueValidSalesforce(RecordingTransport &transport) {
	transport.responses.push_back({200, R"({"access_token":"salesforce-token","instance_url":"https://acme.my.salesforce.com","token_type":"Bearer","expires_in":3600})"});
}

void TestExactTwoPostExchangeProducesMoveOnlyCapability() {
	static_assert(!std::is_copy_constructible<Data360Capability>::value, "capability must not copy bearer material");
	static_assert(std::is_nothrow_move_constructible<Data360Capability>::value, "capability must move safely");
	RecordingTransport transport;
	transport.responses.push_back({200, R"({"access_token":"salesforce-token","instance_url":"https://acme.my.salesforce.com","token_type":"Bearer","expires_in":3600})"});
	transport.responses.push_back({200, R"({"access_token":"data360-token","instance_url":"https://tenant.c360a.salesforce.com","token_type":"Bearer","expires_in":600})"});
	FakeRuntime runtime;
	OAuthExchangeOptions options;
	options.request_timeout_ms = 4321;
	options.max_response_bytes = 64U * 1024U;
	options.expiry_skew_seconds = 30;
	options.utc_now_micros = [] { return INT64_C(1700000000000000); };
	SalesforceOAuthProvider provider(transport, runtime, options);
	const std::string verifier(43, 'v');

	auto capability = provider.Exchange(
	    AuthCompletionMaterial("code +/value", verifier, "https://login.salesforce.com/", "client +/id"));

	Require(transport.requests.size() == 2, "exchange must issue exactly two requests");
	const auto &oauth = transport.requests[0];
	Require(oauth.method == "POST", "Salesforce exchange must POST");
	Require(oauth.url == "https://login.salesforce.com/services/oauth2/token", "unexpected Salesforce endpoint");
	Require(oauth.headers.size() == 2 && oauth.headers.at("Accept") == "application/json" &&
	            oauth.headers.at("Content-Type") == "application/x-www-form-urlencoded",
	        "Salesforce exchange headers are not exact");
	Require(oauth.body == "grant_type=authorization_code&client_id=client%20%2B%2Fid&redirect_uri=http%3A%2F%2Flocalhost%3A8910%2Foauth%2Fcallback&code=code%20%2B%2Fvalue&code_verifier=" + verifier,
	        "Salesforce exchange form is not exact");
	Require(oauth.body.find("client_secret") == std::string::npos, "public-client exchange included a secret");
	Require(!oauth.follow_redirects && oauth.timeout_ms == 4321 && oauth.max_response_bytes == 64U * 1024U,
	        "Salesforce request bounds are wrong");

	const auto &data360 = transport.requests[1];
	Require(data360.method == "POST", "Data 360 exchange must POST");
	Require(data360.url == "https://acme.my.salesforce.com/services/a360/token", "unexpected Data 360 endpoint");
	Require(data360.headers == oauth.headers, "Data 360 headers are not exact");
	Require(data360.body == "grant_type=urn%3Asalesforce%3Agrant-type%3Aexternal%3Acdp&subject_token=salesforce-token&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
	        "Data 360 exchange form is not exact");
	Require(!data360.follow_redirects && data360.timeout_ms == 4321 && data360.max_response_bytes == 64U * 1024U,
	        "Data 360 request bounds are wrong");
	Require(capability.tenant_url == "https://tenant.c360a.salesforce.com", "tenant origin missing");
	Require(capability.access_token == "data360-token", "Data 360 bearer missing");
	Require(capability.expires_at_monotonic_ms == 670000, "provider expiry or safety skew is wrong");
	Require(capability.expires_at_utc_micros == INT64_C(1700000570000000), "UTC expiry is wrong");
}

void TestFixtureCompatibleMinimalResponses() {
	RecordingTransport transport;
	transport.responses.push_back({200, R"({"access_token":"salesforce-token","instance_url":"https://acme.my.salesforce.com"})"});
	transport.responses.push_back({200, R"({"access_token":"data360-token","instance_url":"https://tenant.c360a.salesforce.com"})"});
	FakeRuntime runtime;
	auto options = TestOptions();
	options.default_ttl_seconds = 300;
	SalesforceOAuthProvider provider(transport, runtime, options);
	auto capability = provider.Exchange("https://login.salesforce.com", "client",
	                                    AuthCompletionMaterial("code", std::string(43, 'v')));
	Require(capability.access_token == "data360-token", "minimal fixture response was rejected");
	Require(runtime.now_calls == 1, "expiry used more than one monotonic clock snapshot");
}

void TestNormalizesBareTrustedData360Hostname() {
	RecordingTransport transport;
	QueueValidSalesforce(transport);
	transport.responses.push_back(
	    {200, R"({"access_token":"data360-token","instance_url":"tenant.c360a.salesforce.com","token_type":"Bearer","expires_in":600})"});
	FakeRuntime runtime;
	SalesforceOAuthProvider provider(transport, runtime, TestOptions());
	auto capability = provider.Exchange("https://login.salesforce.com", "client",
	                                    AuthCompletionMaterial("code", std::string(43, 'v')));
	Require(capability.tenant_url == "https://tenant.c360a.salesforce.com",
	        "trusted bare Data 360 hostname was not normalized to HTTPS");
}

void TestRejectsMalformedDuplicateWrongTypeAndOversizedJson() {
	const std::vector<std::string> bad_salesforce = {
	    "not-json",
	    R"({"access_token":"a","access_token":"b","instance_url":"https://acme.my.salesforce.com","token_type":"Bearer","expires_in":1})",
	    R"({"access_token":7,"instance_url":"https://acme.my.salesforce.com","token_type":"Bearer","expires_in":1})",
	    R"({"access_token":"a","instance_url":"https://acme.my.salesforce.com","token_type":"bearer","expires_in":1})",
	    std::string(65537, 'x')};
	for (const auto &json : bad_salesforce) {
		RecordingTransport transport;
		transport.responses.push_back({200, json});
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		RequireThrows([&] { provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
		              "invalid Salesforce JSON was accepted");
		Require(transport.requests.size() == 1, "invalid Salesforce JSON reached Data 360 exchange");
	}

	const std::vector<std::string> bad_data360 = {
	    "[]",
	    R"({"access_token":"a","access_token":"b","instance_url":"https://tenant.c360a.salesforce.com","token_type":"Bearer"})",
	    R"({"access_token":7,"instance_url":"https://tenant.c360a.salesforce.com","token_type":"Bearer"})",
	    R"({"access_token":"a","instance_url":"https://tenant.c360a.salesforce.com","token_type":"bearer"})",
	    R"({"access_token":"a","instance_url":"https://tenant.c360a.salesforce.com","token_type":"Bearer","expires_in":"600"})",
	    "{\"access_token\":\"" + std::string(16385, 'x') + "\",\"instance_url\":\"https://tenant.c360a.salesforce.com\",\"token_type\":\"Bearer\"}"};
	for (const auto &json : bad_data360) {
		RecordingTransport transport;
		QueueValidSalesforce(transport);
		transport.responses.push_back({200, json});
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		RequireThrows([&] { provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
		              "invalid Data 360 JSON was accepted");
	}
}

void TestRejectsUntrustedOrigins() {
	for (const auto &instance : {"http://acme.my.salesforce.com", "https://salesforce.com.evil.example", "https://ACME.my.salesforce.com", "https://acme.my.salesforce.com/path"}) {
		RecordingTransport transport;
		transport.responses.push_back({200, std::string("{\"access_token\":\"sf\",\"instance_url\":\"") + instance + "\",\"token_type\":\"Bearer\",\"expires_in\":600}"});
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		RequireThrows([&] { provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
		              "untrusted Salesforce instance origin was accepted");
		Require(transport.requests.size() == 1, "untrusted Salesforce origin reached second exchange");
	}
	for (const auto &tenant : {"http://tenant.c360a.salesforce.com", "https://c360a.salesforce.com", "https://TENANT.c360a.salesforce.com", "https://tenant.c360a.salesforce.com:443", "https://tenant.c360a.salesforce.com/", "https://tenant.c360a.salesforce.com?x", "https://-tenant.c360a.salesforce.com", "evil.example", "tenant.c360a.salesforce.com.evil.example", "TENANT.c360a.salesforce.com", "tenant.c360a.salesforce.com:443", "tenant.c360a.salesforce.com/path", "tenant.c360a.salesforce.com@evil.example", "tenant.c360a.salesforce.com%2Fevil", "-tenant.c360a.salesforce.com"}) {
		RecordingTransport transport;
		QueueValidSalesforce(transport);
		transport.responses.push_back({200, std::string("{\"access_token\":\"d360\",\"instance_url\":\"") + tenant + "\",\"token_type\":\"Bearer\"}"});
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		RequireThrows([&] { provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
		              "untrusted Data 360 tenant origin was accepted");
	}
}

void TestStatusMappingCancellationExpiryAndRedaction() {
	for (const int status : {401, 403}) {
		RecordingTransport transport;
		transport.responses.push_back({status, "response-body-sentinel"});
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		const auto fault = RequireAuthFault([&] { provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code-sentinel", std::string(43, 'v'))); },
		                                    "Salesforce HTTP failure was not typed");
		Require(fault == AuthFault::TOKEN_EXCHANGE_FAILED, "Salesforce HTTP status did not map to finite fault");
	}
	for (const auto &entry : std::vector<std::pair<int, AuthFault>>{{401, AuthFault::DATA360_EXCHANGE_FAILED},
	                                                               {403, AuthFault::ORG_POLICY_DENIED}}) {
		RecordingTransport transport;
		QueueValidSalesforce(transport);
		transport.responses.push_back({entry.first, "response-body-sentinel"});
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		const auto fault = RequireAuthFault([&] { provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
		                                    "Data 360 HTTP failure was not typed");
		Require(fault == entry.second, "Data 360 HTTP status did not map to finite fault");
	}

	RecordingTransport cancelled_transport;
	QueueValidSalesforce(cancelled_transport);
	FakeRuntime cancelled_runtime;
	cancelled_transport.after_send = [&](size_t count) { if (count == 1) cancelled_runtime.cancelled = true; };
	SalesforceOAuthProvider cancelled_provider(cancelled_transport, cancelled_runtime, TestOptions());
	RequireThrows([&] { cancelled_provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
	              "cancellation before Data 360 exchange was ignored");
	Require(cancelled_transport.requests.size() == 1, "cancellation did not stop the second exchange");

	RecordingTransport late_cancel_transport;
	QueueValidSalesforce(late_cancel_transport);
	late_cancel_transport.responses.push_back({200, R"({"access_token":"data360-token","instance_url":"https://tenant.c360a.salesforce.com"})"});
	FakeRuntime late_cancel_runtime;
	late_cancel_transport.after_send = [&](size_t count) { if (count == 2) late_cancel_runtime.cancelled = true; };
	SalesforceOAuthProvider late_cancel_provider(late_cancel_transport, late_cancel_runtime, TestOptions());
	RequireThrows([&] { late_cancel_provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
	              "cancellation after Data 360 response was ignored");

	RecordingTransport ttl_transport;
	QueueValidSalesforce(ttl_transport);
	ttl_transport.responses.push_back({200, R"({"access_token":"data360-token","instance_url":"https://tenant.c360a.salesforce.com","token_type":"Bearer"})"});
	FakeRuntime ttl_runtime;
	auto ttl_options = TestOptions();
	ttl_options.default_ttl_seconds = 300;
	ttl_options.expiry_skew_seconds = 30;
	SalesforceOAuthProvider ttl_provider(ttl_transport, ttl_runtime, ttl_options);
	auto capability = ttl_provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v')));
	Require(capability.expires_at_monotonic_ms == 370000, "conservative local default TTL was not applied");
	Require(capability.expires_at_utc_micros == INT64_C(1700000270000000), "local default UTC TTL was not applied");

	RecordingTransport overflow_transport;
	QueueValidSalesforce(overflow_transport);
	overflow_transport.responses.push_back({200, R"({"access_token":"data360-token","instance_url":"https://tenant.c360a.salesforce.com","token_type":"Bearer","expires_in":600})"});
	FakeRuntime overflow_runtime;
	overflow_runtime.now_ms = std::numeric_limits<uint64_t>::max() - 100;
	SalesforceOAuthProvider overflow_provider(overflow_transport, overflow_runtime, TestOptions());
	RequireThrows([&] { overflow_provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code", std::string(43, 'v'))); },
	              "overflowing monotonic expiry was accepted");

	const std::vector<std::string> sentinels = {"body-sentinel", "code-sentinel", "verifier-sentinel", "token-sentinel", "header-sentinel", "url-sentinel"};
	RecordingTransport redaction_transport;
	redaction_transport.responses.push_back({200, "{body-sentinel code-sentinel verifier-sentinel token-sentinel header-sentinel url-sentinel"});
	FakeRuntime redaction_runtime;
	SalesforceOAuthProvider redaction_provider(redaction_transport, redaction_runtime, TestOptions());
	const auto parse_error = RequireThrows([&] { redaction_provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code-sentinel", "verifier-sentinel")); },
	                                      "malformed sentinel response was accepted");
	for (const auto &sentinel : sentinels) Require(parse_error.find(sentinel) == std::string::npos, "sensitive sentinel leaked in parse error");

	RecordingTransport throwing_transport;
	throwing_transport.after_send = [](size_t) { throw std::runtime_error("body-sentinel code-sentinel verifier-sentinel token-sentinel header-sentinel url-sentinel"); };
	throwing_transport.responses.push_back({200, "unused"});
	FakeRuntime throwing_runtime;
	SalesforceOAuthProvider throwing_provider(throwing_transport, throwing_runtime, TestOptions());
	const auto transport_error = RequireThrows([&] { throwing_provider.Exchange("https://login.salesforce.com", "client", AuthCompletionMaterial("code-sentinel", "verifier-sentinel")); },
	                                          "transport sentinel failure was accepted");
	for (const auto &sentinel : sentinels) Require(transport_error.find(sentinel) == std::string::npos, "sensitive sentinel leaked in transport error");
}

void TestFailuresHaveStableTypedFaults() {
	RecordingTransport malformed_salesforce;
	malformed_salesforce.responses.push_back({200, "not-json"});
	FakeRuntime malformed_salesforce_runtime;
	SalesforceOAuthProvider malformed_salesforce_provider(malformed_salesforce, malformed_salesforce_runtime, TestOptions());
	Require(RequireAuthFault([&] {
		malformed_salesforce_provider.Exchange("https://login.salesforce.com", "client",
		                                       AuthCompletionMaterial("code", std::string(43, 'v')));
	}, "Salesforce parse failure was not typed") == AuthFault::TOKEN_EXCHANGE_FAILED,
	        "Salesforce parse failure lost D360-AUTH-010 state");

	RecordingTransport malformed;
	QueueValidSalesforce(malformed);
	malformed.responses.push_back({200, "not-json"});
	FakeRuntime malformed_runtime;
	SalesforceOAuthProvider malformed_provider(malformed, malformed_runtime, TestOptions());
	Require(RequireAuthFault([&] {
		malformed_provider.Exchange("https://login.salesforce.com", "client",
		                            AuthCompletionMaterial("code", std::string(43, 'v')));
	}, "Data 360 parse failure was not typed") == AuthFault::DATA360_EXCHANGE_FAILED,
	        "Data 360 parse failure lost D360-AUTH-011 state");

	RecordingTransport denied;
	QueueValidSalesforce(denied);
	denied.responses.push_back({403, "policy-body-sentinel"});
	FakeRuntime denied_runtime;
	SalesforceOAuthProvider denied_provider(denied, denied_runtime, TestOptions());
	Require(RequireAuthFault([&] {
		denied_provider.Exchange("https://login.salesforce.com", "client",
		                         AuthCompletionMaterial("code", std::string(43, 'v')));
	}, "organization policy failure was not typed") == AuthFault::ORG_POLICY_DENIED,
	        "organization policy failure lost D360-AUTH-012 state");

	for (const auto fault : {AuthFault::NETWORK_UNAVAILABLE, AuthFault::TLS_FAILURE}) {
		RecordingTransport transport;
		transport.responses.push_back({200, "unused"});
		transport.after_send = [fault](size_t) { throw AuthFaultException(fault); };
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		Require(RequireAuthFault([&] {
			provider.Exchange("https://login.salesforce.com", "client",
			                  AuthCompletionMaterial("code", std::string(43, 'v')));
		}, "typed transport fault was not preserved") == fault, "typed transport fault changed state");
	}

	for (const auto &entry : std::vector<std::pair<AuthFault, std::string>>{
	         {AuthFault::NETWORK_UNAVAILABLE, "D360-AUTH-008 NETWORK_UNAVAILABLE"},
	         {AuthFault::TLS_FAILURE, "D360-AUTH-009 TLS_FAILURE"}}) {
		RecordingTransport transport;
		transport.responses.push_back({200, "unused"});
		transport.after_send = [&](size_t) { throw std::runtime_error(entry.second); };
		FakeRuntime runtime;
		SalesforceOAuthProvider provider(transport, runtime, TestOptions());
		Require(RequireAuthFault([&] {
			provider.Exchange("https://login.salesforce.com", "client",
			                  AuthCompletionMaterial("code", std::string(43, 'v')));
		}, "known transport fault was not promoted to a typed fault") == entry.first,
		        "known transport fault changed state");
	}

	RecordingTransport unknown;
	unknown.responses.push_back({200, "unused"});
	unknown.after_send = [](size_t) { throw std::runtime_error("secret transport detail"); };
	FakeRuntime unknown_runtime;
	SalesforceOAuthProvider unknown_provider(unknown, unknown_runtime, TestOptions());
	Require(RequireAuthFault([&] {
		unknown_provider.Exchange("https://login.salesforce.com", "client",
		                          AuthCompletionMaterial("code", std::string(43, 'v')));
	}, "unknown transport failure was not safely typed") == AuthFault::TOKEN_EXCHANGE_FAILED,
	        "unknown Salesforce transport failure did not map safely");
}

void TestRejectsUnsafeClientIdBeforeNetwork() {
	RecordingTransport transport;
	FakeRuntime runtime;
	SalesforceOAuthProvider provider(transport, runtime, TestOptions());
	RequireThrows([&] { provider.Exchange("https://login.salesforce.com", "client\nid", AuthCompletionMaterial("code", std::string(43, 'v'))); },
	              "unsafe client identifier was accepted");
	Require(transport.requests.empty(), "unsafe client identifier reached the network");
}

} // namespace

int main() {
	try {
		TestExactTwoPostExchangeProducesMoveOnlyCapability();
		TestFixtureCompatibleMinimalResponses();
		TestNormalizesBareTrustedData360Hostname();
		TestRejectsMalformedDuplicateWrongTypeAndOversizedJson();
		TestRejectsUntrustedOrigins();
		TestStatusMappingCancellationExpiryAndRedaction();
		TestFailuresHaveStableTypedFaults();
		TestRejectsUnsafeClientIdBeforeNetwork();
		std::cout << "salesforce_oauth_provider tests passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "salesforce_oauth_provider test failure: " << error.what() << '\n';
		return 1;
	}
}
