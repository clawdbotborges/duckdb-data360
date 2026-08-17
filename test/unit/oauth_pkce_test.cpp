#include "data360/oauth_pkce.hpp"

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace data360;

namespace {

void Require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

class SequenceRandom final : public RandomSource {
public:
	explicit SequenceRandom(std::vector<uint8_t> bytes_p) : bytes(std::move(bytes_p)) {
	}

	void Fill(uint8_t *output, size_t length) override {
		if (offset + length > bytes.size()) {
			throw std::runtime_error("test randomness exhausted");
		}
		std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
		          bytes.begin() + static_cast<std::ptrdiff_t>(offset + length), output);
		offset += length;
	}

private:
	std::vector<uint8_t> bytes;
	size_t offset = 0;
};

class FailingRandom final : public RandomSource {
public:
	void Fill(uint8_t *, size_t) override {
		throw OAuthError("secure entropy unavailable");
	}
};

template <class FN>
void RequireThrows(FN &&fn, const char *message) {
	try {
		fn();
	} catch (const OAuthError &) {
		return;
	}
	throw std::runtime_error(message);
}

void TestRfc7636S256Vector() {
	Require(CreateS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") ==
	            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
	        "RFC 7636 S256 vector mismatch");
}

void TestVerifierAndStateUseInjectedEntropy() {
	std::vector<uint8_t> bytes(48);
	for (size_t i = 0; i < bytes.size(); i++) {
		bytes[i] = static_cast<uint8_t>(i);
	}
	SequenceRandom random(bytes);
	const auto verifier = GeneratePkceVerifier(random);
	const auto state = GenerateOAuthState(random);
	Require(verifier.size() == 43, "32 random verifier bytes must encode to 43 characters");
	Require(state.size() == 22, "16 random state bytes must encode to 22 characters");
	for (char c : verifier + state) {
		Require((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_',
		        "PKCE values must use unpadded base64url characters");
	}
	Require(ConstantTimeEquals(state, state), "equal state must compare equal");
	Require(!ConstantTimeEquals(state, state + "x"), "different state must compare unequal");
}

void TestEntropyFailureStopsGeneration() {
	FailingRandom random;
	RequireThrows([&] { GeneratePkceVerifier(random); }, "verifier generation ignored entropy failure");
	RequireThrows([&] { GenerateOAuthState(random); }, "state generation ignored entropy failure");
}

void TestSalesforceAuthorizationUrlIsExactAndEncoded() {
	const auto url = BuildSalesforceAuthorizationUrl(
	    "https://acme--dev.sandbox.my.salesforce.com/", "client id/+", "challenge-_", "state-_",
	    "http://localhost:8910/oauth/callback");
	Require(url ==
	            "https://acme--dev.sandbox.my.salesforce.com/services/oauth2/authorize?response_type=code&client_id=client%20id%2F%2B&redirect_uri=http%3A%2F%2Flocalhost%3A8910%2Foauth%2Fcallback&scope=api%20cdp_query_api&code_challenge=challenge-_&code_challenge_method=S256&state=state-_",
	        "authorization URL must use exact endpoint, ordering, scopes, and percent encoding");
	Require(BuildSalesforceAuthorizationUrl("https://login.salesforce.com", "id", "c", "s",
	                                        "http://localhost:8910/oauth/callback")
	                .find("https://login.salesforce.com/services/oauth2/authorize?") == 0,
	        "canonical Salesforce login origin must be accepted");
}

void TestInvalidOriginsAndCallbackAreRejected() {
	for (const auto &origin : {"http://acme.my.salesforce.com", "https://evil.example", "https://salesforce.com",
	                           "https://acme.my.salesforce.com.evil", "https://user@acme.my.salesforce.com",
	                           "https://acme.my.salesforce.com:443", "https://acme.my.salesforce.com/path",
	                           "https://bad-.next.my.salesforce.com", "https://-bad.my.salesforce.com",
	                           "https://acme.my.salesforce.com?x=1", "https://ACME.my.salesforce.com"}) {
		RequireThrows([&] { ValidateSalesforceLoginOrigin(origin); }, "invalid login origin was accepted");
	}
	RequireThrows(
	    [&] { BuildSalesforceAuthorizationUrl("https://acme.my.salesforce.com", "id", "c", "s", "http://127.0.0.1:8910/oauth/callback"); },
	    "non-exact callback must be rejected");
}

void TestPublicOAuthParametersAreBounded() {
	RequireThrows([&] { BuildSalesforceAuthorizationUrl("https://acme.my.salesforce.com", "", "c", "s", FixedOAuthCallbackUrl()); },
	              "empty client id was accepted");
	RequireThrows([&] { BuildSalesforceAuthorizationUrl("https://acme.my.salesforce.com", std::string(1025, 'a'), "c", "s", FixedOAuthCallbackUrl()); },
	              "oversized client id was accepted");
	RequireThrows([&] { BuildSalesforceAuthorizationUrl("https://acme.my.salesforce.com", "id", "bad challenge", "s", FixedOAuthCallbackUrl()); },
	              "invalid challenge was accepted");
}

void TestTokenResponseParserIsStrictAndBounded() {
	auto token = ParseOAuthTokenResponse(
	    "{\"access_token\":\"secret\",\"instance_url\":\"https://tenant.c360a.salesforce.com\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
	Require(token.access_token == "secret" && token.instance_url == "https://tenant.c360a.salesforce.com" &&
	            token.expires_in_seconds == 3600,
	        "valid OAuth token response was not parsed");
	for (const auto &json : {
	         "{\"access_token\":\"a\",\"access_token\":\"b\",\"instance_url\":\"https://x\",\"token_type\":\"Bearer\",\"expires_in\":1}",
	         "{\"access_token\":7,\"instance_url\":\"https://x\",\"token_type\":\"Bearer\",\"expires_in\":1}",
	         "{\"access_token\":\"a\",\"instance_url\":false,\"token_type\":\"Bearer\",\"expires_in\":1}",
	         "{\"access_token\":\"a\",\"instance_url\":\"https://x\",\"token_type\":\"bearer\",\"expires_in\":1}",
	         "{\"access_token\":\"a\",\"instance_url\":\"https://x\",\"token_type\":\"Bearer\",\"expires_in\":\"1\"}",
	         "{\"access_token\":\"a\",\"instance_url\":\"https://x\",\"token_type\":\"Bearer\",\"expires_in\":0}"}) {
		RequireThrows([&] { ParseOAuthTokenResponse(json); }, "malformed OAuth token response was accepted");
	}
	RequireThrows([&] { ParseOAuthTokenResponse(std::string(65537, 'x')); }, "oversized token response was accepted");
	RequireThrows([&] {
		ParseOAuthTokenResponse("{\"access_token\":\"" + std::string(16385, 'x') +
		                        "\",\"instance_url\":\"https://x\",\"token_type\":\"Bearer\",\"expires_in\":1}");
	}, "oversized access token was accepted");
}

} // namespace

int main() {
	try {
		TestRfc7636S256Vector();
		TestVerifierAndStateUseInjectedEntropy();
		TestEntropyFailureStopsGeneration();
		TestSalesforceAuthorizationUrlIsExactAndEncoded();
		TestInvalidOriginsAndCallbackAreRejected();
		TestPublicOAuthParametersAreBounded();
		TestTokenResponseParserIsStrictAndBounded();
		std::cout << "oauth_pkce tests passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "oauth_pkce test failed: " << error.what() << '\n';
		return 1;
	}
}
