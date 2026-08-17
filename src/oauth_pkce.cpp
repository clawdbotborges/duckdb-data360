#include "data360/oauth_pkce.hpp"
#include "mbedtls/sha256.h"
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#include "yyjson.hpp"
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

using namespace duckdb_yyjson;

#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <set>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#else
#include <cerrno>
#include <sys/random.h>
#endif

namespace data360 {
namespace {

std::array<uint8_t, 32> Sha256(const std::string &input) {
	std::array<uint8_t, 32> output = {};
	mbedtls_sha256_context context;
	mbedtls_sha256_init(&context);
	const int result = mbedtls_sha256_starts(&context, 0) ||
	                   mbedtls_sha256_update(&context, reinterpret_cast<const unsigned char *>(input.data()), input.size()) ||
	                   mbedtls_sha256_finish(&context, output.data());
	mbedtls_sha256_free(&context);
	if (result != 0) {
		throw OAuthError("SHA-256 unavailable");
	}
	return output;
}

std::string Base64Url(const uint8_t *input, size_t length) {
	static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	std::string output;
	output.reserve((length * 4U + 2U) / 3U);
	uint32_t accumulator = 0;
	int bits = 0;
	for (size_t i = 0; i < length; i++) {
		accumulator = (accumulator << 8U) | input[i];
		bits += 8;
		while (bits >= 6) {
			bits -= 6;
			output.push_back(alphabet[(accumulator >> bits) & 0x3fU]);
		}
	}
	if (bits > 0) {
		output.push_back(alphabet[(accumulator << (6 - bits)) & 0x3fU]);
	}
	return output;
}

std::string Generate(RandomSource &random, size_t bytes) {
	std::vector<uint8_t> buffer(bytes);
	random.Fill(buffer.data(), buffer.size());
	return Base64Url(buffer.data(), buffer.size());
}

bool IsDnsLabelChar(char value) {
	return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-';
}

bool ValidMyDomainHost(const std::string &host) {
	static const std::string suffix = ".my.salesforce.com";
	if (host.size() > 253 || host.size() <= suffix.size() || host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0) {
		return false;
	}
	const auto prefix = host.substr(0, host.size() - suffix.size());
	bool label_start = true;
	size_t label_length = 0;
	char previous = '\0';
	for (char c : prefix) {
		if (c == '.') {
			if (label_start || label_length > 63 || previous == '-') {
				return false;
			}
			label_start = true;
			label_length = 0;
			previous = c;
			continue;
		}
		if (!IsDnsLabelChar(c) || (label_start && c == '-')) {
			return false;
		}
		label_start = false;
		label_length++;
		previous = c;
	}
	return !label_start && label_length <= 63 && prefix.back() != '-';
}

std::string PercentEncode(const std::string &value) {
	static constexpr char hex[] = "0123456789ABCDEF";
	std::string output;
	for (const unsigned char c : value) {
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~') {
			output.push_back(static_cast<char>(c));
		} else {
			output.push_back('%');
			output.push_back(hex[c >> 4U]);
			output.push_back(hex[c & 0x0fU]);
		}
	}
	return output;
}

bool IsBase64UrlValue(const std::string &value, size_t minimum, size_t maximum) {
	if (value.size() < minimum || value.size() > maximum) {
		return false;
	}
	for (char c : value) {
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
			return false;
		}
	}
	return true;
}

struct JsonDocDeleter {
	void operator()(yyjson_doc *doc) const { yyjson_doc_free(doc); }
};

std::string BoundedJsonString(yyjson_val *value, size_t maximum) {
	if (!yyjson_is_str(value) || yyjson_get_len(value) == 0 || yyjson_get_len(value) > maximum) {
		throw OAuthError("invalid OAuth token response");
	}
	return std::string(yyjson_get_str(value), yyjson_get_len(value));
}

} // namespace

void SystemRandomSource::Fill(uint8_t *output, size_t length) {
	if (!output && length != 0) {
		throw OAuthError("secure entropy unavailable");
	}
#ifdef _WIN32
	if (length > static_cast<size_t>(std::numeric_limits<ULONG>::max()) ||
	    BCryptGenRandom(nullptr, output, static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
		throw OAuthError("secure entropy unavailable");
	}
#elif defined(__APPLE__)
	if (SecRandomCopyBytes(kSecRandomDefault, length, output) != errSecSuccess) {
		throw OAuthError("secure entropy unavailable");
	}
#else
	size_t offset = 0;
	while (offset < length) {
		const auto count = getrandom(output + offset, length - offset, 0);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			throw OAuthError("secure entropy unavailable");
		}
		offset += static_cast<size_t>(count);
	}
#endif
}

std::string GeneratePkceVerifier(RandomSource &random) {
	return Generate(random, 32);
}

std::string GenerateOAuthState(RandomSource &random) {
	return Generate(random, 16);
}

std::string GenerateOpaqueId(RandomSource &random) {
	return Generate(random, 16);
}

std::string CreateS256Challenge(const std::string &verifier) {
	if (!IsBase64UrlValue(verifier, 43, 128)) {
		throw OAuthError("invalid PKCE verifier");
	}
	const auto digest = Sha256(verifier);
	return Base64Url(digest.data(), digest.size());
}

bool ConstantTimeEquals(const std::string &left, const std::string &right) {
	size_t difference = left.size() ^ right.size();
	const size_t count = left.size() > right.size() ? left.size() : right.size();
	for (size_t i = 0; i < count; i++) {
		const auto a = i < left.size() ? static_cast<unsigned char>(left[i]) : 0U;
		const auto b = i < right.size() ? static_cast<unsigned char>(right[i]) : 0U;
		difference |= a ^ b;
	}
	return difference == 0;
}

const std::string &FixedOAuthCallbackUrl() {
	static const std::string url = "http://127.0.0.1:8910/oauth/callback";
	return url;
}

std::string ValidateSalesforceLoginOrigin(const std::string &origin) {
	static const std::string scheme = "https://";
	if (origin.compare(0, scheme.size(), scheme) != 0) {
		throw OAuthError("invalid Salesforce login origin");
	}
	std::string host = origin.substr(scheme.size());
	if (!host.empty() && host.back() == '/') {
		host.pop_back();
	}
	if (host.empty() || host.find_first_of("/@:?#\\") != std::string::npos ||
	    (host != "login.salesforce.com" && host != "test.salesforce.com" && !ValidMyDomainHost(host))) {
		throw OAuthError("invalid Salesforce login origin");
	}
	return scheme + host;
}

std::string BuildSalesforceAuthorizationUrl(const std::string &login_origin, const std::string &client_id,
                                             const std::string &code_challenge, const std::string &state,
                                             const std::string &redirect_uri) {
	const auto origin = ValidateSalesforceLoginOrigin(login_origin);
	if (client_id.empty() || client_id.size() > 1024) {
		throw OAuthError("invalid OAuth client identifier");
	}
	for (unsigned char c : client_id) {
		if (c < 0x20U || c == 0x7fU) {
			throw OAuthError("invalid OAuth client identifier");
		}
	}
	if (!IsBase64UrlValue(code_challenge, 1, 128) || !IsBase64UrlValue(state, 1, 128)) {
		throw OAuthError("invalid public OAuth parameter");
	}
	if (redirect_uri != FixedOAuthCallbackUrl()) {
		throw OAuthError("invalid OAuth callback URL");
	}
	return origin + "/services/oauth2/authorize?response_type=code&client_id=" + PercentEncode(client_id) +
	       "&redirect_uri=" + PercentEncode(redirect_uri) + "&scope=api%20cdp_query_api&code_challenge=" +
	       PercentEncode(code_challenge) + "&code_challenge_method=S256&state=" + PercentEncode(state);
}

OAuthTokenResponse ParseOAuthTokenResponse(const std::string &json) {
	if (json.empty() || json.size() > 64U * 1024U) throw OAuthError("invalid OAuth token response");
	std::unique_ptr<yyjson_doc, JsonDocDeleter> doc(yyjson_read(json.data(), json.size(), 0));
	auto *root = doc ? yyjson_doc_get_root(doc.get()) : nullptr;
	if (!yyjson_is_obj(root)) throw OAuthError("invalid OAuth token response");
	std::set<std::string> names;
	yyjson_obj_iter iterator = yyjson_obj_iter_with(root);
	yyjson_val *key = nullptr;
	while ((key = yyjson_obj_iter_next(&iterator))) {
		const std::string name(yyjson_get_str(key), yyjson_get_len(key));
		if (!names.emplace(name).second) throw OAuthError("invalid OAuth token response");
	}
	auto *access_token = yyjson_obj_get(root, "access_token");
	auto *instance_url = yyjson_obj_get(root, "instance_url");
	auto *token_type = yyjson_obj_get(root, "token_type");
	auto *expires_in = yyjson_obj_get(root, "expires_in");
	OAuthTokenResponse response;
	try {
		response.access_token = BoundedJsonString(access_token, 16U * 1024U);
		response.instance_url = BoundedJsonString(instance_url, 2048);
		if (token_type && BoundedJsonString(token_type, 16) != "Bearer") throw OAuthError("invalid OAuth token response");
		if (expires_in) {
			if (!yyjson_is_uint(expires_in) || yyjson_get_uint(expires_in) == 0 || yyjson_get_uint(expires_in) > 86400U * 365U)
				throw OAuthError("invalid OAuth token response");
			response.expires_in_seconds = yyjson_get_uint(expires_in);
		}
	} catch (...) {
		volatile char *bytes = response.access_token.empty() ? nullptr : &response.access_token[0];
		for (size_t i = 0; i < response.access_token.size(); i++) bytes[i] = 0;
		response.access_token.clear();
		throw;
	}
	return response;
}

} // namespace data360
