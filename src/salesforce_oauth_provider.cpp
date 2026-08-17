#include "data360/salesforce_oauth_provider.hpp"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#include "yyjson.hpp"
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include <chrono>
#include <limits>
#include <memory>
#include <set>
#include <utility>

using namespace duckdb_yyjson;

namespace data360 {
namespace {

constexpr uint64_t MAX_JSON_BYTES = 64U * 1024U;
constexpr uint64_t MAX_TOKEN_BYTES = 16U * 1024U;
constexpr uint64_t MAX_URL_BYTES = 2048;
constexpr uint64_t MAX_EXPIRY_SECONDS = 86400U * 365U;

void SecureClear(std::string &value) noexcept {
	volatile char *bytes = value.empty() ? nullptr : &value[0];
	for (size_t i = 0; i < value.size(); i++) bytes[i] = 0;
	value.clear();
	value.shrink_to_fit();
}

struct WipeOnExit {
	explicit WipeOnExit(std::string &value_p) : value(value_p) {}
	~WipeOnExit() { SecureClear(value); }
	std::string &value;
};

struct JsonDocDeleter {
	void operator()(yyjson_doc *document) const { yyjson_doc_free(document); }
};

std::string FormEncode(const std::string &value) {
	static constexpr char hex[] = "0123456789ABCDEF";
	std::string result;
	result.reserve(value.size());
	for (const unsigned char character : value) {
		if ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
		    (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' ||
		    character == '~') {
			result.push_back(static_cast<char>(character));
		} else {
			result.push_back('%');
			result.push_back(hex[character >> 4U]);
			result.push_back(hex[character & 0x0fU]);
		}
	}
	return result;
}

bool ValidDnsOrigin(const std::string &value, const std::string &suffix) {
	constexpr const char *scheme = "https://";
	if (value.rfind(scheme, 0) != 0 || value.size() > MAX_URL_BYTES) return false;
	const auto host = value.substr(8);
	if (host.empty() || host.size() > 253 || host.find_first_of("/?#@:\\%") != std::string::npos ||
	    host.size() <= suffix.size() || host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
	size_t start = 0;
	while (start < host.size()) {
		const auto end = host.find('.', start);
		const auto length = (end == std::string::npos ? host.size() : end) - start;
		if (length == 0 || length > 63 || host[start] == '-' || host[start + length - 1] == '-') return false;
		for (size_t index = start; index < start + length; index++) {
			const char character = host[index];
			if (!((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-')) return false;
		}
		if (end == std::string::npos) break;
		start = end + 1;
	}
	return true;
}

std::string JsonString(yyjson_val *object, const char *name, size_t maximum) {
	auto *value = yyjson_obj_get(object, name);
	if (!yyjson_is_str(value) || yyjson_get_len(value) == 0 || yyjson_get_len(value) > maximum)
		throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	return std::string(yyjson_get_str(value), yyjson_get_len(value));
}

struct Data360Response {
	std::string token;
	std::string tenant_url;
	uint64_t ttl_seconds = 0;
};

Data360Response ParseData360Response(const std::string &body, uint64_t default_ttl_seconds) {
	if (body.empty() || body.size() > MAX_JSON_BYTES) throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	std::unique_ptr<yyjson_doc, JsonDocDeleter> document(yyjson_read(body.data(), body.size(), 0));
	auto *root = document ? yyjson_doc_get_root(document.get()) : nullptr;
	if (!yyjson_is_obj(root)) throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	std::set<std::string> names;
	yyjson_obj_iter iterator = yyjson_obj_iter_with(root);
	yyjson_val *key = nullptr;
	while ((key = yyjson_obj_iter_next(&iterator))) {
		if (!yyjson_is_str(key) || yyjson_get_len(key) > 128 ||
		    !names.emplace(yyjson_get_str(key), yyjson_get_len(key)).second)
			throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	}
	Data360Response response;
	try {
		response.token = JsonString(root, "access_token", MAX_TOKEN_BYTES);
		response.tenant_url = JsonString(root, "instance_url", MAX_URL_BYTES);
		auto *token_type = yyjson_obj_get(root, "token_type");
		if (token_type && JsonString(root, "token_type", 16) != "Bearer")
			throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
		auto *expires_in = yyjson_obj_get(root, "expires_in");
		if (expires_in) {
			if (!yyjson_is_uint(expires_in) || yyjson_get_uint(expires_in) == 0 || yyjson_get_uint(expires_in) > MAX_EXPIRY_SECONDS)
				throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
			response.ttl_seconds = yyjson_get_uint(expires_in);
		} else {
			response.ttl_seconds = default_ttl_seconds;
		}
	} catch (...) {
		SecureClear(response.token);
		throw;
	}
	return response;
}

int64_t SystemUtcMicros() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void CheckStatus(int status, bool data360_exchange) {
	if (status >= 200 && status < 300) return;
	if (data360_exchange && status == 403) throw AuthFaultException(AuthFault::ORG_POLICY_DENIED);
	throw AuthFaultException(data360_exchange ? AuthFault::DATA360_EXCHANGE_FAILED : AuthFault::TOKEN_EXCHANGE_FAILED);
}

HttpResponse SendSanitized(HttpTransport &transport, const HttpRequest &request, bool data360_exchange) {
	try {
		return transport.Send(request);
	} catch (const AuthFaultException &) {
		throw;
	} catch (const std::exception &error) {
		const std::string detail = error.what();
		if (detail == "D360-AUTH-008 NETWORK_UNAVAILABLE")
			throw AuthFaultException(AuthFault::NETWORK_UNAVAILABLE);
		if (detail == "D360-AUTH-009 TLS_FAILURE") throw AuthFaultException(AuthFault::TLS_FAILURE);
		throw AuthFaultException(data360_exchange ? AuthFault::DATA360_EXCHANGE_FAILED : AuthFault::TOKEN_EXCHANGE_FAILED);
	} catch (...) {
		throw AuthFaultException(data360_exchange ? AuthFault::DATA360_EXCHANGE_FAILED : AuthFault::TOKEN_EXCHANGE_FAILED);
	}
}

} // namespace

Data360Capability::~Data360Capability() noexcept { SecureClear(access_token); }
Data360Capability::Data360Capability(Data360Capability &&other) noexcept
    : tenant_url(std::move(other.tenant_url)), access_token(std::move(other.access_token)),
      expires_at_monotonic_ms(other.expires_at_monotonic_ms), expires_at_utc_micros(other.expires_at_utc_micros) {
	other.expires_at_monotonic_ms = 0;
	other.expires_at_utc_micros = 0;
}
Data360Capability &Data360Capability::operator=(Data360Capability &&other) noexcept {
	if (this != &other) {
		SecureClear(access_token);
		tenant_url = std::move(other.tenant_url);
		access_token = std::move(other.access_token);
		expires_at_monotonic_ms = other.expires_at_monotonic_ms;
		expires_at_utc_micros = other.expires_at_utc_micros;
		other.expires_at_monotonic_ms = 0;
		other.expires_at_utc_micros = 0;
	}
	return *this;
}

SalesforceOAuthProvider::SalesforceOAuthProvider(HttpTransport &transport_p, RuntimeHooks &runtime_p,
                                                 OAuthExchangeOptions options_p)
    : transport(transport_p), runtime(runtime_p), options(std::move(options_p)) {
	if (options.request_timeout_ms == 0 || options.max_response_bytes == 0 || options.max_response_bytes > MAX_JSON_BYTES ||
	    options.default_ttl_seconds == 0 || options.default_ttl_seconds > MAX_EXPIRY_SECONDS)
		throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
}

Data360Capability SalesforceOAuthProvider::Exchange(AuthCompletionMaterial material) {
	const auto login_origin = material.login_origin;
	const auto client_id = material.client_id;
	return Exchange(login_origin, client_id, std::move(material));
}

Data360Capability SalesforceOAuthProvider::Exchange(const std::string &login_origin, const std::string &client_id,
                                                     AuthCompletionMaterial material) {
	std::string origin;
	try {
		origin = ValidateSalesforceLoginOrigin(login_origin);
	} catch (...) {
		throw AuthFaultException(AuthFault::INVALID_LOGIN_ORIGIN);
	}
	if (client_id.empty() || client_id.size() > 1024) throw AuthFaultException(AuthFault::INVALID_CLIENT_ID);
	for (const unsigned char character : client_id) {
		if (character < 0x20U || character == 0x7fU) throw AuthFaultException(AuthFault::INVALID_CLIENT_ID);
	}
	if (runtime.IsCancelled()) throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	HttpRequest oauth;
	oauth.method = "POST";
	oauth.url = origin + "/services/oauth2/token";
	oauth.headers = {{"Accept", "application/json"}, {"Content-Type", "application/x-www-form-urlencoded"}};
	oauth.body = "grant_type=authorization_code&client_id=" + FormEncode(client_id) + "&redirect_uri=" +
	             FormEncode(FixedOAuthCallbackUrl()) + "&code=" + FormEncode(material.authorization_code) +
	             "&code_verifier=" + FormEncode(material.pkce_verifier);
	WipeOnExit wipe_oauth_form(oauth.body);
	oauth.timeout_ms = options.request_timeout_ms;
	oauth.max_response_bytes = options.max_response_bytes;
	auto oauth_response = SendSanitized(transport, oauth, false);
	WipeOnExit wipe_oauth_response(oauth_response.body);
	SecureClear(oauth.body);
	CheckStatus(oauth_response.status, false);
	OAuthTokenResponse salesforce;
	try {
		salesforce = ParseOAuthTokenResponse(oauth_response.body);
	} catch (...) {
		SecureClear(oauth_response.body);
		throw AuthFaultException(AuthFault::TOKEN_EXCHANGE_FAILED);
	}
	SecureClear(oauth_response.body);
	if (!ValidDnsOrigin(salesforce.instance_url, ".salesforce.com")) {
		SecureClear(salesforce.access_token);
		throw AuthFaultException(AuthFault::TOKEN_EXCHANGE_FAILED);
	}
	if (runtime.IsCancelled()) {
		SecureClear(salesforce.access_token);
		throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	}
	HttpRequest data360;
	data360.method = "POST";
	data360.url = salesforce.instance_url + "/services/a360/token";
	data360.headers = oauth.headers;
	data360.body = "grant_type=" + FormEncode("urn:salesforce:grant-type:external:cdp") + "&subject_token=" +
	               FormEncode(salesforce.access_token) + "&subject_token_type=" +
	               FormEncode("urn:ietf:params:oauth:token-type:access_token");
	WipeOnExit wipe_data360_form(data360.body);
	WipeOnExit wipe_salesforce_token(salesforce.access_token);
	data360.timeout_ms = options.request_timeout_ms;
	data360.max_response_bytes = options.max_response_bytes;
	HttpResponse data360_response;
	try {
		data360_response = SendSanitized(transport, data360, true);
	} catch (...) {
		SecureClear(data360.body);
		SecureClear(salesforce.access_token);
		throw;
	}
	SecureClear(data360.body);
	SecureClear(salesforce.access_token);
	WipeOnExit wipe_data360_response(data360_response.body);
	CheckStatus(data360_response.status, true);
	if (runtime.IsCancelled()) throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	Data360Response parsed;
	try {
		parsed = ParseData360Response(data360_response.body, options.default_ttl_seconds);
	} catch (...) {
		SecureClear(data360_response.body);
		throw;
	}
	SecureClear(data360_response.body);
	if (parsed.tenant_url.rfind("https://", 0) != 0) {
		const auto candidate = std::string("https://") + parsed.tenant_url;
		if (!ValidDnsOrigin(candidate, ".c360a.salesforce.com")) {
			SecureClear(parsed.token);
			throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
		}
		parsed.tenant_url = candidate;
	}
	if (!ValidDnsOrigin(parsed.tenant_url, ".c360a.salesforce.com") ||
	    parsed.ttl_seconds <= options.expiry_skew_seconds) {
		SecureClear(parsed.token);
		throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	}
	const uint64_t effective_seconds = parsed.ttl_seconds - options.expiry_skew_seconds;
	const uint64_t now_ms = runtime.NowMs();
	if (effective_seconds > std::numeric_limits<uint64_t>::max() / 1000U ||
	    now_ms > std::numeric_limits<uint64_t>::max() - effective_seconds * 1000U) {
		SecureClear(parsed.token);
		throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	}
	const int64_t now_utc = options.utc_now_micros ? options.utc_now_micros() : SystemUtcMicros();
	if (now_utc < 0 || effective_seconds > static_cast<uint64_t>(std::numeric_limits<int64_t>::max() - now_utc) / 1000000U) {
		SecureClear(parsed.token);
		throw AuthFaultException(AuthFault::DATA360_EXCHANGE_FAILED);
	}
	Data360Capability capability;
	capability.tenant_url = std::move(parsed.tenant_url);
	capability.access_token = std::move(parsed.token);
	capability.expires_at_monotonic_ms = now_ms + effective_seconds * 1000U;
	capability.expires_at_utc_micros = now_utc + static_cast<int64_t>(effective_seconds * 1000000U);
	return capability;
}

} // namespace data360
