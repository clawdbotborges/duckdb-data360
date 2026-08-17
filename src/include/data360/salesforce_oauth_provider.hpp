#pragma once

#include "data360/auth_session_registry.hpp"
#include "data360/query_api.hpp"

#include <cstdint>
#include <functional>
#include <string>

namespace data360 {

struct Data360Capability {
	std::string tenant_url;
	std::string access_token;
	uint64_t expires_at_monotonic_ms = 0;
	int64_t expires_at_utc_micros = 0;

	Data360Capability() = default;
	~Data360Capability() noexcept;
	Data360Capability(const Data360Capability &) = delete;
	Data360Capability &operator=(const Data360Capability &) = delete;
	Data360Capability(Data360Capability &&other) noexcept;
	Data360Capability &operator=(Data360Capability &&other) noexcept;
};

struct OAuthExchangeOptions {
	uint64_t request_timeout_ms = 30000;
	uint64_t max_response_bytes = 64U * 1024U;
	uint64_t default_ttl_seconds = 900;
	uint64_t expiry_skew_seconds = 30;
	std::function<int64_t()> utc_now_micros;
};

class SalesforceOAuthProvider {
public:
	SalesforceOAuthProvider(HttpTransport &transport, RuntimeHooks &runtime, OAuthExchangeOptions options = {});
	Data360Capability Exchange(AuthCompletionMaterial material);
	Data360Capability Exchange(const std::string &login_origin, const std::string &client_id,
	                           AuthCompletionMaterial material);

private:
	HttpTransport &transport;
	RuntimeHooks &runtime;
	OAuthExchangeOptions options;
};

} // namespace data360
