#pragma once

#include "data360/auth_session_registry.hpp"
#include "data360/loopback_listener.hpp"

#include <cstdint>
#include <string>

namespace duckdb {
class ExtensionLoader;
void RegisterData360AuthFunctions(ExtensionLoader &loader);
}

namespace data360 {

struct AuthStatusRow {
	std::string auth_id;
	std::string status;
	int64_t expires_at_utc_micros = 0;
	std::string error_code;
	std::string message;
};

void ValidateAuthClientId(const std::string &client_id);
void ValidateAuthSecretName(const std::string &secret_name);
AuthStatusRow ProjectAuthStatus(const std::string &auth_id, const AuthSessionSnapshot &snapshot);
void ProcessAuthCallback(FixedLoopbackListener &listener, AuthSessionRegistry &registry,
                         const std::string &auth_id, uint64_t timeout_ms,
                         const CancellationCheck &cancelled) noexcept;

} // namespace data360
