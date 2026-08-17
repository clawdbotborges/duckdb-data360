#include "data360/error_codes.hpp"

#include <array>

namespace data360 {
namespace {
constexpr std::array<SafeFault, 18> SAFE_FAULTS {{
    {AuthFault::INVALID_LOGIN_ORIGIN, "D360-AUTH-001", "INVALID_LOGIN_ORIGIN", "The login origin is invalid"},
    {AuthFault::INVALID_CLIENT_ID, "D360-AUTH-002", "INVALID_CLIENT_ID", "The OAuth client identifier is invalid"},
    {AuthFault::CALLBACK_PORT_UNAVAILABLE, "D360-AUTH-003", "CALLBACK_PORT_UNAVAILABLE", "The local callback port is unavailable"},
    {AuthFault::CALLBACK_PROTOCOL_ERROR, "D360-AUTH-004", "CALLBACK_PROTOCOL_ERROR", "The OAuth callback was invalid"},
    {AuthFault::STATE_MISMATCH, "D360-AUTH-005", "STATE_MISMATCH", "The OAuth callback state did not match"},
    {AuthFault::USER_DENIED, "D360-AUTH-006", "USER_DENIED", "Authorization was denied"},
    {AuthFault::SESSION_EXPIRED, "D360-AUTH-007", "SESSION_EXPIRED", "The authorization session expired"},
    {AuthFault::NETWORK_UNAVAILABLE, "D360-AUTH-008", "NETWORK_UNAVAILABLE", "The authorization service is unavailable"},
    {AuthFault::TLS_FAILURE, "D360-AUTH-009", "TLS_FAILURE", "A secure connection could not be established"},
    {AuthFault::TOKEN_EXCHANGE_FAILED, "D360-AUTH-010", "TOKEN_EXCHANGE_FAILED", "The OAuth token exchange failed"},
    {AuthFault::DATA360_EXCHANGE_FAILED, "D360-AUTH-011", "DATA360_EXCHANGE_FAILED", "The Data 360 token exchange failed"},
    {AuthFault::ORG_POLICY_DENIED, "D360-AUTH-012", "ORG_POLICY_DENIED", "Organization policy denied authorization"},
    {AuthFault::SECRET_NAME_INVALID, "D360-AUTH-013", "SECRET_NAME_INVALID", "The secret name is invalid"},
    {AuthFault::PERSISTENCE_FORBIDDEN, "D360-AUTH-014", "PERSISTENCE_FORBIDDEN", "Data 360 OAuth session secrets are temporary"},
    {AuthFault::AUTH_SESSION_NOT_FOUND, "D360-AUTH-015", "AUTH_SESSION_NOT_FOUND", "The authorization session was not found"},
    {AuthFault::AUTH_SESSION_LIMIT_REACHED, "D360-AUTH-016", "AUTH_SESSION_LIMIT_REACHED", "The authorization session limit was reached"},
    {AuthFault::REAUTH_REQUIRED, "D360-AUTH-017", "REAUTH_REQUIRED", "Authorization is required"},
    {AuthFault::UNSUPPORTED_PLATFORM, "D360-AUTH-018", "UNSUPPORTED_PLATFORM", "Interactive authorization is unsupported on this platform"},
}};
} // namespace

unsigned AuthFaultProtocolVersion() noexcept {
	return 1;
}

const SafeFault &GetSafeFault(AuthFault fault) noexcept {
	for (const auto &entry : SAFE_FAULTS) {
		if (entry.fault == fault) {
			return entry;
		}
	}
	return SAFE_FAULTS[3];
}

std::string FormatSafeFault(AuthFault fault) {
	const auto &safe = GetSafeFault(fault);
	return std::string(safe.code) + " " + safe.symbol + ": " + safe.message;
}

AuthFaultException::AuthFaultException(AuthFault fault_p) : std::runtime_error(FormatSafeFault(fault_p)), fault(fault_p) {
}

AuthFault AuthFaultException::Fault() const noexcept {
	return fault;
}

} // namespace data360
