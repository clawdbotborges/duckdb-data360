#pragma once

#include <stdexcept>
#include <string>

namespace data360 {

enum class AuthFault {
	INVALID_LOGIN_ORIGIN,
	INVALID_CLIENT_ID,
	CALLBACK_PORT_UNAVAILABLE,
	CALLBACK_PROTOCOL_ERROR,
	STATE_MISMATCH,
	USER_DENIED,
	SESSION_EXPIRED,
	NETWORK_UNAVAILABLE,
	TLS_FAILURE,
	TOKEN_EXCHANGE_FAILED,
	DATA360_EXCHANGE_FAILED,
	ORG_POLICY_DENIED,
	SECRET_NAME_INVALID,
	PERSISTENCE_FORBIDDEN,
	AUTH_SESSION_NOT_FOUND,
	AUTH_SESSION_LIMIT_REACHED,
	REAUTH_REQUIRED,
	UNSUPPORTED_PLATFORM
};

struct SafeFault {
	AuthFault fault;
	const char *code;
	const char *symbol;
	const char *message;
};

unsigned AuthFaultProtocolVersion() noexcept;
const SafeFault &GetSafeFault(AuthFault fault) noexcept;
std::string FormatSafeFault(AuthFault fault);

class AuthFaultException : public std::runtime_error {
public:
	explicit AuthFaultException(AuthFault fault);
	AuthFault Fault() const noexcept;

private:
	AuthFault fault;
};

} // namespace data360
