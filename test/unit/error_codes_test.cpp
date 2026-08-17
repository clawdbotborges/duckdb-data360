#include "data360/error_codes.hpp"

#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

using namespace data360;

namespace {
void Require(bool value, const char *message) {
	if (!value) {
		throw std::runtime_error(message);
	}
}
} // namespace

int main() {
	try {
		Require(AuthFaultProtocolVersion() == 1, "fault protocol version changed");
		const AuthFault faults[] = {
		    AuthFault::INVALID_LOGIN_ORIGIN,       AuthFault::INVALID_CLIENT_ID,
		    AuthFault::CALLBACK_PORT_UNAVAILABLE, AuthFault::CALLBACK_PROTOCOL_ERROR,
		    AuthFault::STATE_MISMATCH,             AuthFault::USER_DENIED,
		    AuthFault::SESSION_EXPIRED,            AuthFault::NETWORK_UNAVAILABLE,
		    AuthFault::TLS_FAILURE,                AuthFault::TOKEN_EXCHANGE_FAILED,
		    AuthFault::DATA360_EXCHANGE_FAILED,    AuthFault::ORG_POLICY_DENIED,
		    AuthFault::SECRET_NAME_INVALID,        AuthFault::PERSISTENCE_FORBIDDEN,
		    AuthFault::AUTH_SESSION_NOT_FOUND,     AuthFault::AUTH_SESSION_LIMIT_REACHED,
		    AuthFault::REAUTH_REQUIRED,            AuthFault::UNSUPPORTED_PLATFORM};
		std::set<std::string> codes;
		for (const auto fault : faults) {
			const auto &safe = GetSafeFault(fault);
			Require(safe.fault == fault, "fault table returned wrong enum");
			Require(std::string(safe.code).rfind("D360-AUTH-", 0) == 0, "fault code is not stable");
			Require(safe.symbol && *safe.symbol && safe.message && *safe.message, "fault text is empty");
			Require(std::string(safe.message).find("http") == std::string::npos, "fault message contains a URL");
			Require(codes.insert(safe.code).second, "fault code is duplicated");
			AuthFaultException exception(fault);
			Require(exception.Fault() == fault, "typed exception lost fault");
			Require(std::string(exception.what()) == FormatSafeFault(fault), "exception is not static/sanitized");
		}
		Require(codes.size() == 18, "stable fault table is incomplete");
		std::cout << "error_codes tests passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "error_codes test failed: " << error.what() << '\n';
		return 1;
	}
}
