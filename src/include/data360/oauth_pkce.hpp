#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace data360 {

class OAuthError : public std::runtime_error {
public:
	explicit OAuthError(const std::string &message) : std::runtime_error(message) {
	}
};

class RandomSource {
public:
	virtual ~RandomSource() = default;
	virtual void Fill(uint8_t *output, size_t length) = 0;
};

class SystemRandomSource final : public RandomSource {
public:
	void Fill(uint8_t *output, size_t length) override;
};

std::string GeneratePkceVerifier(RandomSource &random);
std::string GenerateOAuthState(RandomSource &random);
std::string GenerateOpaqueId(RandomSource &random);
std::string CreateS256Challenge(const std::string &verifier);
bool ConstantTimeEquals(const std::string &left, const std::string &right);

const std::string &FixedOAuthCallbackUrl();
std::string ValidateSalesforceLoginOrigin(const std::string &origin);
std::string BuildSalesforceAuthorizationUrl(const std::string &login_origin, const std::string &client_id,
                                             const std::string &code_challenge, const std::string &state,
                                             const std::string &redirect_uri = FixedOAuthCallbackUrl());

struct OAuthTokenResponse {
	std::string access_token;
	std::string instance_url;
	uint64_t expires_in_seconds = 0;
};

OAuthTokenResponse ParseOAuthTokenResponse(const std::string &json);

} // namespace data360
