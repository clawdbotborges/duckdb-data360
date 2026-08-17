#pragma once

#include "duckdb/main/secret/secret.hpp"

#include <string>

namespace data360 {
class AuthSessionRegistry;
}

namespace duckdb {

class ClientContext;

class SessionData360Secret final : public KeyValueSecret {
public:
	SessionData360Secret(const vector<string> &scope, const string &name, const string &session_id);
	SessionData360Secret(const SessionData360Secret &other);

	unique_ptr<const BaseSecret> Clone() const override;
	void Serialize(Serializer &serializer) const override;
};

void InstallTemporarySessionSecret(ClientContext &context, data360::AuthSessionRegistry &registry,
                                   const string &secret_name, const string &credential_id);

unique_ptr<BaseSecret> CreateOAuthPkceSecret(ClientContext &context, CreateSecretInput &input);

} // namespace duckdb
