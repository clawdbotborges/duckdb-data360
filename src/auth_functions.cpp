#include "data360/auth_functions.hpp"

#include "data360/loopback_listener.hpp"
#include "data360/native_runtime.hpp"
#include "data360/salesforce_oauth_provider.hpp"
#include "data360/session_credentials.hpp"
#include "data360_extension.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace data360 {

void ValidateAuthClientId(const std::string &value) {
	if (value.empty() || value.size() > 512) throw AuthFaultException(AuthFault::INVALID_CLIENT_ID);
	for (unsigned char c : value) {
		if (!(std::isalnum(c) || c == '.' || c == '_' || c == '-'))
			throw AuthFaultException(AuthFault::INVALID_CLIENT_ID);
	}
}

void ValidateAuthSecretName(const std::string &value) {
	if (value.empty() || value.size() > 128 || !(std::isalpha(static_cast<unsigned char>(value[0])) || value[0] == '_'))
		throw AuthFaultException(AuthFault::SECRET_NAME_INVALID);
	for (unsigned char c : value) {
		if (!(std::isalnum(c) || c == '_')) throw AuthFaultException(AuthFault::SECRET_NAME_INVALID);
	}
}

AuthStatusRow ProjectAuthStatus(const std::string &auth_id, const AuthSessionSnapshot &snapshot) {
	AuthStatusRow row {auth_id, AuthStatusName(snapshot.status), snapshot.expires_at_utc_micros, {}, {}};
	if (snapshot.fault) {
		const auto &safe = GetSafeFault(*snapshot.fault);
		row.error_code = safe.code;
		row.message = safe.message;
	}
	return row;
}

void RecordAuthCompletionFailure(const std::function<bool()> &is_interrupted,
                                 const std::function<void(AuthFault)> &record,
                                 std::exception_ptr failure) {
	if (is_interrupted()) throw duckdb::InterruptException();
	try {
		if (failure) std::rethrow_exception(failure);
	} catch (const AuthFaultException &error) {
		record(error.Fault());
		return;
	} catch (...) {
		record(AuthFault::TOKEN_EXCHANGE_FAILED);
		return;
	}
	record(AuthFault::TOKEN_EXCHANGE_FAILED);
}

void ProcessAuthCallback(FixedLoopbackListener &listener, AuthSessionRegistry &registry,
                         const std::string &auth_id, uint64_t timeout_ms,
                         const CancellationCheck &cancelled) noexcept {
	try {
		auto result = listener.WaitForCallback(timeout_ms, cancelled);
		if (result.Status() == CallbackStatus::ACCESS_DENIED) {
			registry.ReceiveDenied(auth_id, result.State());
		} else {
			registry.ReceiveCallback(auth_id, result.State(), result.TakeCode());
		}
	} catch (const CallbackCancelled &) {
		return;
	} catch (const CallbackProtocolError &) {
		try { registry.Fail(auth_id, AuthFault::CALLBACK_PROTOCOL_ERROR); } catch (...) {}
	} catch (...) {
		try { registry.Fail(auth_id, AuthFault::CALLBACK_PROTOCOL_ERROR); } catch (...) {}
	}
}

} // namespace data360

namespace duckdb {
namespace {

constexpr uint64_t AUTH_TTL_MS = 10U * 60U * 1000U;

struct AuthOneRowState final : GlobalTableFunctionState { bool emitted = false; };
struct AuthStartBindData final : TableFunctionData {
	string login_origin, client_id, secret_name;
	bool SupportStatementCache() const override { return false; }
};
struct AuthIdBindData final : TableFunctionData {
	string auth_id;
	bool SupportStatementCache() const override { return false; }
};
struct EmptyBindData final : TableFunctionData {
	bool SupportStatementCache() const override { return false; }
};

class CallbackThreadOwner final : public data360::AuthCallbackOwner,
                                  public std::enable_shared_from_this<CallbackThreadOwner> {
public:
	explicit CallbackThreadOwner(std::unique_ptr<data360::FixedLoopbackListener> listener_p)
	    : listener(std::move(listener_p)) {}
	~CallbackThreadOwner() override { StopAndJoin(); }

	void Start(data360::AuthSessionRegistry &registry_p, string auth_id_p) {
		auto self = shared_from_this();
		worker = std::thread([self, &registry_p, auth_id = std::move(auth_id_p)]() mutable {
			data360::ProcessAuthCallback(*self->listener, registry_p, auth_id, AUTH_TTL_MS,
			                             [self] { return self->cancelled.load(); });
			self->WorkerExit();
		});
	}
	void Cancel() noexcept override {
		cancelled.store(true);
		if (listener) listener->Cancel();
	}
	void StopAndJoin() noexcept override {
		Cancel();
		std::thread owned;
		{
			std::lock_guard<std::mutex> guard(worker_mutex);
			if (!worker.joinable()) return;
			if (worker.get_id() == std::this_thread::get_id()) {
				worker.detach();
				return;
			}
			owned = std::move(worker);
		}
		owned.join();
	}
private:
	void WorkerExit() noexcept {
		std::lock_guard<std::mutex> guard(worker_mutex);
		if (worker.joinable() && worker.get_id() == std::this_thread::get_id()) worker.detach();
	}
	std::unique_ptr<data360::FixedLoopbackListener> listener;
	std::atomic<bool> cancelled {false};
	std::mutex worker_mutex;
	std::thread worker;
};

class ContextRuntime final : public data360::RuntimeHooks {
public:
	explicit ContextRuntime(ClientContext &context_p) : context(context_p) {}
	bool IsCancelled() override { return context.IsInterrupted(); }
	uint64_t NowMs() override {
		return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
		    std::chrono::steady_clock::now().time_since_epoch()).count());
	}
	void SleepMs(uint64_t ms) override {
		auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
		while (!IsCancelled() && std::chrono::steady_clock::now() < end) std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
private:
	ClientContext &context;
};

string RequiredString(TableFunctionBindInput &input, idx_t index) {
	if (input.inputs[index].IsNull()) throw BinderException("Data 360 auth arguments must not be NULL");
	return input.inputs[index].GetValue<string>();
}

unique_ptr<GlobalTableFunctionState> AuthOneRowInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<AuthOneRowState>();
}

unique_ptr<FunctionData> AuthStartBind(ClientContext &, TableFunctionBindInput &input,
                                      vector<LogicalType> &types, vector<string> &names) {
	auto bind = make_uniq<AuthStartBindData>();
	bind->login_origin = RequiredString(input, 0);
	bind->client_id = RequiredString(input, 1);
	bind->secret_name = RequiredString(input, 2);
	types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::TIMESTAMP_TZ, LogicalType::VARCHAR, LogicalType::VARCHAR};
	names = {"auth_id", "authorization_url", "expires_at", "callback_url", "status"};
	return std::move(bind);
}

unique_ptr<FunctionData> AuthIdBind(ClientContext &, TableFunctionBindInput &input,
                                   vector<LogicalType> &types, vector<string> &names) {
	auto bind = make_uniq<AuthIdBindData>();
	bind->auth_id = RequiredString(input, 0);
	types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::TIMESTAMP_TZ, LogicalType::VARCHAR, LogicalType::VARCHAR};
	names = {"auth_id", "status", "expires_at", "error_code", "message"};
	return std::move(bind);
}

unique_ptr<FunctionData> AuthCompleteBind(ClientContext &, TableFunctionBindInput &input,
                                         vector<LogicalType> &types, vector<string> &names) {
	auto bind = make_uniq<AuthIdBindData>();
	bind->auth_id = RequiredString(input, 0);
	types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::TIMESTAMP_TZ, LogicalType::VARCHAR, LogicalType::VARCHAR};
	names = {"status", "secret_name", "expires_at", "error_code", "message"};
	return std::move(bind);
}

void EmitStatus(DataChunk &out, const data360::AuthStatusRow &row) {
	out.SetValue(0, 0, Value(row.auth_id));
	out.SetValue(1, 0, Value(row.status));
	out.SetValue(2, 0, Value::TIMESTAMPTZ(timestamp_tz_t(row.expires_at_utc_micros)));
	out.SetValue(3, 0, row.error_code.empty() ? Value() : Value(row.error_code));
	out.SetValue(4, 0, row.message.empty() ? Value() : Value(row.message));
	out.SetCardinality(1);
}

void AuthStartExecute(ClientContext &context, TableFunctionInput &input, DataChunk &out) {
	auto &once = input.global_state->Cast<AuthOneRowState>();
	if (once.emitted) return;
	once.emitted = true;
	const auto &bind = input.bind_data->Cast<AuthStartBindData>();
	string origin;
	try { origin = data360::ValidateSalesforceLoginOrigin(bind.login_origin); }
	catch (...) { throw InvalidInputException(data360::FormatSafeFault(data360::AuthFault::INVALID_LOGIN_ORIGIN)); }
	data360::ValidateAuthClientId(bind.client_id);
	data360::ValidateAuthSecretName(bind.secret_name);

	std::shared_ptr<CallbackThreadOwner> owner;
	try { owner = std::make_shared<CallbackThreadOwner>(std::make_unique<data360::FixedLoopbackListener>()); }
	catch (...) { throw InvalidInputException(data360::FormatSafeFault(data360::AuthFault::CALLBACK_PORT_UNAVAILABLE)); }
	auto &state = Data360AuthState::Get(context);
	auto verifier = data360::GeneratePkceVerifier(state.Random());
	auto oauth_state = data360::GenerateOAuthState(state.Random());
	auto challenge = data360::CreateS256Challenge(verifier);
	const auto expires_ms = data360::SteadyAuthClock().NowMs() + AUTH_TTL_MS;
	const auto expires_utc = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
	    std::chrono::system_clock::now().time_since_epoch()).count()) + static_cast<int64_t>(AUTH_TTL_MS * 1000U);
	data360::AuthStartRequest request {origin, bind.client_id, bind.secret_name, oauth_state, verifier,
	                                  expires_ms, expires_utc, owner};
	auto auth_id = state.Registry().Create(std::move(request));
	try { owner->Start(state.Registry(), auth_id); }
	catch (...) { state.Registry().Cancel(auth_id); throw; }
	auto url = data360::BuildSalesforceAuthorizationUrl(origin, bind.client_id, challenge, oauth_state);
	out.SetValue(0, 0, Value(auth_id));
	out.SetValue(1, 0, Value(url));
	out.SetValue(2, 0, Value::TIMESTAMPTZ(timestamp_tz_t(expires_utc)));
	out.SetValue(3, 0, Value(data360::FixedOAuthCallbackUrl()));
	out.SetValue(4, 0, Value("PENDING_USER_ACTION"));
	out.SetCardinality(1);
}

void AuthStatusExecute(ClientContext &context, TableFunctionInput &input, DataChunk &out) {
	auto &once = input.global_state->Cast<AuthOneRowState>(); if (once.emitted) return; once.emitted = true;
	const auto &id = input.bind_data->Cast<AuthIdBindData>().auth_id;
	EmitStatus(out, data360::ProjectAuthStatus(id, Data360AuthState::Get(context).Registry().Snapshot(id)));
}

void AuthCompleteExecute(ClientContext &context, TableFunctionInput &input, DataChunk &out) {
	auto &once = input.global_state->Cast<AuthOneRowState>(); if (once.emitted) return; once.emitted = true;
	const auto &id = input.bind_data->Cast<AuthIdBindData>().auth_id;
	auto &registry = Data360AuthState::Get(context).Registry();
	auto snapshot = registry.Snapshot(id);
	if (snapshot.status == data360::AuthSessionStatus::CALLBACK_RECEIVED) {
		string credential_id;
		bool owns_completion = false;
		try {
			auto material = registry.BeginCompletion(id);
			owns_completion = true;
			ContextRuntime runtime(context); data360::LibcurlTransport transport(&runtime);
			data360::SalesforceOAuthProvider provider(transport, runtime);
			auto capability = provider.Exchange(material.login_origin, material.client_id, std::move(material));
			credential_id = registry.StoreCredential(std::move(capability.tenant_url), std::move(capability.access_token),
			                                         capability.expires_at_monotonic_ms);
			InstallTemporarySessionSecret(context, registry, snapshot.secret_name, credential_id);
			registry.FinishAuthorized(id);
		} catch (...) {
			// Only the caller that won BeginCompletion owns failure finalization.
			// A concurrent completion observer must not fail the in-flight owner.
			if (owns_completion) {
				if (!credential_id.empty()) registry.RemoveCredential(credential_id);
				auto failure = std::current_exception();
				if (context.IsInterrupted()) {
					try { registry.FinishFailed(id, data360::AuthFault::TOKEN_EXCHANGE_FAILED); } catch (...) {}
				}
				data360::RecordAuthCompletionFailure(
				    [&] { return context.IsInterrupted(); },
				    [&](data360::AuthFault fault) { try { registry.FinishFailed(id, fault); } catch (...) {} },
				    failure);
			}
		}
		snapshot = registry.Snapshot(id);
	}
	auto row = data360::ProjectAuthStatus(id, snapshot);
	out.SetValue(0, 0, Value(row.status));
	out.SetValue(1, 0, snapshot.secret_name.empty() ? Value() : Value(snapshot.secret_name));
	out.SetValue(2, 0, Value::TIMESTAMPTZ(timestamp_tz_t(snapshot.expires_at_utc_micros)));
	out.SetValue(3, 0, row.error_code.empty() ? Value() : Value(row.error_code));
	out.SetValue(4, 0, row.message.empty() ? Value() : Value(row.message));
	out.SetCardinality(1);
}

void AuthCancel(DataChunk &input, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, bool>(input.data[0], result, input.size(), [&](string_t id) {
		Data360AuthState::Get(context).Registry().Cancel(id.GetString()); return true;
	});
}

unique_ptr<FunctionData> DiagnosticsBind(ClientContext &, TableFunctionBindInput &,
                                        vector<LogicalType> &types, vector<string> &names) {
	types = {LogicalType::UINTEGER, LogicalType::VARCHAR, LogicalType::BOOLEAN, LogicalType::UBIGINT, LogicalType::UBIGINT};
	names = {"fault_protocol_version", "providers", "callback_supported", "active_session_count", "temporary_oauth_credential_count"};
	return make_uniq<EmptyBindData>();
}
void DiagnosticsExecute(ClientContext &context, TableFunctionInput &input, DataChunk &out) {
	auto &once = input.global_state->Cast<AuthOneRowState>(); if (once.emitted) return; once.emitted = true;
	auto &registry = Data360AuthState::Get(context).Registry();
	out.SetValue(0, 0, Value::UINTEGER(data360::AuthFaultProtocolVersion()));
	out.SetValue(1, 0, Value("oauth_pkce"));
	out.SetValue(2, 0, Value::BOOLEAN(true));
	out.SetValue(3, 0, Value::UBIGINT(registry.SessionCount()));
	out.SetValue(4, 0, Value::UBIGINT(registry.CredentialCount()));
	out.SetCardinality(1);
}

} // namespace

void RegisterData360AuthFunctions(ExtensionLoader &loader) {
	loader.RegisterFunction(TableFunction("data360_auth_start", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                      AuthStartExecute, AuthStartBind, AuthOneRowInit));
	loader.RegisterFunction(TableFunction("data360_auth_status", {LogicalType::VARCHAR}, AuthStatusExecute, AuthIdBind, AuthOneRowInit));
	loader.RegisterFunction(TableFunction("data360_auth_complete", {LogicalType::VARCHAR}, AuthCompleteExecute, AuthCompleteBind, AuthOneRowInit));
	loader.RegisterFunction(TableFunction("data360_diagnostics", {}, DiagnosticsExecute, DiagnosticsBind, AuthOneRowInit));
	ScalarFunction cancel("data360_auth_cancel", {LogicalType::VARCHAR}, LogicalType::BOOLEAN, AuthCancel);
	cancel.SetVolatile(); loader.RegisterFunction(std::move(cancel));
}

} // namespace duckdb
