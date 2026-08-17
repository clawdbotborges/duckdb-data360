#pragma once

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace data360 {

enum class CallbackStatus { CODE_RECEIVED, ACCESS_DENIED };

class CallbackProtocolError : public std::runtime_error {
public:
	explicit CallbackProtocolError(const std::string &message) : std::runtime_error(message) {
	}
};

class CallbackCancelled : public std::runtime_error {
public:
	CallbackCancelled() : std::runtime_error("OAuth callback cancelled") {
	}
};

class CallbackResult {
public:
	CallbackResult(CallbackStatus status, std::string state, std::string code, std::string safe_error_code);
	CallbackResult(const CallbackResult &) = delete;
	CallbackResult &operator=(const CallbackResult &) = delete;
	CallbackResult(CallbackResult &&) noexcept = default;
	CallbackResult &operator=(CallbackResult &&) noexcept = default;

	CallbackStatus Status() const;
	const std::string &State() const;
	const std::string &SafeErrorCode() const;
	std::string TakeCode();

private:
	CallbackStatus status;
	std::string state;
	std::string code;
	std::string safe_error_code;
	bool code_taken = false;
};

CallbackResult ParseOAuthCallbackRequest(const std::string &request);

using CancellationCheck = std::function<bool()>;

enum class LoopbackBindPolicy { REUSE_ADDRESS, EXCLUSIVE_ADDRESS_USE };

constexpr LoopbackBindPolicy NativeLoopbackBindPolicy() {
#ifdef _WIN32
	return LoopbackBindPolicy::EXCLUSIVE_ADDRESS_USE;
#else
	return LoopbackBindPolicy::REUSE_ADDRESS;
#endif
}

class LoopbackAcceptor {
public:
	virtual ~LoopbackAcceptor() = default;
	virtual void Bind(const std::string &address, uint16_t port) = 0;
	virtual std::string AcceptOne(size_t maximum_bytes, uint64_t timeout_ms, const CancellationCheck &cancelled) = 0;
	virtual void Respond(const std::string &response) = 0;
	virtual void Close() noexcept = 0;
};

std::unique_ptr<LoopbackAcceptor> CreateNativeLoopbackAcceptor();

class FixedLoopbackListener {
public:
	explicit FixedLoopbackListener(std::unique_ptr<LoopbackAcceptor> acceptor = CreateNativeLoopbackAcceptor());
	~FixedLoopbackListener();
	FixedLoopbackListener(const FixedLoopbackListener &) = delete;
	FixedLoopbackListener &operator=(const FixedLoopbackListener &) = delete;

	CallbackResult WaitForCallback(uint64_t timeout_ms, const CancellationCheck &cancelled);
	void Cancel() noexcept;

private:
	std::unique_ptr<LoopbackAcceptor> acceptor;
	std::mutex mutex;
	std::condition_variable idle;
	bool consumed = false;
	bool waiting = false;
};

} // namespace data360
