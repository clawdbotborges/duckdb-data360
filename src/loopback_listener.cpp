#include "data360/loopback_listener.hpp"
#include "data360/oauth_pkce.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <map>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = SOCKET;
static constexpr SocketHandle INVALID_SOCKET_HANDLE = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
static constexpr SocketHandle INVALID_SOCKET_HANDLE = -1;
#endif

namespace data360 {
namespace {

constexpr size_t MAX_CALLBACK_REQUEST_BYTES = 8192;
constexpr size_t MAX_CALLBACK_VALUE_BYTES = 2048;
constexpr int64_t SOCKET_WAIT_SLICE_MS = 50;
constexpr int64_t RESPONSE_DEADLINE_MS = 250;

void CloseSocket(SocketHandle socket) noexcept {
	if (socket == INVALID_SOCKET_HANDLE) {
		return;
	}
#ifdef _WIN32
	closesocket(socket);
#else
	close(socket);
#endif
}

bool SetNonBlocking(SocketHandle socket) noexcept {
#ifdef _WIN32
	u_long enabled = 1;
	return ioctlsocket(socket, FIONBIO, &enabled) == 0;
#else
	const int flags = fcntl(socket, F_GETFL, 0);
	return flags >= 0 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool SocketOperationWouldBlock() noexcept {
#ifdef _WIN32
	return WSAGetLastError() == WSAEWOULDBLOCK;
#else
	return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS;
#endif
}

bool SocketOperationInterrupted() noexcept {
#ifdef _WIN32
	return WSAGetLastError() == WSAEINTR;
#else
	return errno == EINTR;
#endif
}

int HexValue(char value) {
	if (value >= '0' && value <= '9') {
		return value - '0';
	}
	if (value >= 'A' && value <= 'F') {
		return value - 'A' + 10;
	}
	if (value >= 'a' && value <= 'f') {
		return value - 'a' + 10;
	}
	return -1;
}

std::string PercentDecode(const std::string &value) {
	std::string output;
	output.reserve(value.size());
	for (size_t i = 0; i < value.size(); i++) {
		const char c = value[i];
		if (c == '%') {
			if (i + 2 >= value.size()) {
				throw CallbackProtocolError("malformed OAuth callback");
			}
			const int high = HexValue(value[i + 1]);
			const int low = HexValue(value[i + 2]);
			if (high < 0 || low < 0) {
				throw CallbackProtocolError("malformed OAuth callback");
			}
			const char decoded = static_cast<char>((high << 4) | low);
			if (static_cast<unsigned char>(decoded) < 0x20U || decoded == 0x7f) {
				throw CallbackProtocolError("malformed OAuth callback");
			}
			output.push_back(decoded);
			i += 2;
		} else {
			if (c == '+' || static_cast<unsigned char>(c) < 0x20U || c == 0x7f) {
				throw CallbackProtocolError("malformed OAuth callback");
			}
			output.push_back(c);
		}
	}
	if (output.size() > MAX_CALLBACK_VALUE_BYTES) {
		throw CallbackProtocolError("oversized OAuth callback field");
	}
	return output;
}

std::map<std::string, std::string> ParseQuery(const std::string &query) {
	std::map<std::string, std::string> values;
	for (size_t start = 0; start <= query.size();) {
		const auto end = query.find('&', start);
		const auto item = query.substr(start, end == std::string::npos ? std::string::npos : end - start);
		const auto equals = item.find('=');
		if (item.empty() || equals == std::string::npos || equals == 0) {
			throw CallbackProtocolError("malformed OAuth callback");
		}
		const auto key = PercentDecode(item.substr(0, equals));
		const auto value = PercentDecode(item.substr(equals + 1));
		if (!values.emplace(key, value).second) {
			throw CallbackProtocolError("duplicate OAuth callback field");
		}
		if (end == std::string::npos) {
			break;
		}
		start = end + 1;
	}
	return values;
}

const std::string &SuccessResponse() {
	static const std::string response =
	    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n"
	    "Content-Length: 76\r\n\r\n<!doctype html><title>Authorization received</title>You may close this page.";
	return response;
}

const std::string &FailureResponse() {
	static const std::string response =
	    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n"
	    "Content-Length: 74\r\n\r\n<!doctype html><title>Authorization failed</title>Please return to DuckDB.";
	return response;
}

class NativeLoopbackAcceptor final : public LoopbackAcceptor {
public:
	NativeLoopbackAcceptor() {
#ifdef _WIN32
		WSADATA data;
		if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
			throw CallbackProtocolError("loopback networking unavailable");
		}
		winsock_started = true;
#endif
	}

	~NativeLoopbackAcceptor() override {
		Close();
#ifdef _WIN32
		if (winsock_started) {
			WSACleanup();
		}
#endif
	}

	void Bind(const std::string &address, uint16_t port) override {
		std::lock_guard<std::mutex> guard(socket_mutex);
		if (address != "127.0.0.1" || port != 8910 || close_requested.load() ||
		    listener != INVALID_SOCKET_HANDLE) {
			throw CallbackProtocolError("invalid loopback bind request");
		}
		listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listener == INVALID_SOCKET_HANDLE) {
			throw CallbackProtocolError("callback port unavailable");
		}
#ifndef _WIN32
		if (listener < 0 || listener >= FD_SETSIZE) {
			CloseSocket(listener);
			listener = INVALID_SOCKET_HANDLE;
			throw CallbackProtocolError("callback listener unavailable");
		}
#endif
		if (!SetNonBlocking(listener)) {
			CloseSocket(listener);
			listener = INVALID_SOCKET_HANDLE;
			throw CallbackProtocolError("callback port unavailable");
		}
		int bind_option = 1;
#ifdef _WIN32
		static_assert(NativeLoopbackBindPolicy() == LoopbackBindPolicy::EXCLUSIVE_ADDRESS_USE,
		              "Windows callback sockets require exclusive address use");
		const int option = SO_EXCLUSIVEADDRUSE;
#else
		static_assert(NativeLoopbackBindPolicy() == LoopbackBindPolicy::REUSE_ADDRESS,
		              "POSIX callback sockets require reusable address binding");
		const int option = SO_REUSEADDR;
#endif
		if (setsockopt(listener, SOL_SOCKET, option, reinterpret_cast<const char *>(&bind_option),
		               sizeof(bind_option)) != 0) {
			CloseSocket(listener);
			listener = INVALID_SOCKET_HANDLE;
			throw CallbackProtocolError("callback port unavailable");
		}
		sockaddr_in endpoint = {};
		endpoint.sin_family = AF_INET;
		endpoint.sin_port = htons(port);
		if (inet_pton(AF_INET, address.c_str(), &endpoint.sin_addr) != 1 ||
		    bind(listener, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) != 0 ||
		    listen(listener, 1) != 0) {
			CloseSocket(listener);
			listener = INVALID_SOCKET_HANDLE;
			throw CallbackProtocolError("callback port unavailable");
		}
	}

	std::string AcceptOne(size_t maximum_bytes, uint64_t timeout_ms, const CancellationCheck &cancelled) override {
		{
			std::lock_guard<std::mutex> guard(socket_mutex);
			if (close_requested.load()) throw CallbackCancelled();
			if (listener == INVALID_SOCKET_HANDLE || maximum_bytes > MAX_CALLBACK_REQUEST_BYTES) {
				throw CallbackProtocolError("invalid callback listener state");
			}
		}
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
		for (;;) {
			if (close_requested.load()) throw CallbackCancelled();
			if (cancelled()) {
				throw CallbackCancelled();
			}
			const auto now = std::chrono::steady_clock::now();
			if (now >= deadline) {
				throw CallbackProtocolError("OAuth callback timed out");
			}
			const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
			std::unique_lock<std::mutex> guard(socket_mutex);
			if (client != INVALID_SOCKET_HANDLE) break;
			if (listener == INVALID_SOCKET_HANDLE) throw CallbackCancelled();
			timeval wait = {};
			wait.tv_usec = static_cast<long>(std::min<int64_t>(remaining, SOCKET_WAIT_SLICE_MS) * 1000);
			fd_set readers;
			FD_ZERO(&readers);
#ifndef _WIN32
			if (listener < 0 || listener >= FD_SETSIZE) {
				throw CallbackProtocolError("callback listener unavailable");
			}
#endif
			FD_SET(listener, &readers);
#ifdef _WIN32
			const int ready = select(0, &readers, nullptr, nullptr, &wait);
#else
			const int ready = select(listener + 1, &readers, nullptr, nullptr, &wait);
#endif
			if (ready < 0) {
				if (SocketOperationInterrupted()) continue;
				throw CallbackProtocolError("callback listener failed");
			}
			if (ready == 0) {
				if (close_requested.load()) throw CallbackCancelled();
				continue;
			}
			const auto accepted = accept(listener, nullptr, nullptr);
			if (accepted == INVALID_SOCKET_HANDLE) {
				if (SocketOperationWouldBlock() || SocketOperationInterrupted()) continue;
				throw CallbackProtocolError("callback listener failed");
			}
			if (!SetNonBlocking(accepted)) {
				CloseSocket(accepted);
				throw CallbackProtocolError("callback listener failed");
			}
#ifndef _WIN32
			if (accepted < 0 || accepted >= FD_SETSIZE) {
				CloseSocket(accepted);
				throw CallbackProtocolError("callback listener unavailable");
			}
#endif
#if defined(SO_NOSIGPIPE) && !defined(_WIN32)
			int enabled = 1;
			if (setsockopt(accepted, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
				CloseSocket(accepted);
				throw CallbackProtocolError("callback listener failed");
			}
#endif
			client = accepted;
			break;
		}
		std::string request;
		request.reserve(std::min<size_t>(maximum_bytes, 1024));
		char buffer[512];
		while (request.find("\r\n\r\n") == std::string::npos) {
			if (close_requested.load()) throw CallbackCancelled();
			if (cancelled()) {
				throw CallbackCancelled();
			}
			const auto now = std::chrono::steady_clock::now();
			if (now >= deadline) throw CallbackProtocolError("OAuth callback timed out");
			const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
			std::unique_lock<std::mutex> guard(socket_mutex);
			if (client == INVALID_SOCKET_HANDLE) throw CallbackCancelled();
			timeval wait = {};
			wait.tv_usec = static_cast<long>(std::min<int64_t>(remaining, SOCKET_WAIT_SLICE_MS) * 1000);
			fd_set readers;
			FD_ZERO(&readers);
#ifndef _WIN32
			if (client < 0 || client >= FD_SETSIZE) {
				throw CallbackProtocolError("callback listener unavailable");
			}
#endif
			FD_SET(client, &readers);
#ifdef _WIN32
			const int ready = select(0, &readers, nullptr, nullptr, &wait);
#else
			const int ready = select(client + 1, &readers, nullptr, nullptr, &wait);
#endif
			if (ready < 0) {
				if (SocketOperationInterrupted()) continue;
				throw CallbackProtocolError("callback listener failed");
			}
			if (ready == 0) {
				if (close_requested.load()) throw CallbackCancelled();
				continue;
			}
#ifdef _WIN32
			const int count = recv(client, buffer, static_cast<int>(sizeof(buffer)), 0);
#else
			const auto count = recv(client, buffer, sizeof(buffer), 0);
#endif
			if (count < 0 && (SocketOperationWouldBlock() || SocketOperationInterrupted())) continue;
			if (count <= 0 || request.size() + static_cast<size_t>(count) > maximum_bytes) {
				throw CallbackProtocolError("invalid or oversized callback request");
			}
			request.append(buffer, static_cast<size_t>(count));
		}
		return request;
	}

	void Respond(const std::string &response) override {
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(RESPONSE_DEADLINE_MS);
		size_t sent = 0;
		while (sent < response.size()) {
			if (close_requested.load() || std::chrono::steady_clock::now() >= deadline) return;
			std::lock_guard<std::mutex> guard(socket_mutex);
			if (close_requested.load() || client == INVALID_SOCKET_HANDLE) return;
			const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
			    deadline - std::chrono::steady_clock::now()).count();
			if (remaining <= 0) return;
			timeval wait = {};
			wait.tv_usec = static_cast<long>(std::min<int64_t>(remaining, SOCKET_WAIT_SLICE_MS) * 1000);
			fd_set writers;
			FD_ZERO(&writers);
#ifndef _WIN32
			if (client < 0 || client >= FD_SETSIZE) return;
#endif
			FD_SET(client, &writers);
#ifdef _WIN32
			const int ready = select(0, nullptr, &writers, nullptr, &wait);
#else
			const int ready = select(client + 1, nullptr, &writers, nullptr, &wait);
#endif
			if (ready < 0) {
				if (SocketOperationInterrupted()) continue;
				return;
			}
			if (ready == 0) continue;
#ifdef _WIN32
			const int count = send(client, response.data() + sent, static_cast<int>(response.size() - sent), 0);
#else
			const auto count = send(client, response.data() + sent, response.size() - sent,
#ifdef MSG_NOSIGNAL
			                        MSG_NOSIGNAL
#else
			                        0
#endif
			);
#endif
			if (count < 0 && (SocketOperationWouldBlock() || SocketOperationInterrupted())) continue;
			if (count <= 0) return;
			sent += static_cast<size_t>(count);
		}
	}

	void Close() noexcept override {
		close_requested.store(true);
		std::lock_guard<std::mutex> guard(socket_mutex);
		if (client != INVALID_SOCKET_HANDLE) {
#ifdef _WIN32
			shutdown(client, SD_BOTH);
#else
			shutdown(client, SHUT_RDWR);
#endif
		}
		CloseSocket(client);
		CloseSocket(listener);
		client = INVALID_SOCKET_HANDLE;
		listener = INVALID_SOCKET_HANDLE;
	}

private:
	std::atomic<bool> close_requested {false};
	std::mutex socket_mutex;
	SocketHandle listener = INVALID_SOCKET_HANDLE;
	SocketHandle client = INVALID_SOCKET_HANDLE;
#ifdef _WIN32
	bool winsock_started = false;
#endif
};

} // namespace

CallbackResult::CallbackResult(CallbackStatus status_p, std::string state_p, std::string code_p,
                               std::string safe_error_code_p)
    : status(status_p), state(std::move(state_p)), code(std::move(code_p)),
      safe_error_code(std::move(safe_error_code_p)) {
}

CallbackStatus CallbackResult::Status() const {
	return status;
}

const std::string &CallbackResult::State() const {
	return state;
}

const std::string &CallbackResult::SafeErrorCode() const {
	return safe_error_code;
}

std::string CallbackResult::TakeCode() {
	if (status != CallbackStatus::CODE_RECEIVED || code_taken || code.empty()) {
		throw CallbackProtocolError("authorization code unavailable");
	}
	code_taken = true;
	return std::move(code);
}

CallbackResult ParseOAuthCallbackRequest(const std::string &request) {
	if (request.empty() || request.size() > MAX_CALLBACK_REQUEST_BYTES) {
		throw CallbackProtocolError("invalid or oversized callback request");
	}
	const auto header_end = request.find("\r\n\r\n");
	if (header_end == std::string::npos || header_end + 4 != request.size()) {
		throw CallbackProtocolError("callback request body forbidden");
	}
	const auto line_end = request.find("\r\n");
	if (line_end == std::string::npos) {
		throw CallbackProtocolError("malformed OAuth callback");
	}
	const auto request_line = request.substr(0, line_end);
	static const std::string prefix = "GET /oauth/callback?";
	static const std::string suffix = " HTTP/1.1";
	if (request_line.compare(0, prefix.size(), prefix) != 0 || request_line.size() <= prefix.size() + suffix.size() ||
	    request_line.compare(request_line.size() - suffix.size(), suffix.size(), suffix) != 0) {
		throw CallbackProtocolError("invalid OAuth callback method or path");
	}
	const auto headers = request.substr(line_end + 2, header_end - (line_end + 2));
	bool found_host = false;
	for (size_t start = 0; start < headers.size();) {
		const auto end = headers.find("\r\n", start);
		auto line = headers.substr(start, end == std::string::npos ? std::string::npos : end - start);
		const auto colon = line.find(':');
		if (colon == std::string::npos || colon == 0 || line[colon - 1] == ' ' || line[colon - 1] == '	')
			throw CallbackProtocolError("malformed callback header");
		auto key = line.substr(0, colon);
		for (unsigned char c : key) {
			if (!std::isalnum(c) && c != '-') throw CallbackProtocolError("malformed callback header");
		}
		std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		auto value = line.substr(colon + 1);
		while (!value.empty() && (value.front() == ' ' || value.front() == '	')) value.erase(value.begin());
		while (!value.empty() && (value.back() == ' ' || value.back() == '	')) value.pop_back();
		for (unsigned char c : value) if (c < 0x20U && c != '	') throw CallbackProtocolError("malformed callback header");
		if (key == "content-length" || key == "transfer-encoding")
			throw CallbackProtocolError("callback request body forbidden");
		if (key == "host") {
			if (found_host || value != "127.0.0.1:8910") throw CallbackProtocolError("invalid callback host");
			found_host = true;
		}
		if (end == std::string::npos) break;
		start = end + 2;
	}
	if (!found_host) throw CallbackProtocolError("invalid callback host");
	const auto query = request_line.substr(prefix.size(), request_line.size() - prefix.size() - suffix.size());
	const auto fields = ParseQuery(query);
	const auto state = fields.find("state");
	if (state == fields.end() || state->second.empty()) {
		throw CallbackProtocolError("OAuth callback state missing");
	}
	const auto error = fields.find("error");
	const auto code = fields.find("code");
	if (error != fields.end()) {
		if (code != fields.end() || error->second != "access_denied") {
			throw CallbackProtocolError("OAuth provider rejected callback");
		}
		return {CallbackStatus::ACCESS_DENIED, state->second, {}, "USER_DENIED"};
	}
	if (code == fields.end() || code->second.empty()) {
		throw CallbackProtocolError("authorization code missing");
	}
	return {CallbackStatus::CODE_RECEIVED, state->second, code->second, {}};
}

std::unique_ptr<LoopbackAcceptor> CreateNativeLoopbackAcceptor() {
	return std::make_unique<NativeLoopbackAcceptor>();
}

FixedLoopbackListener::FixedLoopbackListener(std::unique_ptr<LoopbackAcceptor> acceptor_p) : acceptor(std::move(acceptor_p)) {
	if (!acceptor) {
		throw CallbackProtocolError("callback listener unavailable");
	}
	acceptor->Bind("127.0.0.1", 8910);
}

FixedLoopbackListener::~FixedLoopbackListener() {
	Cancel();
	std::unique_lock<std::mutex> guard(mutex);
	idle.wait(guard, [&] { return !waiting; });
}

CallbackResult FixedLoopbackListener::WaitForCallback(uint64_t timeout_ms, const CancellationCheck &cancelled) {
	{
		std::lock_guard<std::mutex> guard(mutex);
		if (consumed || timeout_ms == 0 || timeout_ms > 600000) {
			throw CallbackProtocolError("invalid callback listener state");
		}
		consumed = true;
		waiting = true;
	}
	try {
		auto request = acceptor->AcceptOne(MAX_CALLBACK_REQUEST_BYTES, timeout_ms, cancelled);
		auto result = ParseOAuthCallbackRequest(request);
		acceptor->Respond(result.Status() == CallbackStatus::CODE_RECEIVED ? SuccessResponse() : FailureResponse());
		acceptor->Close();
		{
			std::lock_guard<std::mutex> guard(mutex);
			waiting = false;
		}
		idle.notify_all();
		return result;
	} catch (...) {
		acceptor->Close();
		{
			std::lock_guard<std::mutex> guard(mutex);
			waiting = false;
		}
		idle.notify_all();
		throw;
	}
}

void FixedLoopbackListener::Cancel() noexcept {
	{
		std::lock_guard<std::mutex> guard(mutex);
		consumed = true;
	}
	acceptor->Close();
}

} // namespace data360
