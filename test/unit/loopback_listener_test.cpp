#include "data360/loopback_listener.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using TestSocket = SOCKET;
static constexpr TestSocket INVALID_TEST_SOCKET = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using TestSocket = int;
static constexpr TestSocket INVALID_TEST_SOCKET = -1;
#endif

using namespace data360;

#ifdef _WIN32
static_assert(NativeLoopbackBindPolicy() == LoopbackBindPolicy::EXCLUSIVE_ADDRESS_USE,
              "Windows loopback listeners must use exclusive address binding");
#else
static_assert(NativeLoopbackBindPolicy() == LoopbackBindPolicy::REUSE_ADDRESS,
              "POSIX loopback listeners must use reusable address binding");
#endif

namespace {

void Require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

template <class FN>
void RequireThrows(FN &&fn, const char *message) {
	try {
		fn();
	} catch (const CallbackProtocolError &) {
		return;
	}
	throw std::runtime_error(message);
}

class FakeAcceptor final : public LoopbackAcceptor {
public:
	std::string request;
	bool bound = false;
	bool closed = false;
	bool responded = false;
	std::string response;

	void Bind(const std::string &address, uint16_t port) override {
		Require(address == "127.0.0.1" && port == 8910, "listener must bind only the fixed IPv4 loopback endpoint");
		bound = true;
	}
	std::string AcceptOne(size_t maximum_bytes, uint64_t, const CancellationCheck &cancelled) override {
		Require(bound && !closed, "accept occurred without a live bind");
		if (cancelled()) {
			throw CallbackCancelled();
		}
		Require(request.size() <= maximum_bytes, "listener passed an undersized request cap");
		return request;
	}
	void Respond(const std::string &value) override {
		responded = true;
		response = value;
	}
	void Close() noexcept override {
		closed = true;
	}
};

void TestExactCallbackParsingAndSingleUseCode() {
	auto result = ParseOAuthCallbackRequest(
	    "GET /oauth/callback?code=abc%2D123&state=received HTTP/1.1\r\nHost: localhost:8910\r\n\r\n");
	Require(result.Status() == CallbackStatus::CODE_RECEIVED, "valid callback was not accepted");
	Require(result.State() == "received", "callback state was not returned for registry validation");
	Require(result.TakeCode() == "abc-123", "authorization code decoding failed");
	RequireThrows([&] { result.TakeCode(); }, "authorization code was reusable");
}

void TestMalformedCallbacksFailClosed() {
	for (const auto &request : {
	         "POST /oauth/callback?code=a&state=s HTTP/1.1\r\n\r\n",
	         "GET /wrong?code=a&state=s HTTP/1.1\r\n\r\n",
	         "GET /oauth/callback?code=a&code=b&state=s HTTP/1.1\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s&state=s HTTP/1.1\r\n\r\n",
	         "GET /oauth/callback?code=%GG&state=s HTTP/1.1\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\ncOnTeNt-LeNgTh: 0\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\ntRaNsFeR-EnCoDiNg: chunked\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nMalformed\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: 127.0.0.1:8910\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: LOCALHOST:8910\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: localhost\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: localhost:80\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: localhost.:8910\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: localhost:8910.evil.example\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: localhost@evil:8910\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: localhost:8910\r\nhOsT: 127.0.0.1:8910\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost : 127.0.0.1:8910\r\n\r\n",
	         "GET /oauth/callback?code=a&state=s HTTP/1.0\r\n\r\n"}) {
		RequireThrows([&] { ParseOAuthCallbackRequest(request); }, "malformed callback was accepted");
	}
	RequireThrows(
	    [&] {
		    ParseOAuthCallbackRequest("GET /oauth/callback?code=" + std::string(2049, 'a') +
		                                      "&state=s HTTP/1.1\r\n\r\n");
	    },
	    "oversized authorization code was accepted");
}

void TestProviderDenialIsSanitized() {
	auto result = ParseOAuthCallbackRequest(
	    "GET /oauth/callback?error=access_denied&error_description=secret-provider-detail&state=s HTTP/1.1\r\nHost: localhost:8910\r\n\r\n");
	Require(result.Status() == CallbackStatus::ACCESS_DENIED, "denial callback did not map to denial");
	Require(result.SafeErrorCode() == "USER_DENIED", "denial error was not sanitized");
	Require(result.SafeErrorCode().find("secret") == std::string::npos, "provider description leaked");
}

void TestListenerBindsBeforeWaitingAndAlwaysCloses() {
	auto acceptor = std::make_unique<FakeAcceptor>();
	auto *fake = acceptor.get();
	fake->request = "GET /oauth/callback?code=abc&state=s HTTP/1.1\r\nHost: localhost:8910\r\n\r\n";
	FixedLoopbackListener listener(std::move(acceptor));
	Require(fake->bound, "listener constructor must bind before authorization URL can be returned");
	auto result = listener.WaitForCallback(5000, [] { return false; });
	Require(result.State() == "s", "listener did not return callback state");
	Require(result.TakeCode() == "abc", "listener did not return parsed callback");
	Require(fake->closed, "one-shot listener did not close after callback");
	Require(fake->responded, "listener did not send a static response");
	Require(fake->response.find("abc") == std::string::npos && fake->response.find("state") == std::string::npos,
	        "response page included sensitive callback material");
	Require(fake->response.find("Content-Length: 76\r\n") != std::string::npos,
	        "success response Content-Length did not match its fixed body");
	RequireThrows([&] { listener.WaitForCallback(5000, [] { return false; }); },
	              "listener accepted a replay callback");
}

void TestListenerCancellationClosesWithoutResponse() {
	auto acceptor = std::make_unique<FakeAcceptor>();
	auto *fake = acceptor.get();
	FixedLoopbackListener listener(std::move(acceptor));
	try {
		listener.WaitForCallback(5000, [] { return true; });
		throw std::runtime_error("cancelled listener returned normally");
	} catch (const CallbackCancelled &) {
	}
	Require(fake->closed && !fake->responded, "cancelled listener did not close cleanly");
}

class BlockingAcceptor final : public LoopbackAcceptor {
public:
	void Bind(const std::string &, uint16_t) override {}
	std::string AcceptOne(size_t, uint64_t, const CancellationCheck &) override {
		std::unique_lock<std::mutex> guard(mutex);
		waiting = true;
		changed.notify_all();
		changed.wait(guard, [&] { return closed; });
		throw CallbackCancelled();
	}
	void Respond(const std::string &) override {}
	void Close() noexcept override {
		std::lock_guard<std::mutex> guard(mutex);
		closed = true;
		changed.notify_all();
	}
	void WaitUntilBlocked() {
		std::unique_lock<std::mutex> guard(mutex);
		changed.wait(guard, [&] { return waiting; });
	}
private:
	std::mutex mutex;
	std::condition_variable changed;
	bool waiting = false;
	bool closed = false;
};

void TestConcurrentCancelInterruptsWaitSafely() {
	auto acceptor = std::make_unique<BlockingAcceptor>();
	auto *blocking = acceptor.get();
	FixedLoopbackListener listener(std::move(acceptor));
	bool was_cancelled = false;
	std::thread waiter([&] {
		try { listener.WaitForCallback(5000, [] { return false; }); }
		catch (const CallbackCancelled &) { was_cancelled = true; }
	});
	blocking->WaitUntilBlocked();
	listener.Cancel();
	waiter.join();
	Require(was_cancelled, "concurrent cancellation did not interrupt callback wait");
	RequireThrows([&] { listener.WaitForCallback(5000, [] { return false; }); },
	              "cancelled listener was reusable");
}

void CloseTestSocket(TestSocket socket) {
	if (socket == INVALID_TEST_SOCKET) return;
#ifdef _WIN32
	closesocket(socket);
#else
	close(socket);
#endif
}

struct TcpPair {
	TestSocket listener = INVALID_TEST_SOCKET;
	TestSocket outbound = INVALID_TEST_SOCKET;
	TestSocket inbound = INVALID_TEST_SOCKET;

	TcpPair() = default;
	TcpPair(const TcpPair &) = delete;
	TcpPair &operator=(const TcpPair &) = delete;
	TcpPair(TcpPair &&other) noexcept
	    : listener(other.listener), outbound(other.outbound), inbound(other.inbound) {
		other.listener = INVALID_TEST_SOCKET;
		other.outbound = INVALID_TEST_SOCKET;
		other.inbound = INVALID_TEST_SOCKET;
	}
	~TcpPair() {
		CloseTestSocket(inbound);
		CloseTestSocket(outbound);
		CloseTestSocket(listener);
	}
};

TcpPair CreateUnrelatedTcpPair() {
	TcpPair pair;
	pair.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Require(pair.listener != INVALID_TEST_SOCKET, "could not create unrelated listener");
	sockaddr_in endpoint = {};
	endpoint.sin_family = AF_INET;
	endpoint.sin_port = 0;
	Require(inet_pton(AF_INET, "127.0.0.1", &endpoint.sin_addr) == 1,
	        "could not encode unrelated loopback endpoint");
	Require(bind(pair.listener, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) == 0,
	        "could not bind unrelated listener");
	Require(listen(pair.listener, 1) == 0, "could not listen on unrelated socket");
#ifdef _WIN32
	int endpoint_size = sizeof(endpoint);
#else
	socklen_t endpoint_size = sizeof(endpoint);
#endif
	Require(getsockname(pair.listener, reinterpret_cast<sockaddr *>(&endpoint), &endpoint_size) == 0,
	        "could not inspect unrelated listener");
	pair.outbound = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Require(pair.outbound != INVALID_TEST_SOCKET, "could not create unrelated client");
	Require(connect(pair.outbound, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) == 0,
	        "could not connect unrelated client");
	pair.inbound = accept(pair.listener, nullptr, nullptr);
	Require(pair.inbound != INVALID_TEST_SOCKET, "callback worker consumed an unrelated connection");
	return pair;
}

enum class NativeWaitResult { PENDING, CANCELLED, PROTOCOL_ERROR, RETURNED };

void WaitForNativeWorker(std::future<void> &worker, const std::chrono::steady_clock::time_point &started) {
	Require(worker.wait_for(std::chrono::milliseconds(900)) == std::future_status::ready,
	        "native callback cancellation exceeded one second");
	worker.get();
	Require(std::chrono::steady_clock::now() - started < std::chrono::seconds(1),
	        "native callback cancellation exceeded one second");
}

void TestNativeCancelDuringAcceptDoesNotReuseDescriptors() {
	const char *configured = std::getenv("DATA360_LOOPBACK_STRESS_REPETITIONS");
	const int repetitions = configured ? std::stoi(configured) : 10;
	Require(repetitions >= 1, "native stress repetition count must be positive");
	for (int iteration = 0; iteration < repetitions; iteration++) {
		auto acceptor = CreateNativeLoopbackAcceptor();
		acceptor->Bind("127.0.0.1", 8910);
		std::atomic<NativeWaitResult> result {NativeWaitResult::PENDING};
		std::promise<void> entered;
		auto entered_future = entered.get_future();
		const auto started = std::chrono::steady_clock::now();
		auto worker = std::async(std::launch::async, [&] {
			entered.set_value();
			try {
				acceptor->AcceptOne(8192, 800, [] { return false; });
				result.store(NativeWaitResult::RETURNED);
			} catch (const CallbackCancelled &) {
				result.store(NativeWaitResult::CANCELLED);
			} catch (const CallbackProtocolError &) {
				result.store(NativeWaitResult::PROTOCOL_ERROR);
			}
		});
		entered_future.wait();
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		acceptor->Close();
		auto unrelated = CreateUnrelatedTcpPair();
		WaitForNativeWorker(worker, started);
		Require(result.load() == NativeWaitResult::CANCELLED,
		        "closing native listener did not report cancellation during accept/select");
	}
}

void TestNativeCancelDuringReadDoesNotReuseDescriptors() {
	auto acceptor = CreateNativeLoopbackAcceptor();
	acceptor->Bind("127.0.0.1", 8910);
	TestSocket callback_client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Require(callback_client != INVALID_TEST_SOCKET, "could not create native callback client");
	sockaddr_in callback_endpoint = {};
	callback_endpoint.sin_family = AF_INET;
	callback_endpoint.sin_port = htons(8910);
	Require(inet_pton(AF_INET, "127.0.0.1", &callback_endpoint.sin_addr) == 1 &&
	            connect(callback_client, reinterpret_cast<sockaddr *>(&callback_endpoint), sizeof(callback_endpoint)) == 0,
	        "could not connect native callback client");
	std::atomic<NativeWaitResult> result {NativeWaitResult::PENDING};
	const auto started = std::chrono::steady_clock::now();
	auto worker = std::async(std::launch::async, [&] {
		try {
			acceptor->AcceptOne(8192, 800, [] { return false; });
			result.store(NativeWaitResult::RETURNED);
		} catch (const CallbackCancelled &) {
			result.store(NativeWaitResult::CANCELLED);
		} catch (const CallbackProtocolError &) {
			result.store(NativeWaitResult::PROTOCOL_ERROR);
		}
	});
	std::this_thread::sleep_for(std::chrono::milliseconds(5));
	acceptor->Close();
	auto unrelated = CreateUnrelatedTcpPair();
	const std::string sentinel = "unrelated-descriptor-payload";
#ifdef _WIN32
	const int sent = send(unrelated.inbound, sentinel.data(), static_cast<int>(sentinel.size()), 0);
#else
	const auto sent = send(unrelated.inbound, sentinel.data(), sentinel.size(), 0);
#endif
	Require(sent >= 0 && static_cast<size_t>(sent) == sentinel.size(), "could not send unrelated payload");
	WaitForNativeWorker(worker, started);
	Require(result.load() == NativeWaitResult::CANCELLED,
	        "closing native client did not report cancellation during read/select");
	char buffer[64] = {};
#ifdef _WIN32
	const int received = recv(unrelated.outbound, buffer, static_cast<int>(sizeof(buffer)), 0);
#else
	const auto received = recv(unrelated.outbound, buffer, sizeof(buffer), 0);
#endif
	Require(received >= 0 && static_cast<size_t>(received) == sentinel.size() &&
	            std::string(buffer, static_cast<size_t>(received)) == sentinel,
	        "callback worker received payload from an unrelated reused descriptor");
	CloseTestSocket(callback_client);
}

void TestNativeRejectsCompetingFixedPortBind() {
	auto first = CreateNativeLoopbackAcceptor();
	first->Bind("127.0.0.1", 8910);
	auto competing = CreateNativeLoopbackAcceptor();
	RequireThrows([&] { competing->Bind("127.0.0.1", 8910); },
	              "native listener allowed a competing fixed-port bind");
	first->Close();
}

void TestNativeResponseToNonReadingClientIsBounded() {
	auto acceptor = CreateNativeLoopbackAcceptor();
	acceptor->Bind("127.0.0.1", 8910);
	TestSocket callback_client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Require(callback_client != INVALID_TEST_SOCKET, "could not create callback client for response test");
	int receive_buffer = 1024;
	Require(setsockopt(callback_client, SOL_SOCKET, SO_RCVBUF,
	                   reinterpret_cast<const char *>(&receive_buffer), sizeof(receive_buffer)) == 0,
	        "could not constrain callback receive buffer");
	sockaddr_in endpoint = {};
	endpoint.sin_family = AF_INET;
	endpoint.sin_port = htons(8910);
	Require(inet_pton(AF_INET, "127.0.0.1", &endpoint.sin_addr) == 1 &&
	            connect(callback_client, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) == 0,
	        "could not connect callback client for response test");
	const std::string request =
	    "GET /oauth/callback?code=a&state=s HTTP/1.1\r\nHost: localhost:8910\r\n\r\n";
#ifdef _WIN32
	const int request_sent = send(callback_client, request.data(), static_cast<int>(request.size()), 0);
#else
	const auto request_sent = send(callback_client, request.data(), request.size(), 0);
#endif
	Require(request_sent >= 0 && static_cast<size_t>(request_sent) == request.size(),
	        "could not send callback request for response test");
	Require(acceptor->AcceptOne(8192, 1000, [] { return false; }) == request,
	        "native listener did not receive callback request for response test");
	const std::string oversized_response(64 * 1024 * 1024, 'x');
	const auto started = std::chrono::steady_clock::now();
	auto worker = std::async(std::launch::async, [&] { acceptor->Respond(oversized_response); });
	Require(worker.wait_for(std::chrono::milliseconds(900)) == std::future_status::ready,
	        "native response blocked on a non-reading client");
	worker.get();
	Require(std::chrono::steady_clock::now() - started < std::chrono::seconds(1),
	        "native response exceeded its bounded send deadline");
	acceptor->Close();
	CloseTestSocket(callback_client);
}

} // namespace

int main() {
	try {
		TestExactCallbackParsingAndSingleUseCode();
		TestMalformedCallbacksFailClosed();
		TestProviderDenialIsSanitized();
		TestListenerBindsBeforeWaitingAndAlwaysCloses();
		TestListenerCancellationClosesWithoutResponse();
		TestConcurrentCancelInterruptsWaitSafely();
		TestNativeCancelDuringAcceptDoesNotReuseDescriptors();
		TestNativeCancelDuringReadDoesNotReuseDescriptors();
		TestNativeRejectsCompetingFixedPortBind();
		TestNativeResponseToNonReadingClientIsBounded();
		std::cout << "loopback_listener tests passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "loopback_listener test failed: " << error.what() << '\n';
		return 1;
	}
}
