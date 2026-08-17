#pragma once

#include "data360/query_api.hpp"

#include <atomic>

namespace data360 {

class LibcurlTransport final : public HttpTransport {
public:
	explicit LibcurlTransport(RuntimeHooks *runtime = nullptr) : runtime(runtime) {
	}
	HttpResponse Send(const HttpRequest &request) override;

private:
	RuntimeHooks *runtime;
};

class JsonQueryResponseCodec final : public QueryResponseCodec {
public:
	QueryResponse Decode(const HttpResponse &response) override;
};

class SteadyRuntime final : public RuntimeHooks {
public:
	explicit SteadyRuntime(const std::atomic<bool> *cancelled = nullptr);
	bool IsCancelled() override;
	uint64_t NowMs() override;
	void SleepMs(uint64_t milliseconds) override;

private:
	const std::atomic<bool> *cancelled;
};

} // namespace data360
