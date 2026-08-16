#pragma once

#include "data360/query_api.hpp"

#include <atomic>

namespace data360 {

QueryCredentials ResolveProcessCapability(const std::string &broker_path, const std::string &login_url,
                                          RuntimeHooks *runtime = nullptr);

class CurlProcessTransport final : public HttpTransport {
public:
	explicit CurlProcessTransport(RuntimeHooks *runtime = nullptr) : runtime(runtime) {
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
