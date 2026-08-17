#include "data360/native_runtime.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>

namespace data360 {
namespace {

struct CurlDeleter { void operator()(CURL *value) const { if (value) curl_easy_cleanup(value); } };
struct HeaderDeleter { void operator()(curl_slist *value) const { if (value) curl_slist_free_all(value); } };
using CurlHandle = std::unique_ptr<CURL, CurlDeleter>;
using CurlHeaders = std::unique_ptr<curl_slist, HeaderDeleter>;

struct TransferState {
	HttpResponse response {0, {}, {}};
	uint64_t limit = 0;
	RuntimeHooks *runtime = nullptr;
	bool cleanup_request = false;
	bool exceeded_limit = false;
	bool exceeded_headers = false;
	bool cancelled = false;
	size_t header_count = 0;
	size_t header_bytes = 0;
};

void InitializeCurl() {
	static std::once_flag once;
	static CURLcode result = CURLE_FAILED_INIT;
	std::call_once(once, [] { result = curl_global_init(CURL_GLOBAL_DEFAULT); });
	if (result != CURLE_OK) throw std::runtime_error("D360-AUTH-008 NETWORK_UNAVAILABLE");
}

bool ContainsForbidden(const std::string &value) {
	return value.find('\r') != std::string::npos || value.find('\n') != std::string::npos ||
	       value.find('\0') != std::string::npos;
}

size_t WriteBody(char *pointer, size_t size, size_t count, void *opaque) {
	auto &state = *static_cast<TransferState *>(opaque);
	if (size != 0 && count > SIZE_MAX / size) {
		state.exceeded_limit = true;
		return CURL_WRITEFUNC_ERROR;
	}
	const auto bytes = size * count;
	if (bytes > state.limit - std::min<uint64_t>(state.response.body.size(), state.limit)) {
		state.exceeded_limit = true;
		return CURL_WRITEFUNC_ERROR;
	}
	state.response.body.append(pointer, bytes);
	return bytes;
}

std::string Lower(std::string value) {
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return value;
}

size_t WriteHeader(char *pointer, size_t size, size_t count, void *opaque) {
	auto &state = *static_cast<TransferState *>(opaque);
	if (size != 0 && count > SIZE_MAX / size) return 0;
	const auto bytes = size * count;
	std::string line(pointer, bytes);
	if (line.rfind("HTTP/", 0) == 0) {
		state.response.headers.clear();
		state.header_count = 0;
		state.header_bytes = 0;
		return bytes;
	}
	if (bytes > 8192 || bytes > 64 * 1024 - std::min<size_t>(state.header_bytes, 64 * 1024) || state.header_count >= 64) {
		state.exceeded_headers = true;
		return 0;
	}
	state.header_bytes += bytes;
	state.header_count++;
	while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
	if (line.empty()) return bytes;
	const auto colon = line.find(':');
	if (colon == std::string::npos || colon == 0) return bytes;
	auto key = Lower(line.substr(0, colon));
	auto value = line.substr(colon + 1);
	while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
	if (key.size() <= 256 && value.size() <= 8192) state.response.headers[key] = value;
	return bytes;
}

int TransferProgress(void *opaque, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
	auto &state = *static_cast<TransferState *>(opaque);
	if (!state.cleanup_request && state.runtime && state.runtime->IsCancelled()) {
		state.cancelled = true;
		return 1;
	}
	return 0;
}

const char *SystemCaBundle() {
	for (const auto *name : {"CURL_CA_BUNDLE", "SSL_CERT_FILE"}) {
		const auto *value = std::getenv(name);
		if (value && *value && !ContainsForbidden(value)) return value;
	}
	for (const auto *path : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	                         "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"}) {
		std::ifstream input(path);
		if (input.good()) return path;
	}
	return nullptr;
}

void Check(CURLcode result) {
	if (result != CURLE_OK) throw std::runtime_error("D360-AUTH-008 NETWORK_UNAVAILABLE");
}

} // namespace

HttpResponse LibcurlTransport::Send(const HttpRequest &request) {
	if (request.follow_redirects || request.timeout_ms == 0 || request.timeout_ms > static_cast<uint64_t>(LONG_MAX) ||
	    request.max_response_bytes == 0 || request.body.size() > 1024ULL * 1024ULL || request.url.rfind("https://", 0) != 0 ||
	    ContainsForbidden(request.url) ||
	    (request.method != "GET" && request.method != "POST" && request.method != "DELETE")) {
		throw std::invalid_argument("Data 360 HTTPS request configuration is invalid");
	}
	for (const auto &header : request.headers) {
		if (header.first.empty() || ContainsForbidden(header.first) || ContainsForbidden(header.second) ||
		    header.first.find(':') != std::string::npos)
			throw std::invalid_argument("Data 360 HTTPS request configuration is invalid");
	}
	if (request.headers.size() > 64) throw std::invalid_argument("Data 360 HTTPS request configuration is invalid");
	size_t request_header_bytes = 0;
	for (const auto &header : request.headers) {
		const auto bytes = header.first.size() + header.second.size() + 4;
		if (bytes > 8192 || bytes > 64 * 1024 - std::min<size_t>(request_header_bytes, 64 * 1024))
			throw std::invalid_argument("Data 360 HTTPS request configuration is invalid");
		request_header_bytes += bytes;
	}
	InitializeCurl();
	CurlHandle easy(curl_easy_init());
	if (!easy) throw std::runtime_error("D360-AUTH-008 NETWORK_UNAVAILABLE");
	TransferState transfer;
	transfer.limit = request.max_response_bytes;
	transfer.runtime = runtime;
	transfer.cleanup_request = request.cleanup_request;

	Check(curl_easy_setopt(easy.get(), CURLOPT_URL, request.url.c_str()));
	Check(curl_easy_setopt(easy.get(), CURLOPT_PROTOCOLS_STR, "HTTPS"));
	Check(curl_easy_setopt(easy.get(), CURLOPT_REDIR_PROTOCOLS_STR, "HTTPS"));
	Check(curl_easy_setopt(easy.get(), CURLOPT_FOLLOWLOCATION, 0L));
	Check(curl_easy_setopt(easy.get(), CURLOPT_MAXREDIRS, 0L));
	Check(curl_easy_setopt(easy.get(), CURLOPT_NOSIGNAL, 1L));
	Check(curl_easy_setopt(easy.get(), CURLOPT_SSL_VERIFYPEER, 1L));
	Check(curl_easy_setopt(easy.get(), CURLOPT_SSL_VERIFYHOST, 2L));
	Check(curl_easy_setopt(easy.get(), CURLOPT_PROXY, ""));
	Check(curl_easy_setopt(easy.get(), CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(request.timeout_ms)));
	Check(curl_easy_setopt(easy.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(request.timeout_ms)));
	Check(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION, WriteBody));
	Check(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &transfer));
	Check(curl_easy_setopt(easy.get(), CURLOPT_HEADERFUNCTION, WriteHeader));
	Check(curl_easy_setopt(easy.get(), CURLOPT_HEADERDATA, &transfer));
	Check(curl_easy_setopt(easy.get(), CURLOPT_NOPROGRESS, 0L));
	Check(curl_easy_setopt(easy.get(), CURLOPT_XFERINFOFUNCTION, TransferProgress));
	Check(curl_easy_setopt(easy.get(), CURLOPT_XFERINFODATA, &transfer));
	if (const auto *ca = SystemCaBundle()) Check(curl_easy_setopt(easy.get(), CURLOPT_CAINFO, ca));

	curl_slist *raw_headers = nullptr;
	auto append_header = [&](const std::string &value) {
		auto *updated = curl_slist_append(raw_headers, value.c_str());
		if (!updated) {
			curl_slist_free_all(raw_headers);
			raw_headers = nullptr;
			throw std::runtime_error("D360-AUTH-008 NETWORK_UNAVAILABLE");
		}
		raw_headers = updated;
	};
	append_header("Expect:");
	for (const auto &header : request.headers) append_header(header.first + ": " + header.second);
	CurlHeaders headers(raw_headers);
	if (!headers) throw std::runtime_error("D360-AUTH-008 NETWORK_UNAVAILABLE");
	Check(curl_easy_setopt(easy.get(), CURLOPT_HTTPHEADER, headers.get()));

	if (request.method == "GET") Check(curl_easy_setopt(easy.get(), CURLOPT_HTTPGET, 1L));
	else if (request.method == "POST") Check(curl_easy_setopt(easy.get(), CURLOPT_POST, 1L));
	else Check(curl_easy_setopt(easy.get(), CURLOPT_CUSTOMREQUEST, "DELETE"));
	if (request.method == "POST" || !request.body.empty()) {
		Check(curl_easy_setopt(easy.get(), CURLOPT_POSTFIELDS, request.body.data()));
		Check(curl_easy_setopt(easy.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size())));
	}

	const auto result = curl_easy_perform(easy.get());
	if (transfer.exceeded_limit) throw std::runtime_error("Data 360 HTTPS response exceeded limit");
	if (transfer.exceeded_headers) throw std::runtime_error("Data 360 HTTPS response headers exceeded limit");
	if (transfer.cancelled || result == CURLE_ABORTED_BY_CALLBACK) throw std::runtime_error("Data 360 query cancelled");
	if (result == CURLE_PEER_FAILED_VERIFICATION || result == CURLE_SSL_CONNECT_ERROR || result == CURLE_SSL_CERTPROBLEM ||
	    result == CURLE_SSL_CACERT_BADFILE)
		throw std::runtime_error("D360-AUTH-009 TLS_FAILURE");
	if (result != CURLE_OK) throw std::runtime_error("D360-AUTH-008 NETWORK_UNAVAILABLE");
	long status = 0;
	Check(curl_easy_getinfo(easy.get(), CURLINFO_RESPONSE_CODE, &status));
	transfer.response.status = static_cast<int>(status);
	return std::move(transfer.response);
}

} // namespace data360
