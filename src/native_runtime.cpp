#include "data360/native_runtime.hpp"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#include "yyjson.hpp"
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include <chrono>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <sstream>
#include <unistd.h>

namespace data360 {
namespace {
using namespace duckdb_yyjson;

struct JsonDocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
using JsonDoc = std::unique_ptr<yyjson_doc, JsonDocDeleter>;

void KillAndReap(pid_t pid) noexcept {
	if (pid <= 0) return;
	kill(pid, SIGKILL);
	while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
	}
}

std::string RunProcess(const std::vector<std::string> &arguments, const std::string &stdin_data,
                       size_t max_output_bytes, uint64_t timeout_ms, const std::vector<std::string> &environment,
                       RuntimeHooks *runtime) {
	if (arguments.empty()) {
		throw std::runtime_error("Data 360 credential helper is invalid");
	}
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	static std::timed_mutex spawn_mutex;
	std::unique_lock<std::timed_mutex> spawn_guard(spawn_mutex, std::defer_lock);
	if (!spawn_guard.try_lock_until(deadline)) {
		throw std::runtime_error("Data 360 process timed out");
	}
	int input_pipe[2] {-1, -1};
	int output_pipe[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, input_pipe) != 0) {
		throw std::runtime_error("Data 360 process pipe creation failed");
	}
	if (pipe(output_pipe) != 0) {
		close(input_pipe[0]); close(input_pipe[1]);
		throw std::runtime_error("Data 360 process pipe creation failed");
	}
	for (const auto fd : {input_pipe[0], input_pipe[1], output_pipe[0], output_pipe[1]}) {
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
	}
	fcntl(input_pipe[0], F_SETFL, fcntl(input_pipe[0], F_GETFL) | O_NONBLOCK);
	fcntl(output_pipe[0], F_SETFL, fcntl(output_pipe[0], F_GETFL) | O_NONBLOCK);
#ifdef __APPLE__
	int no_sigpipe = 1;
	setsockopt(input_pipe[0], SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
	std::vector<char *> argv;
	argv.reserve(arguments.size() + 1);
	for (const auto &argument : arguments) argv.push_back(const_cast<char *>(argument.c_str()));
	argv.push_back(nullptr);
	std::vector<char *> envp;
	envp.reserve(environment.size() + 1);
	for (const auto &entry : environment) envp.push_back(const_cast<char *>(entry.c_str()));
	envp.push_back(nullptr);
	posix_spawn_file_actions_t actions;
	const auto actions_initialized = posix_spawn_file_actions_init(&actions) == 0;
	const auto actions_valid = actions_initialized &&
	                           posix_spawn_file_actions_adddup2(&actions, input_pipe[1], STDIN_FILENO) == 0 &&
	                           posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO) == 0 &&
	                           posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
	                           posix_spawn_file_actions_addclose(&actions, input_pipe[0]) == 0 &&
	                           posix_spawn_file_actions_addclose(&actions, output_pipe[0]) == 0 &&
	                           posix_spawn_file_actions_addclose(&actions, input_pipe[1]) == 0 &&
	                           posix_spawn_file_actions_addclose(&actions, output_pipe[1]) == 0;
	if (!actions_valid) {
		if (actions_initialized) posix_spawn_file_actions_destroy(&actions);
		close(input_pipe[0]); close(input_pipe[1]); close(output_pipe[0]); close(output_pipe[1]);
		throw std::runtime_error("Data 360 process launch failed");
	}
	posix_spawnattr_t attributes;
	sigset_t empty_mask;
	sigset_t default_signals;
	sigemptyset(&empty_mask);
	sigemptyset(&default_signals);
	sigaddset(&default_signals, SIGPIPE);
	const auto attributes_initialized = posix_spawnattr_init(&attributes) == 0;
	const auto attributes_valid = attributes_initialized &&
	                              posix_spawnattr_setsigmask(&attributes, &empty_mask) == 0 &&
	                              posix_spawnattr_setsigdefault(&attributes, &default_signals) == 0 &&
	                              posix_spawnattr_setflags(
	                                  &attributes, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF) == 0;
	if (!attributes_valid) {
		if (attributes_initialized) posix_spawnattr_destroy(&attributes);
		posix_spawn_file_actions_destroy(&actions);
		close(input_pipe[0]); close(input_pipe[1]); close(output_pipe[0]); close(output_pipe[1]);
		throw std::runtime_error("Data 360 process launch failed");
	}
	pid_t pid = -1;
	const auto spawn_result = posix_spawn(&pid, arguments[0].c_str(), &actions, &attributes, argv.data(), envp.data());
	posix_spawnattr_destroy(&attributes);
	posix_spawn_file_actions_destroy(&actions);
	close(output_pipe[1]);
	close(input_pipe[1]);
	spawn_guard.unlock();
	if (spawn_result != 0) {
		close(input_pipe[0]); close(output_pipe[0]);
		throw std::runtime_error("Data 360 process launch failed");
	}
	size_t written = 0;
	std::string output;
	char buffer[8192];
	bool input_open = true;
	bool output_open = true;
	auto terminate = [&]() {
		if (input_open) close(input_pipe[0]);
		if (output_open) close(output_pipe[0]);
		KillAndReap(pid);
	};
	while (input_open || output_open) {
		if (runtime && runtime->IsCancelled()) {
			terminate();
			throw std::runtime_error("Data 360 query cancelled");
		}
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
		if (remaining.count() <= 0) {
			terminate();
			throw std::runtime_error("Data 360 process timed out");
		}
		if (input_open && written == stdin_data.size()) {
			shutdown(input_pipe[0], SHUT_WR);
			close(input_pipe[0]);
			input_open = false;
		}
		pollfd descriptors[2];
		nfds_t descriptor_count = 0;
		if (input_open) descriptors[descriptor_count++] = {input_pipe[0], POLLOUT, 0};
		if (output_open) descriptors[descriptor_count++] = {output_pipe[0], static_cast<short>(POLLIN | POLLHUP), 0};
		const auto poll_timeout = static_cast<int>(std::min<int64_t>(remaining.count(), 50));
		const auto ready = poll(descriptors, descriptor_count, poll_timeout);
		if (ready < 0 && errno == EINTR) continue;
		if (ready < 0) {
			terminate();
			throw std::runtime_error("Data 360 process failed");
		}
		nfds_t current = 0;
		if (input_open) {
			auto &descriptor = descriptors[current++];
			if (descriptor.revents & POLLOUT) {
#ifdef __APPLE__
				const auto count = send(input_pipe[0], stdin_data.data() + written, stdin_data.size() - written, 0);
#else
				const auto count = send(input_pipe[0], stdin_data.data() + written, stdin_data.size() - written, MSG_NOSIGNAL);
#endif
				if (count > 0) written += static_cast<size_t>(count);
				else if (count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
					close(input_pipe[0]); input_open = false;
				}
			}
			if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				close(input_pipe[0]); input_open = false;
			}
		}
		if (output_open) {
			auto &descriptor = descriptors[current];
			while (descriptor.revents & (POLLIN | POLLHUP)) {
				const auto count = read(output_pipe[0], buffer, sizeof(buffer));
				if (count > 0) {
					if (static_cast<size_t>(count) > max_output_bytes - std::min(output.size(), max_output_bytes)) {
						terminate();
						throw std::runtime_error("Data 360 process response exceeded limit");
					}
					output.append(buffer, static_cast<size_t>(count));
					continue;
				}
				if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) break;
				close(output_pipe[0]); output_open = false; break;
			}
			if (descriptor.revents & (POLLERR | POLLNVAL)) {
				close(output_pipe[0]); output_open = false;
			}
		}
	}
	int status = 0;
	pid_t wait_result = 0;
	while (true) {
		wait_result = waitpid(pid, &status, WNOHANG);
		if (wait_result < 0 && errno == EINTR) continue;
		if (wait_result != 0) break;
		if (runtime && runtime->IsCancelled()) {
			KillAndReap(pid);
			throw std::runtime_error("Data 360 query cancelled");
		}
		if (std::chrono::steady_clock::now() >= deadline) {
			KillAndReap(pid);
			throw std::runtime_error("Data 360 process timed out");
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	if (wait_result < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		throw std::runtime_error("Data 360 process failed");
	}
	return output;
}

JsonDoc Parse(const std::string &body) {
	JsonDoc doc(yyjson_read(body.data(), body.size(), YYJSON_READ_NUMBER_AS_RAW));
	if (!doc || !yyjson_is_obj(yyjson_doc_get_root(doc.get()))) {
		throw std::runtime_error("Data 360 response was invalid JSON");
	}
	return doc;
}

bool TryUnsigned(yyjson_val *value, uint64_t &result) {
	if (yyjson_is_uint(value)) {
		result = yyjson_get_uint(value);
		return true;
	}
	if (!yyjson_is_raw(value)) {
		return false;
	}
	const std::string raw(yyjson_get_raw(value), yyjson_get_len(value));
	if (raw.empty() || raw.find_first_not_of("0123456789") != std::string::npos) {
		return false;
	}
	try {
		size_t consumed = 0;
		result = std::stoull(raw, &consumed);
		return consumed == raw.size();
	} catch (...) {
		return false;
	}
}

bool OptionalUnsigned(yyjson_val *object, const char *key, uint64_t &result) {
	auto value = yyjson_obj_get(object, key);
	if (!value) return false;
	if (!TryUnsigned(value, result)) {
		throw std::runtime_error("Data 360 response contained an invalid count");
	}
	return true;
}

std::string RequiredString(yyjson_val *object, const char *key) {
	auto value = yyjson_obj_get(object, key);
	if (!yyjson_is_str(value) || yyjson_get_len(value) == 0) {
		throw std::runtime_error("Data 360 response was missing a required field");
	}
	return std::string(yyjson_get_str(value), yyjson_get_len(value));
}

std::string CurlConfigEscape(const std::string &value) {
	std::string result;
	for (const char character : value) {
		switch (character) {
		case '\\': result += "\\\\"; break;
		case '"': result += "\\\""; break;
		case '\n': result += "\\n"; break;
		case '\r': result += "\\r"; break;
		default: result += character; break;
		}
	}
	return result;
}

std::string JsonScalar(yyjson_val *value) {
	if (yyjson_is_str(value)) return std::string(yyjson_get_str(value), yyjson_get_len(value));
	if (yyjson_is_bool(value)) return yyjson_get_bool(value) ? "true" : "false";
	if (yyjson_is_raw(value)) return std::string(yyjson_get_raw(value), yyjson_get_len(value));
	if (yyjson_is_num(value)) {
		if (yyjson_is_uint(value)) return std::to_string(yyjson_get_uint(value));
		if (yyjson_is_sint(value)) return std::to_string(yyjson_get_sint(value));
		char number[32];
		const auto length = std::snprintf(number, sizeof(number), "%.17g", yyjson_get_real(value));
		if (length <= 0 || static_cast<size_t>(length) >= sizeof(number)) {
			throw std::runtime_error("Data 360 numeric value was invalid");
		}
		return std::string(number, static_cast<size_t>(length));
	}
	throw std::runtime_error("Data 360 result contained a non-scalar value");
}

std::vector<std::string> MinimalEnvironment(bool include_home) {
	std::vector<std::string> environment {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC",
	                                      "PYTHONNOUSERSITE=1", "PYTHONSAFEPATH=1", "PYTHONPATH="};
	if (include_home) {
		const auto home = std::getenv("HOME");
		if (!home || !*home || std::strchr(home, '\n') || std::strchr(home, '\r')) {
			throw std::runtime_error("Data 360 credential helper environment is invalid");
		}
		environment.emplace_back(std::string("HOME=") + home);
	}
	return environment;
}

void ValidateRootOwnedTool(const char *path) {
	struct stat tool_stat {};
	if (lstat(path, &tool_stat) != 0 || !S_ISREG(tool_stat.st_mode) || tool_stat.st_uid != 0 ||
	    (tool_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0 || (tool_stat.st_mode & S_IXUSR) == 0) {
		throw std::runtime_error("Data 360 trusted process tool is unavailable");
	}
}

} // namespace

QueryCredentials ResolveProcessCapability(const std::string &broker_path, const std::string &login_url,
                                          RuntimeHooks *runtime) {
	if (broker_path.empty() || broker_path.front() != '/' || login_url.empty()) {
		throw std::invalid_argument("Data 360 credential helper configuration is invalid");
	}
	const auto broker_fd = open(broker_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	struct stat broker_stat {};
	if (broker_fd < 0 || fstat(broker_fd, &broker_stat) != 0 || !S_ISREG(broker_stat.st_mode) ||
	    broker_stat.st_uid != geteuid() || (broker_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
	    (broker_stat.st_mode & S_IXUSR) == 0 || broker_stat.st_size <= 0 || broker_stat.st_size > 1024 * 1024) {
		if (broker_fd >= 0) close(broker_fd);
		throw std::invalid_argument("Data 360 credential helper is not a trusted executable");
	}
	ValidateRootOwnedTool("/usr/bin/python3");
	std::string broker_source(static_cast<size_t>(broker_stat.st_size), '\0');
	size_t broker_read = 0;
	while (broker_read < broker_source.size()) {
		const auto count = pread(broker_fd, broker_source.data() + broker_read, broker_source.size() - broker_read,
		                         static_cast<off_t>(broker_read));
		if (count < 0 && errno == EINTR) continue;
		if (count <= 0) {
			close(broker_fd);
			throw std::runtime_error("Data 360 credential helper could not be read safely");
		}
		broker_read += static_cast<size_t>(count);
	}
	close(broker_fd);
	std::string body;
	body = RunProcess({"/usr/bin/python3", "-I", "-E", "-s", "-", "--login-url", login_url, "--emit-capability"},
	                  broker_source,
	                  64ULL * 1024ULL, 30000, MinimalEnvironment(true), runtime);
	if (body.empty()) {
		throw std::runtime_error("Data 360 credential helper returned an empty response");
	}
	auto doc = Parse(body);
	auto root = yyjson_doc_get_root(doc.get());
	const auto token_type = RequiredString(root, "token_type");
	if (token_type != "Bearer") throw std::runtime_error("Data 360 credential helper returned an unsupported token type");
	return {RequiredString(root, "instance_url"), RequiredString(root, "access_token")};
}

HttpResponse CurlProcessTransport::Send(const HttpRequest &request) {
	const auto request_started = std::chrono::steady_clock::now();
	if (request.follow_redirects || request.timeout_ms == 0 || request.max_response_bytes == 0 ||
	    request.body.size() > 1024ULL * 1024ULL ||
	    (request.method != "GET" && request.method != "POST" && request.method != "DELETE")) {
		throw std::invalid_argument("Data 360 HTTPS request configuration is invalid");
	}
	ValidateRootOwnedTool("/usr/bin/curl");
	std::string config = "silent\nshow-error\nfail-with-body\ninclude\nmax-redirs = \"0\"\n"
	                     "header = \"Expect:\"\nmax-time = \"" +
	                     std::to_string(static_cast<double>(request.timeout_ms) / 1000.0) + "\"\nrequest = \"" + request.method +
	                     "\"\nurl = \"" + CurlConfigEscape(request.url) + "\"\n";
	for (const auto &header : request.headers) {
		config += "header = \"" + CurlConfigEscape(header.first + ": " + header.second) + "\"\n";
	}
	if (!request.body.empty()) config += "data = \"" + CurlConfigEscape(request.body) + "\"\n";
	try {
		const auto header_allowance = 64ULL * 1024ULL;
		const auto raw_limit = request.max_response_bytes > SIZE_MAX - header_allowance
		                           ? SIZE_MAX
		                           : static_cast<size_t>(request.max_response_bytes + header_allowance);
		const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		                            std::chrono::steady_clock::now() - request_started).count();
		if (request.cleanup_request && elapsed_ms >= static_cast<int64_t>(request.timeout_ms)) {
			throw std::runtime_error("cleanup deadline exceeded");
		}
		const auto process_timeout = request.cleanup_request
		                                 ? request.timeout_ms - static_cast<uint64_t>(elapsed_ms)
		                                 : request.timeout_ms + 1000;
		auto raw = RunProcess({"/usr/bin/curl", "-q", "--config", "-"}, config, raw_limit, process_timeout,
		                      MinimalEnvironment(false), request.cleanup_request ? nullptr : runtime);
		auto separator = raw.find("\r\n\r\n");
		size_t separator_size = 4;
		if (separator == std::string::npos) {
			separator = raw.find("\n\n");
			separator_size = 2;
		}
		if (separator == std::string::npos) throw std::runtime_error("missing HTTP headers");
		std::istringstream header_stream(raw.substr(0, separator));
		std::string line;
		if (!std::getline(header_stream, line)) throw std::runtime_error("missing HTTP status");
		int status = 0;
		if (std::sscanf(line.c_str(), "HTTP/%*s %d", &status) != 1) throw std::runtime_error("invalid HTTP status");
		HttpResponse response {status, raw.substr(separator + separator_size), {}};
		if (response.body.size() > request.max_response_bytes) {
			throw std::runtime_error("response exceeded limit");
		}
		while (std::getline(header_stream, line)) {
			if (!line.empty() && line.back() == '\r') line.pop_back();
			const auto colon = line.find(':');
			if (colon == std::string::npos) continue;
			auto key = line.substr(0, colon);
			std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			auto value = line.substr(colon + 1);
			while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
			response.headers[key] = value;
		}
		return response;
	} catch (...) {
		throw std::runtime_error("Data 360 HTTPS request failed");
	}
}

QueryResponse JsonQueryResponseCodec::Decode(const HttpResponse &response) {
	if (response.status < 200 || response.status >= 300) throw std::runtime_error("Data 360 Query API request failed");
	for (const auto *status_header : {"x-hyperdb-status", "status"}) {
		if (const auto header = response.headers.find(status_header); header != response.headers.end()) {
			try {
				auto status_doc = Parse(header->second);
				auto query_id = yyjson_obj_get(yyjson_doc_get_root(status_doc.get()), "queryId");
				if (yyjson_is_str(query_id) && yyjson_get_len(query_id) > 0) {
					QueryResponse submitted;
					submitted.state = QueryState::RUNNING;
					submitted.query_id = std::string(yyjson_get_str(query_id), yyjson_get_len(query_id));
					return submitted;
				}
			} catch (...) {
				// Continue to the bounded response body shapes below.
			}
		}
	}
	if (const auto location = response.headers.find("location"); location != response.headers.end()) {
		const std::string marker = "/api/v3/query/";
		const auto marker_pos = location->second.find(marker);
		if (marker_pos != std::string::npos) {
			const auto id_start = marker_pos + marker.size();
			const auto id_end = location->second.find_first_of("/?#", id_start);
			const auto query_id = location->second.substr(id_start, id_end - id_start);
			if (!query_id.empty()) {
				QueryResponse submitted;
				submitted.state = QueryState::RUNNING;
				submitted.query_id = query_id;
				return submitted;
			}
		}
	}
	auto doc = Parse(response.body);
	auto root = yyjson_doc_get_root(doc.get());
	QueryResponse result;
	if (auto query_id = yyjson_obj_get(root, "queryId"); yyjson_is_str(query_id)) {
		result.query_id = std::string(yyjson_get_str(query_id), yyjson_get_len(query_id));
	}
	if (auto completion = yyjson_obj_get(root, "completionStatus"); yyjson_is_str(completion)) {
		const std::string state(yyjson_get_str(completion), yyjson_get_len(completion));
		result.state = (state == "FINISHED" || state == "RESULTS_PRODUCED") ? QueryState::COMPLETE
		                                                                  : (state == "RUNNING" ? QueryState::RUNNING : QueryState::FAILED);
		result.has_chunk_count = OptionalUnsigned(root, "chunkCount", result.chunk_count);
		result.has_row_count = OptionalUnsigned(root, "rowCount", result.row_count);
		return result;
	}
	if (!result.query_id.empty()) {
		result.state = QueryState::RUNNING;
		return result;
	}
	// Chunk responses can repeat metadata alongside the row payload. Decode both
	// so the cursor can reject execution-time schema drift before yielding rows.
	auto metadata_object = yyjson_obj_get(root, "metadata");
	if (!yyjson_is_obj(metadata_object)) metadata_object = root;
	if (auto columns = yyjson_obj_get(metadata_object, "columns"); yyjson_is_arr(columns)) {
		size_t index, maximum;
		yyjson_val *column;
		yyjson_arr_foreach(columns, index, maximum, column) {
			if (!yyjson_is_obj(column)) throw std::runtime_error("Data 360 metadata column was invalid");
			auto name = yyjson_obj_get(column, "name");
			if (!yyjson_is_str(name)) name = yyjson_obj_get(column, "columnName");
			auto type = yyjson_obj_get(column, "type");
			if (!yyjson_is_str(type)) type = yyjson_obj_get(column, "typeName");
			auto nullable = yyjson_obj_get(column, "nullable");
			if (!yyjson_is_str(name) || !yyjson_is_str(type) || !yyjson_is_bool(nullable))
				throw std::runtime_error("Data 360 metadata column was incomplete");
			result.metadata.push_back({std::string(yyjson_get_str(name), yyjson_get_len(name)),
			                           std::string(yyjson_get_str(type), yyjson_get_len(type)), yyjson_get_bool(nullable)});
		}
	}
	if (auto data = yyjson_obj_get(root, "data"); yyjson_is_arr(data)) {
		if (auto next = yyjson_obj_get(root, "next"); yyjson_is_str(next)) {
			result.chunk.next_url = std::string(yyjson_get_str(next), yyjson_get_len(next));
		}
		size_t row_index, row_maximum;
		yyjson_val *row;
		yyjson_arr_foreach(data, row_index, row_maximum, row) {
			if (!yyjson_is_arr(row)) throw std::runtime_error("Data 360 result row was invalid");
			std::vector<Cell> cells;
			size_t cell_index, cell_maximum;
			yyjson_val *cell;
			yyjson_arr_foreach(row, cell_index, cell_maximum, cell) {
				cells.push_back(yyjson_is_null(cell) ? Cell() : Cell(JsonScalar(cell)));
			}
			result.chunk.rows.push_back(std::move(cells));
		}
		result.state = QueryState::COMPLETE;
		result.has_returned_rows = OptionalUnsigned(root, "returnedRows", result.returned_rows);
		return result;
	}
	if (!result.metadata.empty()) {
		result.state = QueryState::COMPLETE;
		return result;
	}
	throw std::runtime_error("Data 360 response shape was not recognized");
}

SteadyRuntime::SteadyRuntime(const std::atomic<bool> *cancelled_p) : cancelled(cancelled_p) {
}
bool SteadyRuntime::IsCancelled() {
	return cancelled && cancelled->load();
}
uint64_t SteadyRuntime::NowMs() {
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
	                                 std::chrono::steady_clock::now().time_since_epoch()).count());
}
void SteadyRuntime::SleepMs(uint64_t milliseconds) {
	std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

} // namespace data360
