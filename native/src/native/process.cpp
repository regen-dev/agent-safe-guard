#include "sg/process.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace sg {
namespace {

std::vector<char*> BuildArgv(const std::vector<std::string>& argv) {
  std::vector<char*> out;
  out.reserve(argv.size() + 1);
  for (const auto& arg : argv) {
    out.push_back(const_cast<char*>(arg.c_str()));
  }
  out.push_back(nullptr);
  return out;
}

std::string ReadFdToString(int fd) {
  std::string out;
  char buffer[4096];
  while (true) {
    const ssize_t n = ::read(fd, buffer, sizeof(buffer));
    if (n == 0) {
      break;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    out.append(buffer, static_cast<std::size_t>(n));
  }
  return out;
}

void WriteAll(int fd, std::string_view data) {
  const char* ptr = data.data();
  std::size_t remaining = data.size();
  while (remaining > 0) {
    const ssize_t n = ::write(fd, ptr, remaining);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    ptr += n;
    remaining -= static_cast<std::size_t>(n);
  }
}

}  // namespace

ProcessResult RunProcess(const std::vector<std::string>& argv,
                         const std::optional<std::string>& stdin_text) {
  ProcessResult result;
  if (argv.empty()) {
    result.stderr_text = "empty argv";
    return result;
  }

  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  int stdin_pipe[2] = {-1, -1};
  if (::pipe(stdout_pipe) != 0 || ::pipe(stderr_pipe) != 0 ||
      (stdin_text.has_value() && ::pipe(stdin_pipe) != 0)) {
    result.stderr_text = std::strerror(errno);
    return result;
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    result.stderr_text = std::strerror(errno);
    return result;
  }

  if (pid == 0) {
    ::dup2(stdout_pipe[1], STDOUT_FILENO);
    ::dup2(stderr_pipe[1], STDERR_FILENO);
    if (stdin_text.has_value()) {
      ::dup2(stdin_pipe[0], STDIN_FILENO);
    }

    ::close(stdout_pipe[0]);
    ::close(stdout_pipe[1]);
    ::close(stderr_pipe[0]);
    ::close(stderr_pipe[1]);
    if (stdin_text.has_value()) {
      ::close(stdin_pipe[0]);
      ::close(stdin_pipe[1]);
    }

    auto child_argv = BuildArgv(argv);
    ::execvp(child_argv[0], child_argv.data());
    _exit(127);
  }

  ::close(stdout_pipe[1]);
  ::close(stderr_pipe[1]);
  if (stdin_text.has_value()) {
    ::close(stdin_pipe[0]);
    WriteAll(stdin_pipe[1], *stdin_text);
    ::close(stdin_pipe[1]);
  }

  result.stdout_text = ReadFdToString(stdout_pipe[0]);
  result.stderr_text = ReadFdToString(stderr_pipe[0]);
  ::close(stdout_pipe[0]);
  ::close(stderr_pipe[0]);

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      break;
    }
  }

  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.exit_code = 128 + WTERMSIG(status);
  }
  return result;
}

int ExecProcess(const std::vector<std::string>& argv) {
  if (argv.empty()) {
    return 1;
  }
  auto exec_argv = BuildArgv(argv);
  ::execvp(exec_argv[0], exec_argv.data());
  return 127;
}

int SpawnAndWait(const std::vector<std::string>& argv) {
  if (argv.empty()) {
    return 1;
  }
  const pid_t pid = ::fork();
  if (pid < 0) {
    return 127;
  }
  if (pid == 0) {
    auto exec_argv = BuildArgv(argv);
    ::execvp(exec_argv[0], exec_argv.data());
    _exit(127);
  }

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return 127;
    }
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 127;
}

}  // namespace sg
