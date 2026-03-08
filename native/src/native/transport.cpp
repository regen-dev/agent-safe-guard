#include "sg/transport.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace sg {
namespace {

constexpr int kSystemdFirstFd = 3;
constexpr std::size_t kMaxPacketBytes = 4 * 1024 * 1024 + 64;

void SetCloExec(int fd) {
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags >= 0) {
    (void)::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
  }
}

bool TakeSystemdSocket(int* fd, std::string* error) {
  const char* raw_fds = std::getenv("LISTEN_FDS");
  const char* raw_pid = std::getenv("LISTEN_PID");
  if (raw_fds == nullptr || raw_pid == nullptr) {
    return false;
  }

  char* end = nullptr;
  const long listen_pid = std::strtol(raw_pid, &end, 10);
  if (end == raw_pid || *end != '\0' || listen_pid != static_cast<long>(::getpid())) {
    return false;
  }

  end = nullptr;
  const long listen_fds = std::strtol(raw_fds, &end, 10);
  if (end == raw_fds || *end != '\0' || listen_fds < 1) {
    return false;
  }

  int sock_type = 0;
  socklen_t sock_type_len = sizeof(sock_type);
  if (::getsockopt(kSystemdFirstFd, SOL_SOCKET, SO_TYPE, &sock_type, &sock_type_len) !=
      0) {
    if (error != nullptr) {
      *error = "systemd fd is not a socket";
    }
    return false;
  }

  if (sock_type != SOCK_SEQPACKET && sock_type != SOCK_STREAM) {
    if (error != nullptr) {
      *error = "unsupported systemd socket type";
    }
    return false;
  }

  *fd = kSystemdFirstFd;
  return true;
}

bool FillSockAddr(const std::string& path, sockaddr_un* addr, socklen_t* len,
                  std::string* error) {
  if (path.empty()) {
    if (error != nullptr) {
      *error = "socket path is empty";
    }
    return false;
  }
  if (path.size() >= sizeof(addr->sun_path)) {
    if (error != nullptr) {
      *error = "socket path exceeds unix socket limit";
    }
    return false;
  }

  std::memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  std::snprintf(addr->sun_path, sizeof(addr->sun_path), "%s", path.c_str());
  *len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);
  return true;
}

}  // namespace

bool OpenServer(const ServerOptions& options, ServerHandle* out, std::string* error) {
  if (out == nullptr) {
    if (error != nullptr) {
      *error = "server handle output is null";
    }
    return false;
  }

  out->listen_fd = -1;
  out->bound_socket_path.clear();
  out->using_systemd_socket = false;

  if (options.prefer_systemd_socket) {
    int systemd_fd = -1;
    if (TakeSystemdSocket(&systemd_fd, error)) {
      out->listen_fd = systemd_fd;
      out->using_systemd_socket = true;
      return true;
    }
  }

  if (options.socket_path.empty()) {
    if (error != nullptr) {
      *error = "socket_path is required without systemd socket activation";
    }
    return false;
  }

  const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd < 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    return false;
  }
  SetCloExec(fd);

  std::error_code ec;
  std::filesystem::create_directories(std::filesystem::path(options.socket_path).parent_path(),
                                      ec);

  ::unlink(options.socket_path.c_str());

  sockaddr_un addr;
  socklen_t addr_len = 0;
  if (!FillSockAddr(options.socket_path, &addr, &addr_len, error)) {
    ::close(fd);
    return false;
  }

  if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    ::close(fd);
    return false;
  }

  if (::chmod(options.socket_path.c_str(), 0600) != 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    ::close(fd);
    ::unlink(options.socket_path.c_str());
    return false;
  }

  if (::listen(fd, static_cast<int>(options.backlog)) != 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    ::close(fd);
    ::unlink(options.socket_path.c_str());
    return false;
  }

  out->listen_fd = fd;
  out->bound_socket_path = options.socket_path;
  out->using_systemd_socket = false;
  return true;
}

int AcceptClient(int listen_fd, std::string* error) {
  const int fd = ::accept(listen_fd, nullptr, nullptr);
  if (fd >= 0) {
    SetCloExec(fd);
  }
  if (fd < 0 && error != nullptr) {
    *error = std::strerror(errno);
  }
  return fd;
}

int ConnectClient(const std::string& socket_path, std::string* error) {
  const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd < 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    return -1;
  }
  SetCloExec(fd);

  sockaddr_un addr;
  socklen_t addr_len = 0;
  if (!FillSockAddr(socket_path, &addr, &addr_len, error)) {
    ::close(fd);
    return -1;
  }

  if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    ::close(fd);
    return -1;
  }

  return fd;
}

bool SendPacket(int fd, std::span<const std::uint8_t> packet, std::string* error) {
  if (packet.empty()) {
    if (error != nullptr) {
      *error = "empty packet";
    }
    return false;
  }
  if (packet.size() > kMaxPacketBytes) {
    if (error != nullptr) {
      *error = "packet exceeds max size";
    }
    return false;
  }
  ssize_t rc = 0;
  do {
    rc = ::send(fd, packet.data(), packet.size(), MSG_NOSIGNAL);
  } while (rc < 0 && errno == EINTR);

  if (rc < 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    return false;
  }
  if (static_cast<std::size_t>(rc) != packet.size()) {
    if (error != nullptr) {
      *error = "short send on seqpacket transport";
    }
    return false;
  }
  return true;
}

bool RecvPacket(int fd, std::vector<std::uint8_t>* packet, std::string* error) {
  if (packet == nullptr) {
    if (error != nullptr) {
      *error = "packet output is null";
    }
    return false;
  }

  std::vector<std::uint8_t> buffer(kMaxPacketBytes);

  iovec iov{};
  iov.iov_base = buffer.data();
  iov.iov_len = buffer.size();

  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t rc = 0;
  do {
    rc = ::recvmsg(fd, &msg, 0);
  } while (rc < 0 && errno == EINTR);

  if (rc < 0) {
    if (error != nullptr) {
      *error = std::strerror(errno);
    }
    return false;
  }

  if (rc == 0) {
    if (error != nullptr) {
      *error = "peer closed connection";
    }
    return false;
  }

  if ((msg.msg_flags & MSG_TRUNC) != 0) {
    if (error != nullptr) {
      *error = "received truncated packet";
    }
    return false;
  }

  buffer.resize(static_cast<std::size_t>(rc));
  *packet = std::move(buffer);
  return true;
}

void CloseFd(int fd) {
  if (fd >= 0) {
    ::close(fd);
  }
}

void CleanupServerSocket(const ServerHandle& handle) {
  if (handle.listen_fd >= 0 && !handle.using_systemd_socket) {
    ::close(handle.listen_fd);
  }
  if (!handle.using_systemd_socket && !handle.bound_socket_path.empty()) {
    ::unlink(handle.bound_socket_path.c_str());
  }
}

}  // namespace sg
