#include "sg/systemd_notify.hpp"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace sg {
namespace {

void Notify(std::string payload) {
  const char* raw_addr = std::getenv("NOTIFY_SOCKET");
  if (raw_addr == nullptr || *raw_addr == '\0') {
    return;
  }

  std::string addr_path(raw_addr);
  if (addr_path.size() >= sizeof(sockaddr_un::sun_path)) {
    return;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;

  bool abstract = false;
  if (!addr_path.empty() && addr_path[0] == '@') {
    abstract = true;
    addr.sun_path[0] = '\0';
    std::memcpy(addr.sun_path + 1, addr_path.data() + 1, addr_path.size() - 1);
  } else {
    std::memcpy(addr.sun_path, addr_path.data(), addr_path.size());
    addr.sun_path[addr_path.size()] = '\0';
  }

  const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return;
  }

  const socklen_t addr_len = abstract
                                 ? static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) +
                                                          addr_path.size())
                                 : static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) +
                                                          addr_path.size() + 1);

  (void)::sendto(fd, payload.data(), payload.size(), MSG_NOSIGNAL,
                 reinterpret_cast<const sockaddr*>(&addr), addr_len);
  ::close(fd);
}

}  // namespace

void NotifySystemdReady(const std::string& status) {
  std::string payload = "READY=1\nSTATUS=" + status;
  Notify(std::move(payload));
}

void NotifySystemdStopping(const std::string& status) {
  std::string payload = "STOPPING=1\nSTATUS=" + status;
  Notify(std::move(payload));
}

}  // namespace sg
