#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace sg {

struct ServerOptions {
  std::string socket_path;
  bool prefer_systemd_socket = true;
  std::uint32_t backlog = 128;
};

struct ServerHandle {
  int listen_fd = -1;
  std::string bound_socket_path;
  bool using_systemd_socket = false;
};

bool OpenServer(const ServerOptions& options, ServerHandle* out, std::string* error);
int AcceptClient(int listen_fd, std::string* error);
int ConnectClient(const std::string& socket_path, std::string* error);

bool SendPacket(int fd, std::span<const std::uint8_t> packet, std::string* error);
bool RecvPacket(int fd, std::vector<std::uint8_t>* packet, std::string* error);

void CloseFd(int fd);
void CleanupServerSocket(const ServerHandle& handle);

}  // namespace sg
