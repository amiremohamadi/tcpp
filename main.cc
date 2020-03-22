#include <iostream>
#include <tuntap.hh>

int main() {
  Iface iface("tun0", Iface::Mode::TUN);
  uint8_t bytes[1500];

  while (1) {
    size_t nbytes = iface.receive(bytes, 1500);
    std::cout << nbytes << std::endl;
  }

  return 0;
}
