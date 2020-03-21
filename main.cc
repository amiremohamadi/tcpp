#include <iostream>
#include <tuntap.hh>

int main() {
  try {
    Iface iface("tun0", Mode::TUN);
  } catch (const char *e) {
    std::cout << e << std::endl;
  }
  return 0;
}
