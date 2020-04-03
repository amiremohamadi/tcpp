#include <arpa/inet.h>
#include <iostream>
#include <packetparse.hh>
#include <tuntap.hh>

int main() {
  Iface iface("tun0", Iface::Mode::TUN);
  uint8_t bytes[1500];

  while (1) {
    size_t nbytes = iface.receive(bytes, 1500);
    uint16_t eth_flags = bytes[0] << 8 | bytes[1]; // big-endian
    uint16_t eth_proto = bytes[2] << 8 | bytes[3]; // big-endian

    /*     for (int i = 0; i < nbytes; i++) { */
    /*       std::cout << (int)bytes[i] << " "; */
    /*     } */
    /*     std::cout << std::endl << std::endl; */

    if (eth_proto != 0x800) {
      // ignore no ipv4 packets
      continue;
    }

    // parse ether header
    PacketParse::ipv4hdr *hdr = (PacketParse::ipv4hdr *)(bytes + 4);

    std::cout << std::hex << htonl(hdr->daddr) << std::endl;
  }

  return 0;
}
