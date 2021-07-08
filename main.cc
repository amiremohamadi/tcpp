#include <arpa/inet.h>
#include <fmt/format.h>
#include <iostream>
#include <map>
#include <packetparse.hh>
#include <tcp.hh>
#include <tuntap.hh>
#include <vector>

#define MTU 1504 // maximum transmission unit

int main() {
  Iface iface("tun0", Iface::Mode::TUN);
  try {
    iface.device_alloc();
  } catch (const char *c) {
    fmt::print(c);
  }

  uint8_t bytes[MTU];

  while (1) {
    size_t nbytes = iface.receive(bytes, MTU);
		std::cout << "nbytes: " << nbytes << std::endl;
    std::vector<uint8_t> vbytes(bytes, bytes + nbytes);

    uint16_t eth_flags = bytes[0] << 8 | bytes[1]; // big-endian
    uint16_t eth_proto = bytes[2] << 8 | bytes[3]; // big-endian

    if (eth_proto != 0x800)
      // ignore no ipv4 packets
      // https://en.wikipedia.org/wiki/EtherType
      continue;

    // parse ether header
    PacketParse::ipv4hdr *ip_hdr = (PacketParse::ipv4hdr *)(bytes + 4);

    if (ip_hdr->proto != 0x06)
      // ignore non-TCP packets
      // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
      continue;

    // refer tp ipv4 rfc, ihl is the ip header length in 32 bit words
    PacketParse::tcphdr *tcp_hdr =
        (PacketParse::tcphdr *)(bytes + 4 + ip_hdr->ihl * 4);

    // each connection is identified by a quad
    Quad q = {.saddr = ip_hdr->saddr,
              .daddr = ip_hdr->daddr,
              .sport = tcp_hdr->sport,
              .dport = tcp_hdr->dport};

    // if we had a connection with this quad before, return and continue
    // else we trying to make a new connection and put it on connections
    if (Tcp::is_exists(q)) {
			auto conn = Tcp::get_conn(q);
			Tcp::on_packet(ip_hdr, tcp_hdr, conn);
    } else {
      // connection is new
      Connection conn;
      std::vector<uint8_t> p = Tcp::accept(ip_hdr, tcp_hdr, conn);
      if (p.empty())
        continue;

      p.insert(p.begin(), bytes[3]);
      p.insert(p.begin(), bytes[2]);
      p.insert(p.begin(), bytes[1]);
      p.insert(p.begin(), bytes[0]);
      fmt::print("[{0:02d}]\n", fmt::join(p, ", "));
      /* fmt::print("[{0:02x}]\n", fmt::join(vbytes, ", ")); */
      /* std::cout << std::hex << ntohl(tcp_hdr->seq) << std::endl; */
      iface.send(&p[0], p.size());

      /* std::cout << std::dec << ntohs(tcp_hdr->sport) << std::endl; */
      /* fmt::print("{}\n", fmt::join(vbytes, " ")); */
      Tcp::insert(q, conn);
    }
  }

  return 0;
}
