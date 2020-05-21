#include <packetparse.hh>

uint16_t PacketParse::checksum(std::vector<uint8_t> byts) {
  const uint16_t *buf = (uint16_t *)&byts[0];
  size_t size = byts.size();
  uint32_t sum = 0;

  // calculate sum
  while (size > 1) {
    sum += *buf++;
    size -= 2;
  }

  // if size is odd
  if (size & 1)
    sum += *(uint8_t *)buf;

  // fold the sum to 16 bits
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

std::vector<uint8_t> PacketParse::packet_to_bytes(const uint8_t *pkt,
                                                  size_t len) {
  // convert a packet struct to bytes
  return std::vector<uint8_t>(pkt, pkt + len);
}

uint16_t PacketParse::tcp_checksum(struct pseudohdr phdr, struct tcphdr thdr) {
  // convert header to bytes
  auto phdr_bytes = packet_to_bytes((uint8_t *)&phdr, sizeof(pseudohdr));

  // convert header to bytes
  auto tcp_bytes = packet_to_bytes((uint8_t *)&thdr, sizeof(tcphdr));

  // merge tcp and pseudo header bytes to calculate checksum
  phdr_bytes.insert(phdr_bytes.end(), tcp_bytes.begin(), tcp_bytes.end());

  return checksum(phdr_bytes);
}

uint16_t PacketParse::ip_checksum(struct ipv4hdr ip) {
  // convert header to bytes
  auto ip_bytes = packet_to_bytes((uint8_t *)&ip, sizeof(ipv4hdr));

  // calculate checksum
  return checksum(ip_bytes);
}
