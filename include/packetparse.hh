// a simple packet parser library.

#ifndef PACKETPARSE_HH
#define PACKETPARSE_HH

#include <cstdint>
#include <vector>

using std::size_t;

// the minimum data offset size (size of the tcp header itself)
#define TCP_MINIMUM_DATA_OFFSET 5

class PacketParse {
  // TODO: define functions for parsing packets
  // parse network packets
public:
  struct ipv4hdr;
  struct tcphdr;
  struct pseudohdr;

  static std::vector<uint8_t> packet_to_bytes(const uint8_t *, size_t);
  static uint16_t tcp_checksum(struct pseudohdr, struct tcphdr);
  static uint16_t ip_checksum(struct ipv4hdr);

private:
  static uint16_t checksum(std::vector<uint8_t> bytes);
};

struct PacketParse::ipv4hdr {
  // rfc 791: internet protocol
  /* 0                   1                   2                   3     */
  /* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1   */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |Version|  IHL  |Type of Service|          Total Length         | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |         Identification        |Flags|      Fragment Offset    | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |  Time to Live |    Protocol   |         Header Checksum       | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |                       Source Address                          | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |                    Destination Address                        | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |                    Options                    |    Padding    | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  // the order is changed for little-endian hosts
  // TODO: support big-endian hosts
  uint8_t ihl : 4;
  uint8_t version : 4;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t frag_offset;
  uint8_t ttl;
  uint8_t proto;
  uint16_t csum;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__((packed));

struct PacketParse::tcphdr {
  // rfc 793: transmition control protocol
  /* 0                   1                   2                   3     */
  /* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1   */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |          Source Port          |       Destination Port        | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |                        Sequence Number                        | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |                    Acknowledgment Number                      | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |  Data |           |U|A|P|R|S|F|                               | */
  /* | Offset| Reserved  |R|C|S|S|Y|I|            Window             | */
  /* |       |           |G|K|H|T|N|N|                               | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |           Checksum            |         Urgent Pointer        | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |                    Options                    |    Padding    | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /* |                             data                              | */
  /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack_seq;
  /* #if __BYTE_ORDER__ == __LITTLE_ENDIAN */
  uint8_t rsvd : 4;
  uint8_t dataoff : 4;
  /* #else */
  /* uint8_t dataoff : 4; */
  /* uint8_t rsvd : 6; */
  /* #endif */
  uint8_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1,
      cwr : 1;
  uint16_t win;
  uint16_t csum;
  uint16_t urp;
} __attribute__((packed));

struct PacketParse::pseudohdr {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t reserved;
  uint8_t proto;
  uint16_t len;
} __attribute__((packed));

#endif
