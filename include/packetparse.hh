// a simple packet parser library.

#ifndef PACKETPARSE_HH
#define PACKETPARSE_HH

class PacketParse {
  // TODO: define functions for parsing packets
  // parse network packets
public:
  struct ipv4hdr;
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
  uint8_t version : 4;
  uint8_t ihl : 4;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint8_t flags : 3;
  uint16_t frag : 13;
  uint8_t ttl;
  uint8_t proto;
  uint16_t csum;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__((packed));

#endif
