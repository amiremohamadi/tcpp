// a simple packet parser library.

#ifndef PACKETPARSE_HH
#define PACKETPARSE_HH

class PacketParse {
  // TODO: define functions for parsing packets
  // parse network packets
public:
  struct ipv4hdr;
  struct tcphdr;
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
  uint8_t data[];
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
#if __BYTE_ORDER__ == __LITTLE_ENDIAN
  uint8_t rsvd : 4;
  uint8_t dataoff : 4;
#else
  uint8_t dataoff : 4;
  uint8_t rsvd : 4;
#endif
  uint8_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1;
  uint16_t win;
  uint16_t csum;
  uint16_t urp;
  uint8_t data[];
} __attribute__((packed));

#endif
