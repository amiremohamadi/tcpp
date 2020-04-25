#ifndef TCP_HH
#define TCP_HH

#include <arpa/inet.h>
#include <iostream>
#include <map>
#include <packetparse.hh>
#include <string.h>
#include <vector>

#define MTU 1504 // maximum transmission unit

struct connection {
  enum State { CLOSED, LISTEN, SYNRCVD, ESTAB } state;
  // keeps track of send sequence varuables
  struct sendseq {

    /*         1         2          3          4               */
    /*    ----------|----------|----------|----------          */
    /*           SND.UNA    SND.NXT    SND.UNA                 */
    /*                                +SND.WND                 */
    /*  1 - old sequence numbers which have been acknowledged  */
    /*  2 - sequence numbers of unacknowledged data            */
    /*  3 - sequence numbers allowed for new data transmission */
    /*  4 - future sequence numbers which are not yet allowed  */
    /*                    Send Sequence Space	                 */
    uint32_t una;
    uint32_t nxt;
    uint16_t wnd;
    bool up;
    size_t wl1;
    size_t wl2;
    uint32_t iss;
  } send;

  // keeps track of receive sequence varuables
  struct recvseq {
    /*     1          2          3                            */
    /*    ----------|----------|----------                    */
    /*           RCV.NXT    RCV.NXT                           */
    /*                     +RCV.WND                           */
    /* 1 - old sequence numbers which have been acknowledged  */
    /* 2 - sequence numbers allowed for new reception         */
    /* 3 - future sequence numbers which are not yet allowed  */
    /*                 Receive Sequence Space                 */
    uint32_t nxt;
    uint16_t wnd;
    bool up;
    uint32_t irs;
  } recv;
};

struct quad {
  // each quad stores ip and port for source and destination
  // this is used for identifying connections
  uint32_t saddr, daddr;
  uint16_t sport, dport;

  bool operator<(const quad &right) const {
    // to use connectionid as hashmap-key
    return std::make_tuple(this->saddr, this->daddr, this->sport, this->dport) <
           std::make_tuple(right.saddr, right.daddr, right.sport, right.dport);
  }
};

class Tcp {
  // all tcp stuffs gonna hanle here
public:
  static bool is_exists(quad &);
  static void insert(quad, connection);
  static std::vector<uint8_t> accept(PacketParse::ipv4hdr *,
                                     PacketParse::tcphdr *, connection &);

private:
  static std::map<quad, connection> connections;
  static uint16_t checksum(uint8_t[], size_t);
  static bool is_between_wrapped(uint32_t, uint32_t, uint32_t);
};

#endif
