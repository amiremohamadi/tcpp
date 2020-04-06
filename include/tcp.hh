#ifndef TCP_HH
#define TCP_HH

#include <map>

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
    size_t una;
    size_t nxt;
    size_t wnd;
    bool up;
    size_t wl1;
    size_t wl2;
    size_t iss;
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
    size_t nxt;
    size_t wnd;
    bool up;
    size_t irs;
  } recv;
};

class Tcp {
  // all tcp stuffs gonna hanle here
public:
  struct quad;
  map<quad, connection> connections;

private:
};

struct quad {
  // each quad stores ip and port for source and destination
  // this is used for identifying connections
  uint32_t saddr, daddr;
  uint16_t sport, dport;

  bool operator<(const quad &right) {
    // to use connectionid as hashmap-key
    return std::make_tuple(this->saddr, this->daddr, this->sport, this->dport) <
           std::make_tuple(right.saddr, right.daddr, right.sport, right.dport);
  }
};

#endif
