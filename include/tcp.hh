#ifndef TCP_HH
#define TCP_HH

#include <map>
class Tcp {
  // all tcp stuffs gonna hanle here
public:
  struct quad;
  map<quad, connection> connections;

private:
  enum State { Closed, Listen, SynRcvd, Estab };
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
