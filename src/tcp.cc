#include <tcp.hh>

std::map<Quad, Connection> Tcp::connections = {};

uint16_t Tcp::checksum(uint8_t bytes[], size_t size) {
  const uint16_t *buf = (uint16_t *)bytes;
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

bool Tcp::is_between_wrapped(uint32_t start, uint32_t x, uint32_t end) {
  // refer to rfc 793: (for acceptable ack) check if the order is correct
  auto wrapping_lt = [](uint32_t lhs, uint32_t rhs) {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left
    //     edge of the window, and if it is not, discarding the data as
    //     "old".  To insure that new data is never mistakenly considered
    //     old and vice- versa, the left edge of the sender's window has to
    //     be at most 2**31 away from the right edge of the receiver's
    //     window.
    return ((lhs - rhs) % (1 << 31)) > (1 << 31);
  };

  return wrapping_lt(start, x) && wrapping_lt(x, end);
}

bool Tcp::is_exists(Quad &q) {
  // if a quad exists in connections
  return (connections.count(q) > 0);
}

Connection &Tcp::get_conn(Quad &q) {
	return connections[q];
}

void Tcp::insert(Quad q, Connection conn) {
  // add new connection
  connections[q] = conn;
}

std::vector<uint8_t> Tcp::accept(PacketParse::ipv4hdr *ip_hdr,
                                 PacketParse::tcphdr *tcp_hdr,
                                 Connection &conn) {
  // ignore non-syn packets
  if (tcp_hdr->syn != 1)
    return {};

  uint32_t iss = 0;
  uint16_t wnd = 1024;

  // TCB: transmission control block (rfc 793)
  conn = {
      .state = Connection::State::SYNRCVD,
      // Send Sequence Space
      /* SND.UNA - send unacknowledged */
      /* SND.NXT - send next */
      /* SND.WND - send window */
      /* SND.UP  - send urgent pointer */
      /* SND.WL1 - segment sequence number used for last window update */
      /* SND.WL2 - segment acknowledgment number used for last window update */
      /* ISS     - initial send sequence number */
      .send = {.una = iss,
               .nxt = iss + 1,
               .wnd = wnd,
               .up = false,
               .wl1 = 0,
               .wl2 = 0},
      // Receive Sequence Space
      /* RCV.NXT - receive next */
      /* RCV.WND - receive window */
      /* RCV.UP  - receive urgent pointer */
      /* IRS     - initial receive sequence number */
      .recv = {.nxt = tcp_hdr->seq + 1,
               .wnd = tcp_hdr->win,
               .up = false,
               .irs = tcp_hdr->seq}};

  // the syn packet received, we send back a syn_ack packet
  PacketParse::tcphdr syn_ack = {
      .sport = tcp_hdr->dport,
      .dport = tcp_hdr->sport,
      .seq = htonl(iss),
      .ack_seq = htonl(ntohl(tcp_hdr->seq) + 1), // TODO: replace with sth else
      .rsvd = 0,
      .dataoff = TCP_MINIMUM_DATA_OFFSET,
      .fin = 0,
      .syn = 1,
      .rst = 0,
      .psh = 0,
      .ack = 1,
      .urg = 0,
      .ece = 0,
      .cwr = 0,
      .win = wnd, // maybe this should be another thing
      .csum = 0,
      .urp = 0};

  PacketParse::ipv4hdr ip = {
      .ihl = TCP_MINIMUM_DATA_OFFSET,
      .version = 4,
      .tos = 0, // be aware of this
      .len = htons(sizeof(PacketParse::ipv4hdr) + sizeof(PacketParse::tcphdr)),
      .id = (0),
      .frag_offset = (0), // don't know why!
      .ttl = 64,
      .proto = 6,
      .csum = 0,
      .saddr = ip_hdr->daddr,
      .daddr = ip_hdr->saddr};

  // to calculate tcp checksum we need the pseudo header
  struct PacketParse::pseudohdr phdr = {
      .saddr = ip.saddr,
      .daddr = ip.daddr,
      .reserved = 0,
      .proto = ip.proto,
      .len = htons(sizeof(struct PacketParse::tcphdr))};

  // calculate ip header checksum
  ip.csum = PacketParse::ip_checksum(ip);
  // convert struct to bytes
  auto ip_bytes = PacketParse::packet_to_bytes((uint8_t *)&ip,
                                               sizeof(PacketParse::ipv4hdr));

  // calculate the tcp header checksum
  syn_ack.csum = PacketParse::tcp_checksum(phdr, syn_ack);
  // convert struct to bytes
  auto tcp_bytes = PacketParse::packet_to_bytes((uint8_t *)&syn_ack,
                                                sizeof(PacketParse::tcphdr));

  // construct the final result, contains ip + tcp header and payload
  ip_bytes.insert(ip_bytes.end(), tcp_bytes.begin(), tcp_bytes.end());

  return ip_bytes;
}

std::vector<uint8_t> Tcp::on_packet(PacketParse::ipv4hdr *ip_hdr,
                                    PacketParse::tcphdr *tcp_hdr,
                                    Connection &conn) {

  // first of all we must check that the sequence number is valid
  // acceptable ack
  // SND.UNA < SEG.ACK =< SND>NXT
  // TODO: if any bug happened we must check the wrapping
  uint32_t ack = tcp_hdr->ack_seq;
	// TODO: check using wrapped_between function
  if (!(ntohl(conn.send.una) < ntohl(ack)) && !(ntohl(ack) <= ntohl(conn.send.nxt))) {
    // this is error and must be handled
		std::cerr << "Bad ack number1" << std::endl;
    return {};
  }

  // valid segment check, okay if it acks at least oen byte which means one of
  // the following states happened:
  // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
  // RCV.NXT =< SEG.SEQ+SEQ.LEN-1 < RCV.NXT+RCV.WND
  uint32_t seqn = tcp_hdr->seq;
  size_t len = ip_hdr->len - (ip_hdr->ihl + tcp_hdr->dataoff) * 4; // not implemented

  if (tcp_hdr->fin)
    len += 1;

  if (tcp_hdr->syn)
    len += 1;

  uint32_t wend = ntohl(conn.recv.nxt) + (uint32_t)ntohs(conn.recv.wnd);
  if (len == 0) {
    // zero length segments has seperate rules to being acceptable
    if (conn.recv.wnd == 0) {
      if (seqn != conn.recv.nxt)
        return {};
    } else if (!(ntohl(conn.recv.nxt) - 1 < ntohl(seqn)) && !(ntohl(seqn) <= wend)) {
      return {};
    }
  } else {
    if (conn.recv.wnd == 0) {
      return {};
    } else if (!(ntohl(conn.recv.nxt) - 1 < ntohl(seqn)) && !(ntohl(seqn) <= wend) &&
				!(ntohl(conn.recv.nxt) - 1 < seqn + len - 1) && !(ntohl(seqn) + len - 1 <= wend)) {
      return {};
    }
  }

  switch (conn.state) {
  case Connection::State::SYNRCVD:
    // expect to get an ACK for our SYN
    if (!tcp_hdr->ack)
      return {};
    // must have ACKed out SYN, since we detected at least one acked byte, and
    // we have send only one byte which is the SYN
    conn.state = Connection::State::ESTAB;
    break;

  case Connection::State::ESTAB:
    break;

  default:
    break;
  }

	return {};
}
