#include <tcp.hh>

uint16_t Tcp::checksum(uint8_t bytes[], size_t size) {
  const uint16_t *buf = bytes;
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

Tcp::Tcp(std::string name, Iface::Mode mode) {
  this->iface.set(name, mode);
  this->iface.device_alloc();
}

size_t Tcp::receive(uint8_t bytes[], size_t len) {
  // wrapper method for Iface::receive
  this->iface.receive(bytes, len);
}
