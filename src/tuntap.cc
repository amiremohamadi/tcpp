#include <tuntap.hh>

Iface::Iface() {
  this->name = "";
  this->mode = this->Mode::TUN;
}

int Iface::device_alloc() {
  // allocate tun/tap device
  // on successful allocation, file descriptor id is returned

  struct ifreq ifr;

  if (this->name.empty()) {
    throw "device name must be specified! (non-empty)";
  }

  if ((this->fd = open("/dev/net/tun", O_RDWR)) == -1) {
    throw "can't open tun/tap device! make sure that one exists.";
  }

  // clear the ifr
  memset(&(ifr), 0, sizeof(ifr));

  // Flags:
  // IFF_TUN   - TUN device (no Ethernet headers)
  // IFF_TAP   - TAP device
  // IFF_NO_PI - Do not provide packet information
  ifr.ifr_flags = this->mode;

  strcpy(ifr.ifr_name, this->name.c_str());

  if (ioctl(fd, TUNSETIFF, (void *)&ifr) == -1) {
    throw "can't apply changes!";
  }

  return this->fd;
}

Iface::~Iface() { close(fd); }

void Iface::set(std::string name, Mode mode) {
  this->name = name;
  this->mode = mode;
}

size_t Iface::receive(uint8_t buf[], size_t len) {
  // receives a packet from interface.
  // blocks untill a packet sent into the virtual interface
  // make sure that the buffer is large enough. it is MTU of the interface
  // (usually 1500) + 4 for the header info
  // on successful receive, the number of bytes copied into buf is returned
  return read(this->fd, buf, len);
}

size_t Iface::send(uint8_t buf[], size_t len) const {
  // sends a packet into the interface.
  // the buffer must be valid reperesentation of a packet
  // (with appropriate headers).
  // on successful send, the number of bytes sent in the packet is returned
  return write(this->fd, buf, len);
}
