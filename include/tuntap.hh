// a tun/tap binding for C++.
//
// this is a basic interface to create userspace virtual network adapter.
//
// for basic usage, create and Iface object and call the send/receive method.
//
// creating the devices requires 'CAP_NETADM' privillages
// (most commonly by running as root)

#ifndef TUNTAP_HH
#define TUNTAP_HH

#include <exception>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>

class Iface {
  // creates new virtual interface.
public:
  enum Mode { TUN = IFF_TUN, TAP = IFF_TAP };
  Iface(std::string = "", Mode = Mode::TUN);
  ~Iface();
  void set(std::string = "", Mode = Mode::TUN);
  int device_alloc();
  size_t receive(uint8_t[], size_t);
  size_t send(uint8_t[], size_t) const;

private:
  int fd; // file descriptor
  Mode mode;
  std::string name;
};

#endif
