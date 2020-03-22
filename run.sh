#!/bin/zsh

# check if dir 'build' exists
if [ ! -d 'build' ]; then
    mkdir build
fi

cmake -S . -B build
cmake --build build

# grant access
sudo setcap cap_net_admin=eip ./build/tcpp

# run on the background
cd build/
./tcpp &
pid=$!

# setup tun0
sudo ip link set tun0 up
sudo ip address add 192.168.0.1/32 dev tun0
sudo ip route add 192.168.0.2/32 dev tun0

trap "kill $pid" INT TERM
wait $pid
