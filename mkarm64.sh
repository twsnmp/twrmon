#!/bin/sh
apt update
apt install -y wget
apt-get install -y flex bison byacc
apt install -y g++-aarch64-linux-gnu
cd /tmp
wget http://www.tcpdump.org/release/libpcap-1.10.1.tar.gz
tar xzf libpcap-1.10.1.tar.gz
cd libpcap-1.10.1
export CC=aarch64-linux-gnu-gcc
./configure --prefix=/usr --host=arm64-linux --with-pcap=linux
make
make install
cd /twrmon
aarch64-linux-gnu-gcc -o $1/twrmon.arm64

