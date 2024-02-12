# netdisk

A SAN-like remote block device server/client for Linux in C/C++. netdisk has two components:

## Status

**v0.0.1 ALPHA** 
* Working
* Not performance optimised
* Static drive size 100Mb
* IOCTL not implemented
* Will not automatically unload when disconnected
* Will not automatically reconnect

## Overview

* A server (netdiskd) that listens on a configurable TCP Port (26547 by default) for connections from the netdisk driver module, and reads or writes blocks on a specified device or file according to commands over that connection.
* A client (netdisk) block device driver kernel module that connects to a netdiskd server, exposing its configured (remote) device or file as a local device.

netdisk supports several features:

* All communication is encrypted using AES256, both server and client must have a pre-shared 32 byte AES key configured.
* The server may read and write blocks from an actual device or a file simulating a device.
* The server may be configured to be read only.
* The client may be configured to use local in-memory caching (write through to server).

## Building

```sh
git clone https://github.com/tomdionysus/netdisk.git
cd netdisk
mkdir build
cd build
cmake ..
make
make install
```

The `netdiskd` server can be built under Linux and MacOSX, however `netdisk_module` client will only be built and installed under linux. You must update the kernel module dependencies afterward:

```sh
depmod
```

## Getting Started

### Server

You must supply a 256 bit encrption key as a 64 character hex string, and the file of the disk image, which must exist.

```sh
dd if=/dev/zero of=./disk.netdisk bs=1M count=100
netdiskd --key=6f334a6b4aa5a7ac8462387a3cdb8f5755b3c1ef0947cb1492c86793265166c0 --file=./disk.netdisk
```

### Client

The client is a linux kernel module, that can be loaded using `modprobe`. You must supply an indentical 256 bit encrption key, as well as the IP address of a running `netdiskd` server.

```sh
modprobe netdisk key=6f334a6b4aa5a7ac8462387a3cdb8f5755b3c1ef0947cb1492c86793265166c0 address=192.168.1.40
```

You can see the block device using `lsblk`:

```sh
NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda       8:0    0    8G  0 disk 
├─sda1    8:1    0  300M  0 part /boot
├─sda2    8:2    0    2G  0 part [SWAP]
└─sda3    8:3    0  5.7G  0 part /
sr0      11:0    1 1024M  0 rom  
netdisk 253:0    0  100M  0 disk /netdisk
```

You can format the drive to ext4 using `mkfs`:

```sh
mkfs.ext4 -L NetdiskDrive /dev/netdisk
```

And mount it using `mount`

```sh
mkdir /netdisk
mount /dev/netdisk /netdisk
```

## Troubleshooting

`netdiskd` can take a log level parameter to give more info:

```sh
netdiskd --log_level=DEBUG --key=6f334a6b4aa5a7ac8462387a3cdb8f5755b3c1ef0947cb1492c86793265166c0 --file=./disk.netdisk
```

The `netdisk` kernel module logs can be seen using `dmesg`:

```
[ 1766.028397] netdisk: loaded. Server: 192.168.1.40 Port: 26547, Device Name: netdisk
```

## Uses

* SAN - A remote file or device can be configured to be usable over a network as a local block device for a single client.
* Read Only Remote Device - A remote file or device can be configured as a read-only local block device for multiple clients (network boot).
* (Roadmap) Copy-On-Write Remote Device - A remote file or device can be configured as a copy-on-write block device for multiple clients (persistent overlay per client based on one read only image).

## Encrption

* AES256 is used with a pre-shared key (netdisk performs no key exchange).
* All traffic are encrypted in CBC mode, with a random IV for each side of each session.
* netdiskd will not allow a client without the correct key, or an incompatible version, to establish a session.

## Status

netdisk is working ALPHA software.

## Dependencies

* [tiny-AES-c](deps/tiny-AES-c) - [Github](https://github.com/kokke/tiny-AES-c) 
