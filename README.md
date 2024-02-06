# netdisk

A SAN-like remote block device server/client for Linux in C/C++. netdisk has two components:

Status: **v0.0.1 ALPHA**

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

You must supply a 256bit encrption key as a hex string, and the file of the disk image.

```sh
netdiskd --key=6f334a6b4aa5a7ac8462387a3cdb8f5755b3c1ef0947cb1492c86793265166c0 --file=./disk.netdisk
```

### Client

The client is a linux kernel module, that can be loaded using `modprobe`. You must supply an indentical 256bit encrption key as a hex string, as well as the ip address of a running `netdiskd` server.

```sh
modprobe netdisk key=6f334a6b4aa5a7ac8462387a3cdb8f5755b3c1ef0947cb1492c86793265166c0 address=192.168.1.40
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
