# netdisk

A SAN-like remote block device server/client for Linux in C/C++. netdisk has two components:

* A server (netdiskd) that listens on a configurable TCP Port (26547 by default) for connections from the netdisk driver module, and reads or writes blocks on a specified device or file according to commands over that connection.
* A client (netdisk) block device driver kernel module that connects to a netdiskd server, exposing its configured (remote) device or file as a local device.

netdisk supports several features:

* All communication is encrypted using AES256, both server and client must have a pre-shared 32 byte AES key configured.
* The server may read and write blocks from an actual device or a file simulating a device.
* The server may be configured to be read only.
* The client may be configured to use local in-memory caching (write through to server).

## Uses

* SAN - A remote file or device can be configured to be usable over a network as a local block device for a single client.
* Read Only Remote Device - A remote file or device can be configured as a read-only local block device for multiple clients (network boot).
* (Roadmap) Copy-On-Write Remote Device - A remote file or device can be configured as a copy-on-write block device for multiple clients (persistent overlay per client based on one read only image).

## Encrption

* AES256 is used with a pre-shared key (netdisk performs no key exchange).
* Blocks are encrypted in CBC mode, with a cryptographic random IV for each connection.
* netdiskd will not allow a client without the correct key to establish a session.
* A combination of sequence numbers and timestamps are used to mitigate replay attacks.

## Status

netdisk is prototype in Feb 2024 and under development. Please do not use until marked ALPHA.

## Dependencies

* [tiny-AES-c](deps/tiny-AES-c) - [Github](https://github.com/kokke/tiny-AES-c) 
* [red-black-tree](deps/red-black-tree) (Fork) - [Original Github](https://github.com/tomdionysus/red-black-tree)
