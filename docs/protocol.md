# Protocol

The netdisk protocol is a binary protocol that works over TCP. A client connects to a server, and the protocol assumes each side exists in one of a number of states:

| State                            | Description                                                 | Actions                                                                       |
|:---------------------------------|:------------------------------------------------------------|:------------------------------------------------------------------------------|
| NETDISK_SESSION_STATE_INITIAL    | The initial state after the TCP connection is established   | Send a random 32 byte IV.                                                     |
| NETDISK_SESSION_STATE_IV         | The node is waiting for the IV                              | Set up the AES context with the received IV, and send the encrypted handshake |
| NETDISK_SESSION_STATE_HANDSHAKE  | The node is waiting for the handshake                       | Decrypt and check the handshake magic number and version                      |
| NETDISK_SESSION_STATE_READY      | Packets are received, decrypted and processed.              | Normal operation, encrypted data is transferred both ways                     |

## NETDISK_SESSION_STATE_INITIAL

* Each side enters this state when the TCP connection is established. 
* Each node should immediately generate and send a 32 byte initialisation vector (IV).
* Each side then sets state to NETDISK_SESSION_STATE_IV.

## NETDISK_SESSION_STATE_IV

* Each side should wait to receive the other's 32 byte IV
* When received, that establishes the other side's AES context.
* All traffic past this point is encrypted with AES CBC using that context.
* Each node then constructs, encrypts and sends a handshake packet
* Each side then sets state to NETDISK_SESSION_STATE_HANDSHAKE.

## NETDISK_SESSION_STATE_HANDSHAKE

* Each side should wait to recieve the other's handshake.
* The handshake is decrypted and checked for a magic number and the version.
* If either are incorrect or incompatible, the connection is closed.
* If correct, each side stores the other's node ID, a unique 64 bit identifier.
* Each side then sets state to NETDISK_SESSION_STATE_READY.

## NETDISK_SESSION_STATE_READY

* Each side enters a loop of receiving and decrypting a header packet, and if indicated a data block.
* Operations are processed given the header and data.
* Each side may send to the other more encrypted header packets, and if indicated data blocks.

# Normal Operation

In Normal operation each side waits for and decrypts a 16 byte header packet:

```c
struct packet_header {
  uint16_t type;
  uint16_t flags;
  uint32_t length;
  uint32_t block_id;
  uint32_t transaction_id;
}
```

If the `length` field is non-zero, the node should immediately try to receive that number of bytes, which must not exceed `NETDISK_MAX_PACKET_SIZE` and be an exact multiple of 16 (AES block size).
The operation is then processed depending on this header and data - the `type` field is the operation:

| Command                          | Description                                                                                                                                |
|:---------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------|
| NETDISK_COMMAND_READ             | Read from the device                                                                                                                       |
| NETDISK_COMMAND_WRITE            | Write to the device                                                                                                                        |

| Reply                            | Description                                                                                                                                |
|:---------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------|
| NETDISK_REPLY_READ_OK            | The read was successful, the `length`, `block_id` and `transaction_id` describe the data. The read will be sent after with `length` bytes. |
| NETDISK_REPLY_WRITE_OK           | The write was successful, the `block_id` and `transaction_id` describe the write.                                                          |
| NETDISK_REPLY_READ_ONLY          | A write was requested to a read only device, the `block_id` and `transaction_id` describe the write.                                       |
| NETDISK_REPLY_OUT_OF_RANGE       | A write was requested to an out of range block, the `block_id` and `transaction_id` describe the write.                                    |
| NETDISK_REPLY_ERROR              | An unknown error has occured                                                                                                               |

## NETDISK_COMMAND_READ

**Client:** The client should set up the `block_id` and `transaction_id` fields to describe the data to be read. `length` should be set to zero.

**Server:** The server should reply with NETDISK_REPLY_READ_OK if the read was successful, and immediately send the data of `length` bytes. On an error, the `length` should be set to zero, and a packet of type NETDISK_REPLY_OUT_OF_RANGE or NETDISK_REPLY_ERROR should be sent with the appropriate `block_id` and `transaction_id` values.

## NETDISK_COMMAND_WRITE

**Client:** The client should set up the `length`, `block_id` and `transaction_id` fields to describe the data to be written, and immediately send the data of `length` bytes.

**Server:** The server should reply with NETDISK_REPLY_WRITE_OK and if the write was successful, with `length` set to zero and the the appropriate `block_id` and `transaction_id` values. On an error, a packet of type NETDISK_REPLY_READ_ONLY, NETDISK_REPLY_OUT_OF_RANGE or NETDISK_REPLY_ERROR should be sent with the appropriate `block_id` and `transaction_id` values.

## NETDISK_REPLY_ERROR

