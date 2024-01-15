#include "process_packet.h"
#include "transaction.h"

static void process_packet_start(packet_t *packet, struct sockaddr_in* from_addr) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_OK:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

static void process_packet_stop(packet_t *packet, struct sockaddr_in* from_addr) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_OK:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

static void process_packet_read(packet_t *packet, struct sockaddr_in* from_addr) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_READ_OK:
    // Find transaction
    transaction_t *trans = find_transaction(packet->fields.user_data);
    if(trans == NULL) {
      printk(KERN_ALERT "netdisk: received unknown transaction from %pI4:%u\n", &from_addr->sin_addr, ntohs(from_addr->sin_port));
      break;
    }
    if(rq_data_dir(trans->orig_rq) != READ) {
      printk(KERN_ALERT "netdisk: NETDISK_REPLY_READ_OK received for non-READ transaction from %pI4:%u\n", &from_addr->sin_addr, ntohs(from_addr->sin_port));
      break;
    }
    // Find the chunk
    chunk_t *chk = find_chunk(trans, packet->fields.block_offset);
    if(chk == NULL) {
      printk(KERN_ALERT "netdisk: received unknown chunk from %pI4:%u\n", &from_addr->sin_addr, ntohs(from_addr->sin_port));
      break;
    }
    // Copy the data from packet
    memcpy(chk->data, packet->fields.payload, chk->size);

    // Remove the chunk
    // printk(KERN_ALERT "netdisk: block completed %llu (transaction %llu)\n", chk->block_id, trans->id);
    remove_chunk(trans, chk);
    
    // If the transaction is empty, release it.
    if(RB_EMPTY_ROOT(&trans->chunk_tree)) {
      printk(KERN_ALERT "netdisk: transaction completed %llu/%llu chunks, %llu/%llu bytes (transaction %llu)\n", trans->completed_chunks, trans->total_chunks, trans->completed_bytes, trans->total_bytes, trans->id);
      _release_transaction(trans, false);
    }
    break;
  case NETDISK_REPLY_OUT_OF_RANGE:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

static void process_packet_write(packet_t *packet, struct sockaddr_in* from_addr) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_WRITE_OK:
    // Find transaction
    transaction_t *trans = find_transaction(packet->fields.user_data);
    if(trans == NULL) {
      printk(KERN_ALERT "netdisk: received unknown transaction from %pI4:%u\n", &from_addr->sin_addr, ntohs(from_addr->sin_port));
      break;
    }
    if(rq_data_dir(trans->orig_rq) != WRITE) {
      printk(KERN_ALERT "netdisk: NETDISK_REPLY_WRITE_OK received for non-WRITE transaction from %pI4:%u\n", &from_addr->sin_addr, ntohs(from_addr->sin_port));
      break;
    }
    // Find the chunk
    chunk_t *chk = find_chunk(trans, packet->fields.block_offset);
    if(chk == NULL) {
      printk(KERN_ALERT "netdisk: received unknown chunk from %pI4:%u\n", &from_addr->sin_addr, ntohs(from_addr->sin_port));
      break;
    }
    // Remove the chunk
    remove_chunk(trans, chk);
    // If the transaction is empty, release it.
    if(RB_EMPTY_ROOT(&trans->chunk_tree)) release_transaction(trans);
    break;
  case NETDISK_REPLY_OUT_OF_RANGE:
    break;
  case NETDISK_REPLY_READ_ONLY:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

void process_packet(packet_t *packet, struct sockaddr_in* addr) {
  // printk(KERN_DEBUG "netdisk: received %s / %s from %pI4:%u\n", packet_command_to_str(packet->fields.command), packet_reply_to_str(packet->fields.reply), &addr->sin_addr, ntohs(addr->sin_port));

  switch(packet->fields.command) {
  case NETDISK_COMMAND_START:
    process_packet_start(packet, addr);
    break;
    case NETDISK_COMMAND_STOP:
    process_packet_stop(packet, addr);
    break;
    case NETDISK_COMMAND_READ:
    process_packet_read(packet, addr);
    break;
    case NETDISK_COMMAND_WRITE:
    process_packet_write(packet, addr);
    break;
  default:
    break;
  }
}