#include "session.h"

#include <memory.h>
#include <stdio.h>

session_t *session_create(int socket_fd, struct sockaddr_in remote_addr, void *(handler)(void *arg)) {
  session_t *session = malloc(sizeof(session_t));
  if (!session) {
    return NULL;
  }
  memset(session, 0, sizeof(session_t));

  session->socket_fd = socket_fd;
  session->state = NETDISK_SESSION_STATE_INITIAL;
  session->remote_addr = remote_addr;
  sprintf(session->remote_addr_str, "%s:%d", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));

  if (pthread_create(&session->thread_id, NULL, handler, session) != 0) {
    session_release(session);
    return NULL;
  }

  // Allocate session buffer.
  session->buffer = malloc(NETDISK_MAX_PACKET_SIZE);
  if (!session->buffer) {
    session_release(session);
    return NULL;
  }

  return session;
}

void session_release(session_t *session) {
  if (session->buffer) free(session->buffer);
  free(session);
}
