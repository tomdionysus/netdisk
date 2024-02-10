#include "session.h"

#include <memory.h>

session_t *session_create(int socket_fd, void *(handler)(void *arg)) {
  session_t *session = malloc(sizeof(session_t));
  memset(session, 0, sizeof(session_t));

  session->socket_fd = socket_fd;
  session->state = NETDISK_SESSION_STATE_INITIAL;

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
