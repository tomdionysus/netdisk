#include "session.h"

#include <memory.h>
#include <stdio.h>

session_t *session_create(int socket_fd, struct sockaddr_in remote_addr, void *(main_thread)(void *arg), void *(send_thread)(void *arg)) {
  session_t *session = malloc(sizeof(session_t));
  if (!session) {
    return NULL;
  }

  session->socket_fd = socket_fd;
  session->state = NETDISK_SESSION_STATE_INITIAL;
  session->remote_addr = remote_addr;
  sprintf(session->remote_addr_str, "%s:%d", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));

  // Send Queue
  session->send_queue = packet_queue_allocate(128);
  if(!session->send_queue) {
    return NULL;
  }

  // Send Thread
  if (pthread_create(&session->send_thread_id, NULL, send_thread, session) != 0) {
    session_release(session);
    return NULL;
  }  

  // Main handler thread
  if (pthread_create(&session->main_thread_id, NULL, main_thread, session) != 0) {
    session_release(session);
    return NULL;
  }

  return session;
}

void session_release(session_t *session) {
  // Stop Send Thread
  pthread_cancel(session->send_thread_id);

  // Send Queue
  packet_queue_free(session->send_queue);

  // Free Session
  free(session);
}
