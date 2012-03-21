/***** Dependencies: *****/

#include "conn.h"

#include <stdlib.h>

/***** Cleanup functions: *****/

void init_conn(struct conn *p_conn) {
  p_conn->pollfd_idx = SIZE_MAX;
  p_conn->sock = -1;
  p_conn->addr_str[0] = '\0';
  p_conn->stage = STAGE_FREE;
  p_conn->state_size = 0;
  p_conn->buf_next = p_conn->buf;
  p_conn->data_size = 0;
  p_conn->path = NULL;
  p_conn->item_type = '\0';
  p_conn->init_response = NULL;
  p_conn->buffer_response = NULL;
  p_conn->cleanup_response = NULL;
}

void cleanup_conn(struct conn *p_conn) {
  int sock = p_conn->sock;

  /* If there's no connection yet, don't do anything. */
  if (sock == -1) {
    return;
  }

  /* Close the client connection's socket. */
  if (r_close(sock)) {
    log_pwarn(p_conn->addr_str, "Couldn't close connection socket");
  }

  /* Free client resources. */
  free(p_conn->path);
  if (p_conn->cleanup_response) {
    p_conn->cleanup_response(p_conn);
  }

  /* Reinitialize the connection info structure. */
  init_conn(p_conn);
}
