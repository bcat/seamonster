/*
 *    seamonster / a tiny hack of a gopher server
 *       conn.c / connection state structures
 *
 * Copyright © 2011-12 Jonathan Rascher <jon@bcat.name>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE
 */

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
