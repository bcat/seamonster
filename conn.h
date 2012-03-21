/*
 *    seamonster / a tiny hack of a gopher server
 *       conn.h / connection state structures
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

#ifndef CONN_H
#define CONN_H

/***** Dependencies: *****/

#include "common.h"

/***** Connection-specific data: *****/

enum {
  STAGE_FREE,
  STAGE_REQUEST_START,
  STAGE_REQUEST_PREV_CR,
  STAGE_RESPONSE_START,
  STAGE_RESPONSE_BODY
};

struct conn {
  /*
   * Index of this connection. (This is a worker.c implementation detail and
   * should not be used from request handlers.)
   */
  size_t conn_idx;

  /*
   * Index of this connection's pollfd, or SIZE_MAX if there is not currently
   * an associated pollfd. (This is a worker.c implementation detail and
   * should not be used from request handlers.)
   */
  size_t pollfd_idx;

  /*
   * File descriptor for the client connection's associated socket or -1 if
   * not connected.
   */
  int sock;

  /*
   * String representation of client's IP address or NULL if not connected.
   */
  char addr_str[INET_ADDRSTRLEN];

  /*
   * Current connection stage; begins at STAGE_FREE.
   */
  int stage;

  /*
   * Size of request-specific state structure; defaults to 0.
   */
  size_t state_size;

  /*
   * Buffer for request-specific state storage and socket IO.
   */
  char buf[CONN_BUF_SIZE];

  /*
   * Next byte to send/receive for socket IO.
   */
  char *buf_next;

  /*
   * Amount of response data that's actually stored at *buf_next.
   */
  size_t data_size;

  /*
   * Absolute file system path of requested resource or NULL if no such path
   * could be resolved.
   */
  char *path;

  /*
   * Gopher item type character for requested resource or a NUL character if
   * the correct item type could not be determined.
   */
  char item_type;

  int (*init_response)(struct conn *);

  int (*buffer_response)(struct conn *);

  void (*cleanup_response)(struct conn *);
};

/***** Basic connection functions: *****/

void init_conn(struct conn *p_conn);

void cleanup_conn(struct conn *p_conn);

#endif /* CONN_H */
