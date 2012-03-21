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

#include <poll.h>

/***** Connection-specific data: *****/

enum {
  STAGE_FREE,
  STAGE_REQUEST_START,
  STAGE_REQUEST_PREV_CR,
  STAGE_RESPONSE_START,
  STAGE_RESPONSE_BODY,
  STAGE_RESPONSE_EOM
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

/***** Request handler macros (declaration): *****/

#define RH_DECLARE(name) \
    void new_##name##_response(struct conn *p_conn);

/***** Request handler macros (definition): *****/

#define RH_BEGIN(name) \
    struct state_; \
    static int init_response_(struct conn *); \
    static int buffer_response_(struct conn *); \
    static void cleanup_response_(struct conn *); \
    void new_##name##_response(struct conn *p_conn) { \
      p_conn->init_response = init_response_; \
      p_conn->buffer_response = buffer_response_; \
      p_conn->cleanup_response = cleanup_response_; \
    }

#define RH_BEGIN_STATE \
    struct state_ {

#define RH_END_STATE \
      int : 0; \
    };

#define RH_BEGIN_INIT \
    int init_response_(struct conn *p_conn_) { \
      struct state_ *p_state_ = (struct state_ *)p_conn_->buf; \
      p_conn_->state_size = sizeof(*p_state_); \
      { \

#define RH_END_INIT \
      } \
    }

#define RH_BEGIN_BUFFER \
    int buffer_response_(struct conn *p_conn_) { \
      struct state_ *p_state_ = (struct state_ *)p_conn_->buf; \
      (void)sizeof(p_state_); /* Suppress unused variable warning. */ \
      {

#define RH_END_BUFFER \
      } \
    }

#define RH_BEGIN_CLEANUP \
    void cleanup_response_(struct conn *p_conn_) { \
      struct state_ *p_state_ = (struct state_ *)p_conn_->buf; \
      (void)sizeof(p_state_); /* Suppress unused variable warning. */ \
      {

#define RH_END_CLEANUP \
      } \
    }

#define RH_END

/***** Request handler macros (implementation): *****/

#define RH_CONN(field) (p_conn_->field)

#define RH_STATE(field) (p_state_->field)

/***** Basic connection functions: *****/

void init_conn(struct conn *p_conn);

void cleanup_conn(struct conn *p_conn);

#endif /* CONN_H */
