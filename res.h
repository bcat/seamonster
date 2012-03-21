/*
 *    seamonster / a tiny hack of a gopher server
 *        res.h / response handler helpers
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

/***** Response handler macros (declaration): *****/

#define RH_DECLARE(name) \
    void new_##name##_response(struct conn *p_conn);

/***** Response handler macros (definition): *****/

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

/***** Response handler macros (implementation): *****/

#define RH_CONN(field) (p_conn_->field)

#define RH_STATE(field) (p_state_->field)
