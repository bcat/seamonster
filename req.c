/***** Dependencies: *****/

#include "req.h"

#include <errno.h>

/***** Request processing functions: *****/

int parse_request(struct conn *p_conn) {
  int ret = 0, sock = p_conn->sock;
  char *buf = p_conn->buf, *buf_next = p_conn->buf_next;
  size_t buf_size = sizeof(p_conn->buf) - (buf_next - buf);
  ssize_t recv_size;

  switch (recv_size = r_read(sock, buf_next, buf_size)) {
    case -1:
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        ret = 0;
      } else {
        log_pwarn(p_conn->addr_str, "Couldn't read request from client");
        ret = -1;
      }
      goto cleanup;

    case 0:
      log_warn(p_conn->addr_str, "Client sent incomplete request");
      ret = -1;
      goto cleanup;
  }

  do {
    switch(*buf_next) {
    case '\0':
      log_warn(p_conn->addr_str, "Unexpected NUL in client request");
      ret = -1;
      goto cleanup;

    case '\n':
      if (p_conn->stage == STAGE_REQUEST_PREV_CR) {
        ret = 1;
        goto cleanup;
      }
      break;

    case '\r':
      *buf_next = '\0';
      p_conn->stage = STAGE_REQUEST_PREV_CR;
      break;

    case '\t':
      *buf_next = '\0';

    default:
      p_conn->stage = STAGE_REQUEST_START;
    }

    ++buf_next;
  } while (buf_next < buf + recv_size);

  if (recv_size == buf_size) {
    log_warn(p_conn->addr_str, "Client request too large");
    ret = -1;
    goto cleanup;
  }

cleanup:
  if (ret == 1) {
    if (shutdown(sock, SHUT_RD)) {
      log_pwarn(p_conn->addr_str,
          "Couldn't shut down read end of client socket");
      ret = -1;
    }
  }

  return ret;
}
