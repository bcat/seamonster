/***** Dependencies: *****/

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/***** Buffer sizes: *****/

#define LOG_BUF_SIZE PIPE_BUF

/***** Logging functions: *****/

void log_msg(int pri, const char *addr_str, const char *format,
    va_list varargs) {
  char buf[LOG_BUF_SIZE], *buf_next = buf;
  int buf_size = sizeof(buf), str_size;

  if (addr_str) {
    if ((str_size = snprintf(buf_next, buf_size, "%s - ", addr_str)) < 0) {
      return;
    }
    buf_next += (str_size < buf_size) ? str_size : buf_size;
    buf_size -= (str_size < buf_size) ? str_size : buf_size;
  }

  if ((str_size = vsnprintf(buf_next, buf_size, format, varargs)) < 0) {
    return;
  }
  buf_next += (str_size < buf_size) ? str_size : buf_size;

  syslog(pri, "%s", buf);
}

void log_info(const char *addr_str, const char *format, ...) {
  va_list varargs;

  va_start(varargs, format);
  log_msg(LOG_INFO, addr_str, format, varargs);
  va_end(varargs);
}

void log_warn(const char *addr_str, const char *format, ...) {
  va_list varargs;

  va_start(varargs, format);
  log_msg(LOG_WARNING, addr_str, format, varargs);
  va_end(varargs);
}

void log_error(const char *addr_str, const char *format, ...) {
  va_list varargs;

  va_start(varargs, format);
  log_msg(LOG_ERR, addr_str, format, varargs);
  va_end(varargs);
}

void log_perror(const char *addr_str, const char *s) {
  log_error(addr_str, "%s: %s", s, strerror(errno));
}

/***** String functions: *****/

int asprintf(char **p_s, const char *format, ...) {
  va_list varargs;
  int ret;

  va_start(varargs, format);
  ret = vasprintf(p_s, format, varargs);
  va_end(varargs);

  return ret;
}

int vasprintf(char **p_s, const char *format, va_list va) {
  int ret;
  char *s = NULL;
  va_list va2;

  va_copy(va2, va);

  if ((ret = vsnprintf(NULL, 0, format, va)) < 0) {
    goto cleanup;
  }

  if (!(s = malloc(ret + 1))) {
    ret = -1;
    goto cleanup;
  }

  if ((ret = vsnprintf(s, ret + 1, format, va2)) < 0) {
    goto cleanup;
  }

cleanup:
  va_end(va2);
  if (ret < 0) {
    free(s);
  } else {
    *p_s = s;
  }

  return ret;
}

/***** IO functions: *****/

int r_close(int fildes) {
  int ret;
  while ((ret = close(fildes)) == -1 && errno == EINTR);
  return ret;
}

int r_open(const char *path, int oflag, ...) {
  int ret;

  if (oflag & O_CREAT) {
    va_list varargs;
    mode_t mode;

    va_start(varargs, oflag);
    mode = va_arg(varargs, mode_t);
    va_end(varargs);

    while ((ret = open(path, oflag, mode)) == -1 && errno == EINTR);
  } else {
    while ((ret = open(path, oflag)) == -1 && errno == EINTR);
  }

  return ret;
}

ssize_t r_read(int fildes, void *buf, size_t nbytes) {
  ssize_t ret;
  while ((ret = read(fildes, buf, nbytes)) == -1 && errno == EINTR);
  return ret;
}

ssize_t r_write(int fildes, const void *buf, size_t nbyte) {
  ssize_t ret;
  do {
    while ((ret = write(fildes, buf, nbyte)) == -1
        && errno == EINTR);
    buf = (const char *) buf + ret;
    nbyte -= ret;
  } while (nbyte && ret != -1);
  return ret;
}

/***** Socket functions: *****/

int r_accept(int socket, struct sockaddr *address, socklen_t *address_len) {
  int ret;
  while ((ret = accept(socket, address, address_len)) == -1
      && errno == EINTR);
  return ret;
}
