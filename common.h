/*
 *    seamonster / a tiny hack of a gopher server
 *     common.h / global variables, useful wrappers, shared definitions
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

#ifndef COMMON_H
#define COMMON_H

/***** Dependencies: *****/

#include <limits.h>
#include <signal.h>
#include <stdarg.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/wait.h>

/***** Explicit declarations of POSIX limits: *****/

#ifndef OPEN_MAX
#define OPEN_MAX      1024
#endif

#ifndef PIPE_BUF
#define PIPE_BUF      _POSIX_PIPE_BUF
#endif

/***** Buffer sizes, all in one place: *****/

#define LOG_BUF_SIZE  PIPE_BUF
#define CONN_BUF_SIZE 16384

/***** Configuration data structure: *****/

struct config {
  int daemonize;
  const char *pid_file;

  const char *hostname;
  in_port_t port;
  int backlog;

  const char *user;

  size_t num_workers;

  size_t conns_per_worker;

  const char *srv_path;
};

/***** Logging functions: *****/

/*
 * Log a formatted message with the specified priority and optionally the
 * specified IP address.
 */
void log_msg(int pri, const char *addr_str, const char *format,
    va_list varargs);

/*
 * Log a formatted message at DEBUG priority, optionally including the
 * specified IP address.
 */
void log_debug(const char *addr_str, const char *format, ...);

/*
 * Log a formatted message at INFO priority, optionally including the
 * specified IP address.
 */
void log_info(const char *addr_str, const char *format, ...);

/*
 * Log a formatted message at WARNING priority, optionally including the
 * specified IP address.
 */
void log_warn(const char *addr_str, const char *format, ...);

/*
 * Log a formatted message at ERR priority, optionally including the
 * specified IP address.
 */
void log_error(const char *addr_str, const char *format, ...);

/*
 * Log a message associated with the current value of errno at WARN priority,
 * optionally including the specified IP address.
 */
void log_pwarn(const char *addr_str, const char *s);

/*
 * Log a message associated with the current value of errno at ERR priority,
 * optionally including the specified IP address.
 */
void log_perror(const char *addr_str, const char *s);

/***** String functions: *****/

/*
 * Write formatted data into a dynamically allocated string whose address will
 * be stored in the specified memory location.
 *
 * Returns the length of the newly-allocated string on success and a negative
 * value on failure.
 */
int asprintf(char **p_s, const char *format, ...);

/*
 * Write formatted data from the given varargs list into a dynamically
 * allocated string whose address will be stored in the specified memory
 * location.
 *
 * Returns the length of the newly-allocated string on success and a negative
 * value on failure.
 */
int vasprintf(char **p_s, const char *format, va_list va);

/***** IO functions: *****/

/*
 * Close the specified file descriptor, retrying when interrupted.
 *
 * Returns 0 on success and -1 on error.
 */
int r_close(int fildes);

/*
 * Open the file at the specified path with all the usual flag and mode
 * choices, retrying when interrupted.
 *
 * Returns the newly opened file descriptor on success and -1 on error.
 */
int r_open(const char *path, int oflag, ...);

/*
 * Read at most the specified number of bytes from the given file descriptor,
 * retrying when interrupted.
 *
 * Returns the number of bytes read on success and -1 on error.
 */
ssize_t r_read(int fildes, void *buf, size_t nbyte);

/*
 * Write at most the specified number of bytes to the given file descriptor,
 * retrying when interrupted.
 *
 * Returns the total number of bytes written on success and -1 on error.
 */
ssize_t r_write(int fildes, const void *buf, size_t nbyte);

/***** Socket functions: *****/

/*
 * Accept an incoming connection request on the given socket, retrying when
 * interrupted.
 *
 * Returns a newly opened file descriptor on success and -1 on error.
 */
int r_accept(int socket, struct sockaddr *address, socklen_t *address_len);

/***** Global variables: *****/

extern volatile sig_atomic_t g_terminating;

extern pid_t g_server_pid;

extern struct config g_config;

#endif /* COMMON_H */
