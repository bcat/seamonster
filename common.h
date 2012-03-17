#ifndef    COMMON_H
# define   COMMON_H

/***** Dependencies: *****/

# include <limits.h>
# include <signal.h>
# include <stdarg.h>

# include <arpa/inet.h>

# include <sys/socket.h>
# include <sys/wait.h>

/***** Explicit declarations of POSIX limits: *****/

# ifndef OPEN_MAX
#   define OPEN_MAX 1024
# endif

# ifndef PIPE_BUF
#   define PIPE_BUF _POSIX_PIPE_BUF
# endif

/***** Configuration data structure: *****/

struct config {
  int daemonize;
  const char *pid_file;

  const char *hostname;
  in_port_t port;
  int backlog;

  const char *user;

  size_t num_workers;

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
 * Write the specified number of bytes to the given file descriptor, retrying
 * when interrupted.
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
