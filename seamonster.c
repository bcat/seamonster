#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <magic.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* Default configuration options: */

#define DEFAULT_DAEMONIZE 0
#define DEFAULT_PID_FILE  "/var/run/seamonster.pid"
#define DEFAULT_HOSTNAME  "localhost"
#define DEFAULT_PORT      70
#define DEFAULT_BACKLOG   256
#define DEFAULT_USER      "nobody"
#define DEFAULT_WORKERS   4
#define DEFAULT_SRV_PATH  "/srv/gopher"

/* Buffer sizes and other magic numbers: */

#ifndef OPEN_MAX
# define OPEN_MAX         1024
#endif

#ifndef PIPE_BUF
# define PIPE_BUF         _POSIX_PIPE_BUF
#endif

#define PID_FILE_MODE     (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#define LOG_BUF_SIZE      PIPE_BUF
#define REQUEST_BUF_SIZE  PIPE_BUF
#define RESPONSE_BUF_SIZE PIPE_BUF
#define DIRENTRY_BUF_SIZE 592

static const int ONE = 1;

/* Gopher protocol strings: */

#define RESPONSE_EOM      ".\r\n"
#define RESPONSE_ERR      "3Error reading resource\tinvalid.invalid\t70\r\n"

/* Gopher item type characters: */

#define ITEM_TYPE_TXT     '0'
#define ITEM_TYPE_DIR     '1'
#define ITEM_TYPE_BIN     '9'
#define ITEM_TYPE_GIF     'g'
#define ITEM_TYPE_HTM     'h'
#define ITEM_TYPE_IMG     'I'

/* Command line options: */

#define OPT_HELP          '\0'
#define OPT_VERSION       '\1'
#define OPT_DAEMONIZE     'd'
#define OPT_PID_FILE      'P'
#define OPT_HOST          'h'
#define OPT_PORT          'p'
#define OPT_BACKLOG       'b'
#define OPT_USER          'u'
#define OPT_WORKERS       'w'
#define OPT_SRV_PATH      's'

#define OPTSTRING         "dP:h:p:b:u:w:s:"

static const struct option LONGOPTS[] = {
  { "help",      0, NULL, OPT_HELP },
  { "version",   0, NULL, OPT_VERSION },
  { "daemonize", 0, NULL, OPT_DAEMONIZE },
  { "pid-file",  1, NULL, OPT_PID_FILE },
  { "host",      1, NULL, OPT_HOST },
  { "port",      1, NULL, OPT_PORT },
  { "backlog",   1, NULL, OPT_BACKLOG },
  { "user",      1, NULL, OPT_USER },
  { "workers",   1, NULL, OPT_WORKERS },
  { "srv-path",  1, NULL, OPT_SRV_PATH },
  { 0 }
};

/* Documentation: */

#define VERSION           "seamonster 0.1 / A tiny hack of a Gopher " \
                              "server\n" \
                          "Copyright (C) 2011 Jonathan Rascher\n\n" \
                          "    May your love reach to the sky\n" \
                          "    May your sun be always bright\n" \
                          "    May hope guide you\n" \
                          "    Your best dreams come true\n" \
                          "    When we reach out to the sun\n" \
                          "    When you and I are one\n" \
                          "    My heart is true\n" \
                          "    Let love cover you\n" \
                          "--- \"Seamonster\" by the violet burning\n"

#define USAGE             "Usage: %s [options]\n\n"
#define USAGE_HELP        "Try %s --help for more information\n"

/* Forwards declarations: */

int main(int argc, char **argv);

static int r_close(int fildes);
static int r_open(const char *path, int oflag, ...);
static ssize_t r_read(int fildes, void *buf, size_t nbyte);
static ssize_t r_write(int fildes, const void *buf, size_t nbyte);
static int r_accept(int socket, struct sockaddr *address,
    socklen_t *address_len);

static int asprintf(char **p_s, const char *format, ...);
static int vasprintf(char **p_s, const char *format, va_list va);

static void log_msg(int pri, const char *addr_str, const char *format,
    va_list varargs);
static void log_info(const char *addr_str, const char *format, ...);
static void log_warn(const char *addr_str, const char *format, ...);
static void log_error(const char *addr_str, const char *format, ...);
static void log_perror(const char *addr_str, const char *s);

static void sigterm_handler(int signum);
static void delete_pid_file(void);

static int parse_config(int argc, char **argv);

static int daemonize();

static int create_passive_sock();

static int drop_privs();

static pid_t *create_workers(int passive_sock);
static pid_t start_worker(int passive_sock);

static char **parse_request(int sock);
static void free_request(const char *const *request);

static int sanitize_path(const char *in_path, char **out_path);
static char get_item_type(const char *path);

static const char *serve_file(const char *path, int sock,
    const char *addr_str, int is_txt);

static int menu_filter(const struct dirent *p_dirent);
static int menu_sort(const struct dirent **pp_dirent1,
    const struct dirent **pp_dirent2);
static const char *serve_menu(const char *path, int sock,
    const char *addr_str);

static void handle_conn(int sock, const char *addr_str);

static int worker_main(int passive_sock);

/* Global variables: */

static volatile sig_atomic_t terminating;

static pid_t server_pid;

static struct {
  int daemonize;
  const char *pid_file;

  const char *hostname;
  short port;
  in_port_t backlog;

  const char *user;

  size_t num_workers;

  const char *srv_path;
} config;

/*
 * Close the specified file descriptor, retrying when interrupted.
 *
 * Returns 0 on success and -1 on error.
 */
int r_close(int fildes) {
  int ret;
  while ((ret = close(fildes)) == -1 && errno == EINTR);
  return ret;
}

/*
 * Open the file at the specified path with all the usual flag and mode
 * choices, retrying when interrupted.
 *
 * Returns the newly-opened file descriptor on success and -1 on error.
 */
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

/*
 * Read at most the specified number of bytes from the given file descriptor,
 * retrying when interrupted.
 *
 * Returns the number of bytes read on success and -1 on error.
 */
ssize_t r_read(int fildes, void *buf, size_t nbytes) {
  ssize_t ret;
  while ((ret = read(fildes, buf, nbytes)) == -1 && errno == EINTR);
  return ret;
}

/*
 * Write the specified number of bytes to the given file descriptor, retrying
 * when interrupted.
 *
 * Returns the total number of bytes written on success and -1 on error.
 */
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

int r_accept(int socket, struct sockaddr *address, socklen_t *address_len) {
  int ret;
  while ((ret = accept(socket, address, address_len)) == -1
      && errno == EINTR);
  return ret;
}

/*
 * Write formatted data into a dynamically allocated string whose address will
 * be stored in the specified memory location.
 *
 * Returns the length of the newly-allocated string on success and a negative
 * value on failure.
 */
int asprintf(char **p_s, const char *format, ...) {
  va_list varargs;
  int ret;

  va_start(varargs, format);
  ret = vasprintf(p_s, format, varargs);
  va_end(varargs);

  return ret;
}

/*
 * Write formatted data from the given varargs list into a dynamically
 * allocated string whose address will be stored in the specified memory
 * location.
 *
 * Returns the length of the newly-allocated string on success and a negative
 * value on failure.
 */
int vasprintf(char **p_s, const char *format, va_list va) {
  int ret;
  char *s;

  if ((ret = vsnprintf(NULL, 0, format, va)) < 0) {
    return ret;
  }

  if (!(s = malloc(ret + 1))) {
    return -1;
  }

  if ((ret = vsnprintf(s, ret + 1, format, va)) < 0) {
    free(s);
    return ret;
  }

  *p_s = s;
  return ret;
}

/*
 * Log a formatted message with the specified priority and optionally the
 * specified IP address.
 */
void log_msg(int pri, const char *addr_str, const char *format,
    va_list varargs) {
  char buf[LOG_BUF_SIZE], *buf_next = buf;
  int buf_size = sizeof(buf), str_size;

  if (addr_str) {
    if ((str_size = snprintf(buf_next, buf_size, "%s - ", addr_str)) == -1) {
      return;
    }
    buf_next += (str_size < buf_size) ? str_size : buf_size;
    buf_size -= (str_size < buf_size) ? str_size : buf_size;
  }

  if ((str_size = vsnprintf(buf_next, buf_size, format, varargs)) == -1) {
    return;
  }
  buf_next += (str_size < buf_size) ? str_size : buf_size;

  syslog(pri, "%s", buf);
}

/*
 * Log a formatted message at INFO priority, optionally including the
 * specified IP address.
 */
void log_info(const char *addr_str, const char *format, ...) {
  va_list varargs;

  va_start(varargs, format);
  log_msg(LOG_INFO, addr_str, format, varargs);
  va_end(varargs);
}

/*
 * Log a formatted message at WARNING priority, optionally including the
 * specified IP address.
 */
void log_warn(const char *addr_str, const char *format, ...) {
  va_list varargs;

  va_start(varargs, format);
  log_msg(LOG_WARNING, addr_str, format, varargs);
  va_end(varargs);
}

/*
 * Log a formatted message at ERR priority, optionally including the
 * specified IP address.
 */
void log_error(const char *addr_str, const char *format, ...) {
  va_list varargs;

  va_start(varargs, format);
  log_msg(LOG_ERR, addr_str, format, varargs);
  va_end(varargs);
}

/*
 * Log a message associated with the current value of errno at ERR priority,
 * optionally including the specified IP address.
 */
void log_perror(const char *addr_str, const char *s) {
  log_error(addr_str, "%s: %s", s, strerror(errno));
}

/*
 * Respond to SIGTERM by setting a termination flag.
 */
void sigterm_handler(int signum) {
  if (!terminating) {
    terminating = 1;
  }
}

/*
 * Delete PID file (if running as a daemon) when the server exits normally.
 */
void delete_pid_file(void) {
  if (getpid() == server_pid && config.daemonize) {
    unlink(config.pid_file);
  }
}

/*
 * Parse command line arguments into the global config.
 *
 * Returns 0 on success and -1 on error or if a help/version option has been
 * provided. If an invalid option is provided, errno will be set to EINVAL.
 */
int parse_config(int argc, char **argv) {
  int opt;
  long optnum;

  config.daemonize = DEFAULT_DAEMONIZE;
  config.port = DEFAULT_PORT;
  config.backlog = DEFAULT_BACKLOG;
  config.num_workers = DEFAULT_WORKERS;

  while ((opt = getopt_long(argc, argv, OPTSTRING, LONGOPTS, NULL)) != -1) {
    switch (opt) {
    case OPT_HELP:
      /* TODO: Print out help documentation. */
      return -1;

    case OPT_VERSION:
      fprintf(stderr, "%s", VERSION);
      return -1;

    case OPT_HOST:
      free((char *) config.hostname);
      if (!(config.hostname = strdup(optarg))) {
        perror("Couldn't allocate hostname string");
        return -1;
      }
      break;

    case OPT_PORT:
      errno = 0;
      optnum = strtol(optarg, NULL, 10);
      if (errno) {
        perror("Couldn't parse port number");
        return -1;
      }

      if (optnum < 1 || optnum > 65535) {
        fprintf(stderr, "Port number is out of range\n");
        errno = EINVAL;
        return -1;
      }

      config.port = (in_port_t) optnum;
      break;

    case OPT_BACKLOG:
      errno = 0;
      optnum = strtol(optarg, NULL, 10);
      if (errno) {
        perror("Couldn't parse backlog size");
        return -1;
      }

      if (optnum < INT_MIN || optnum > INT_MAX) {
        fprintf(stderr, "Backlog size is out of range\n");
        errno = EINVAL;
        return -1;
      }

      config.backlog = (int) strtol(optarg, NULL, 10);
      break;

    case OPT_USER:
      free((char *) config.user);
      if (!(config.user = strdup(optarg))) {
        perror("Couldn't allocate user string");
        return -1;
      }
      break;

    case OPT_DAEMONIZE:
      config.daemonize = 1;
      break;

    case OPT_PID_FILE:
      free((char *) config.pid_file);
      if (!(config.pid_file = strdup(optarg))) {
        perror("Couldn't allocate PID file string");
        return -1;
      }
      break;

    case OPT_WORKERS:
      errno = 0;
      optnum = strtol(optarg, NULL, 10);
      if (errno) {
        perror("Couldn't parse number of workers");
        return -1;
      }

      if (optnum < 0 || optnum > SIZE_MAX) {
        fprintf(stderr, "Number of workers is out of range\n");
        errno = EINVAL;
        return -1;
      }

      config.num_workers = (size_t) optnum;
      break;

    case OPT_SRV_PATH:
      free((char *) config.srv_path);
      if (!(config.srv_path = strdup(optarg))) {
        perror("Couldn't allocate service path string");
        return -1;
      }
      break;

    default:
      fprintf(stderr, USAGE, argv[0]);
      fprintf(stderr, USAGE_HELP, argv[0]);
      errno = EINVAL;
      return -1;
    }
  }

  if ((!config.pid_file && !(config.pid_file = strdup(DEFAULT_PID_FILE)))
      || (!config.hostname && !(config.hostname = strdup(DEFAULT_HOSTNAME)))
      || (!config.user && !(config.user = strdup(DEFAULT_USER)))) {
    perror("Couldn't copy default configuration string");
    return -1;
  }

  if (!(config.srv_path = realpath(config.srv_path
          ? config.srv_path : DEFAULT_SRV_PATH, NULL))) {
    perror("Couldn't find absolute service path");
    return -1;
  }

  return 0;
}

/*
 * Run as a daemon.
 *
 * Based on Section 13.3 in _Advanced Programming in the UNIX Environment_ by
 * Stevens.
 */
int daemonize() {
  char *pid_str = NULL;
  int ret = 0, i, open_max, pid_fd = -1;

  /* Fork once to make sure we're not a process group leader. */
  switch (fork()) {
  case -1:
    log_perror(NULL, "Couldn't fork process when daemonizing");
    ret = -1;
    goto cleanup;

  case 0:
    break;

  default:
    _exit(0);
  }

  /* Become the leader of a new session and process group, and change to the
   * root directory. */
  if (setsid() == -1) {
    log_perror(NULL, "Couldn't become a session leader");
    ret = -1;
    goto cleanup;
  }

  if (chdir("/")) {
    log_perror(NULL, "Couldn't change to root directory");
    ret = -1;
    goto cleanup;
  }

  /* Fork again so that we aren't a process group leader anymore, preventing
   * us from acquiring a controlling terminal. */
  switch (fork()) {
  case -1:
    log_perror(NULL, "Couldn't fork process when daemonizing");
    ret = -1;
    goto cleanup;

  case 0:
    break;

  default:
    _exit(0);
  }

  /* Record our new server PID. */
  server_pid = getpid();

  /* Set a permissive file mode mask. */
  umask(0);

  /* Create a PID file, and prepare to delete it on exit. */
  if ((pid_fd = r_open(config.pid_file, O_WRONLY | O_CREAT | O_EXCL,
          PID_FILE_MODE)) == -1) {
    log_perror(NULL, "Couldn't create PID file for writing");
    ret = -1;
    goto cleanup;
  }

  if (asprintf(&pid_str, "%ld\n", (long) server_pid) < 0) {
    log_perror(NULL, "Couldn't allocate PID string");
    ret = -1;
    goto cleanup;
  }

  if (r_write(pid_fd, pid_str, strlen(pid_str)) == -1) {
    log_perror(NULL, "Couldn't write to PID file");
    ret = -1;
    goto cleanup;
  }

  atexit(delete_pid_file);

  /* Close all (possibly) open files. */
  errno = 0;
  if ((open_max = (int) sysconf(_SC_OPEN_MAX)) == -1 && errno) {
    log_perror(NULL, "Couldn't determine maximum file descriptor");
    ret = -1;
    goto cleanup;
  }

  for (i = 0; i < ((open_max != -1) ? open_max : OPEN_MAX); ++i) {
    if (r_close(i) == -1 && errno != EBADF) {
      log_perror(NULL, "Couldn't close file descriptor when daemonizing");
      ret = -1;
      goto cleanup;
    }
  }

  /* Reopen stdin, stdout, and stderr, redirecting them to /dev/null. */
  if (r_open("/dev/null", O_RDONLY) != STDIN_FILENO
      || r_open("/dev/null", O_WRONLY) != STDOUT_FILENO
      || dup(STDOUT_FILENO) != STDERR_FILENO) {
    log_perror(NULL, "Couldn't redirect standard streams to /dev/null");
    ret = -1;
    goto cleanup;
  }

cleanup:
  r_close(pid_fd);
  free(pid_str);

  if (ret == -1 && pid_fd != -1) {
    unlink(config.pid_file);
  }

  return ret;
}

/*
 * Create a passive socket to listen for incoming connections.
 */
int create_passive_sock() {
  int sock;
  struct sockaddr_in addr = { 0 };

  addr.sin_family = AF_INET;
  addr.sin_port = htons(config.port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    log_perror(NULL, "Couldn't create passive socket");
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE))) {
    log_perror(NULL, "Couldn't enable port reuse on passive socket");
    return -1;
  }

  if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
    log_perror(NULL, "Couldn't bind passive socket");
    return -1;
  }

  if (listen(sock, config.backlog)) {
    log_perror(NULL, "Couldn't put passive socket in listening mode");
    return -1;
  }

  return sock;
}

/*
 * Drop root privileges and run as the user specified in the server
 * configuration.
 *
 * Returns 0 on success and -1 on error.
 */
int drop_privs() {
  struct passwd *p_passwd;

  errno = 0;
  if (!(p_passwd = getpwnam(config.user))) {
    if (errno) {
      log_perror(NULL, "Couldn't read password file");
    } else {
      log_error(NULL, "User does not exist");
    }
    return -1;
  }

  if (setgid(p_passwd->pw_gid)) {
    log_perror(NULL, "Couldn't change group");
    return -1;
  }

  if (setgroups(0, NULL)) {
    log_perror(NULL, "Couldn't remove supplementary groups");
    return -1;
  }

  if (setuid(p_passwd->pw_uid)) {
    log_perror(NULL, "Couldn't change user");
    return -1;
  }

  return 0;
}

/*
 * Start the number of worker processes requested in the server
 * configuration.
 *
 * Returns a pointer to an array of PIDs on success and NULL on error.
 */
pid_t *create_workers(int passive_sock) {
  size_t i, j;
  pid_t *pids = malloc(config.num_workers * sizeof(pid_t));

  if (!pids) {
    log_perror(NULL, "Couldn't allocate array to store worker PIDs");
    return NULL;
  }

  for (i = 0; i < config.num_workers; ++i) {
    if ((pids[i] = start_worker(passive_sock)) == -1) {
      log_perror(NULL, "Couldn't fork worker to handle connections");
      for (j = 0; i < i; ++j) {
        kill(pids[j], SIGTERM);
      }
      return NULL;
    }
  }

  return pids;
}

/*
 * Fork a new worker process to handle connections to the specified passive
 * socket.
 *
 * Returns the PID of the new worker on success and -1 on error.
 */
pid_t start_worker(int passive_sock) {
  pid_t pid;

  if (!(pid = fork())) {
    exit(worker_main(passive_sock));
  }

  return pid;
}

/*
 * Parse a tab-delimited Gopher request.
 *
 * Returns a pointer to an array of strings representing the tab-delimited
 * request fields on success and NULL on error.
 */
char **parse_request(int sock) {
  int done = 0;
  size_t i, num_chunks = 1;
  char *buf_start = NULL, *buf_next = NULL, *buf_end = NULL, **request;

  do {
    ssize_t recv_size;

    if (buf_next == buf_end) {
      size_t data_size = buf_next - buf_start, buf_size;

      buf_size = buf_start ? buf_end - buf_start : REQUEST_BUF_SIZE;

      if (!(buf_start = realloc(buf_start, buf_size * 2))) {
        return NULL;
      }

      buf_next = buf_start + data_size;
      buf_end = buf_start + buf_size * 2;
    }

    recv_size = r_read(sock, buf_next, buf_end - buf_next);

    if (recv_size == -1) {
      free(buf_start);
      return NULL;
    }

    switch(recv_size) {
    case -1:
      free(buf_start);
      return NULL;

    case 0:
      free(buf_start);
      num_chunks = 0;
      done = 1;
      break;

    default:
      do {
        switch (*buf_next++) {
        case '\t':
          ++num_chunks;
          break;

        case '\r':
          *(buf_next - 1) = '\0';
          done = 1;
        }
      } while (--recv_size && !done);
    }
  } while (!done);

  if (!(request = malloc((num_chunks + 1) * sizeof(*request)))) {
    free(buf_start);
    return NULL;
  }

  for (i = 0; i < num_chunks; ++i) {
    request[i] = buf_start;
    buf_start = strchr(buf_start, '\t');

    if (buf_start) {
      *buf_start++ = '\0';
    }
  }

  request[num_chunks] = NULL;

  return request;
}

/*
 * Free the resources associated with a parsed Gopher request.
 */
void free_request(const char *const *request) {
  if (request) {
    free((char *) *request);
  }
  free((const char **) request);
}

/*
 * Sanitize the given path by converting it to an absolute path which must be
 * rooted in the path specified in the server configuration.
 *
 * Returns 0 on success and -1 on error. If the path referred to by in_path
 * lies within the srv_path hierarchy, then the out_path will be reassigned to
 * point to reference the sanitized (absolute) path. If in_path refers to an
 * invalid location, then out_put will be assigned a NULL pointer.
 */
int sanitize_path(const char *in_path, char **out_path) {
  if (!(*out_path = realpath(in_path, NULL))) {
    return -1;
  }

  if (strstr(*out_path, config.srv_path) != *out_path) {
    free(*out_path);
    *out_path = NULL;
  }

  return 0;
}

/*
 * Return the Gopher protocol item type character associated with the
 * specified path, using the magic library to differentiate text files,
 * images, and arbitrary binary files.
 *
 * Returns a Gopher item type character on success and '\0' on error.
 */
char get_item_type(const char *path) {
  char item_type = ITEM_TYPE_BIN;
  const char *mime_type = NULL;
  struct stat path_stat;
  magic_t cookie = NULL;

  if (stat(path, &path_stat)) {
    goto cleanup;
  }

  if (S_ISDIR(path_stat.st_mode)) {
    item_type = ITEM_TYPE_DIR;
    goto cleanup;
  }

  if (!(cookie = magic_open(MAGIC_MIME_TYPE))
      || magic_load(cookie, NULL)
      || !(mime_type = magic_file(cookie, path))) {
    item_type = '\0';
    goto cleanup;
  }

  if (strstr(mime_type, "text/") == mime_type) {
    item_type = !strcmp(mime_type + sizeof("text/") - 1, "html")
        ? ITEM_TYPE_HTM
        : ITEM_TYPE_TXT;
  } else if (strstr(mime_type, "image/") == mime_type) {
    item_type = !strcmp(mime_type + sizeof("image/") - 1, "gif")
        ? ITEM_TYPE_GIF
        : ITEM_TYPE_IMG;
  }

cleanup:
  if (cookie) {
    magic_close(cookie);
  }

  return item_type;
}

/*
 * Serve a Gopher protocol file response (text or binary, as specified) to the
 * given socket.
 *
 * Returns NULL on success and a Gopher error response on failure.
 */
const char *serve_file(const char *path, int sock, const char *addr_str,
    int is_txt) {
  const char *err_msg = NULL;
  char buf[RESPONSE_BUF_SIZE];
  ssize_t data_size;
  int file;

  while ((file = open(path, O_RDONLY)) == -1 && errno == EINTR);

  if (file == -1) {
    log_perror(addr_str, "Couldn't open resource");
    err_msg = RESPONSE_ERR;
    goto cleanup;
  }

  while ((data_size = r_read(file, buf, sizeof(buf)))) {
    if (data_size == -1) {
      log_perror(addr_str, "Couldn't read resource");
      err_msg = RESPONSE_ERR;
      goto cleanup;
    }

    if (r_write(sock, buf, data_size) == -1) {
      log_perror(addr_str, "Couldn't send resource to client");
      goto cleanup;
    }
  }

  if (is_txt) {
    if (r_write(sock, RESPONSE_EOM, sizeof(RESPONSE_EOM)) == -1) {
      log_perror(addr_str, "Couldn't send resource to client");
      goto cleanup;
    }
  }

cleanup:
  r_close(file);

  return err_msg;
}

/*
 * scandir filter for generating Gopher menu responses. The current directory
 * entry (.) will be filtered out, as will directory entries whose names
 * contain characters that are not valid in Gopher menu responses.
 */
int menu_filter(const struct dirent *p_dirent) {
  const char *name = p_dirent->d_name;
  char ch;

  if (name[0] == '.' && name[1] == '\0') {
    return 0;
  }

  while ((ch = *name++)) {
    if (ch == '\t' || ch == '\r' || ch == '\n') {
      return 0;
    }
  }

  return 1;
}

/*
 * scandir sort function for generating Gopher menu responses. The parent
 * directory entry (..) is always sorted first, and the remaining directory
 * entries are ordered according to strcoll.
 */
int menu_sort(const struct dirent **pp_dirent1,
    const struct dirent **pp_dirent2) {
  const char *name1 = (*pp_dirent1)->d_name, *name2 = (*pp_dirent2)->d_name;

  if (!strcmp(name1, "..")) {
    return !!strcmp(name2, "..");
  } else {
    return strcoll(name1, name2);
  }
}

/*
 * Serve a Gopher protocol menu response to the given socket.
 *
 * Returns NULL on success and a Gopher error response on failure.
 */
const char *serve_menu(const char *path, int sock, const char *addr_str) {
  const char *err_msg = NULL;
  char item_type;
  struct dirent **p_dirents = NULL;
  int num_dirents;

  if ((num_dirents = scandir(path, &p_dirents, menu_filter, menu_sort))
      == -1) {
    log_perror(addr_str, "Couldn't scan resource directory");
    err_msg = RESPONSE_ERR;
    goto cleanup;
  }

  while (num_dirents-- && !err_msg) {
    const char *file_name = p_dirents[num_dirents]->d_name;
    int direntry_size;
    char *file_path = NULL, *sanitized_path = NULL,
         direntry_buf[DIRENTRY_BUF_SIZE];

    if (!(file_path = malloc(strlen(path) + strlen(file_name) + 2))) {
      log_perror(addr_str, "Couldn't allocate file path");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    strcpy(file_path, path);
    strcat(file_path, "/");
    strcat(file_path, file_name);

    if (sanitize_path(file_path, &sanitized_path)) {
      log_perror(addr_str, "Couldn't sanitize file path");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if (!sanitized_path) {
      goto inner_cleanup;
    }

    if (!(item_type = get_item_type(sanitized_path))) {
      log_perror(addr_str, "Couldn't determine item type");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if ((direntry_size = snprintf(
            direntry_buf,
            sizeof(direntry_buf),
            "%c%.70s\t%.255s\t%.255s\t%hd\r\n",
            item_type,
            file_name,
            sanitized_path + strlen(config.srv_path),
            config.hostname,
            config.port)) == -1) {
      log_perror(addr_str, "Couldn't format menu entry");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if (r_write(sock, direntry_buf, direntry_size) == -1) {
      log_perror(addr_str, "Couldn't send menu entry to client");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

  inner_cleanup:
    free(file_path);
    free(sanitized_path);
    free(p_dirents[num_dirents]);
  }

  if (r_write(sock, RESPONSE_EOM, sizeof(RESPONSE_EOM)) == -1) {
    log_perror(addr_str, "Couldn't send resource to client");
    goto cleanup;
  }

cleanup:
  free(p_dirents);

  return err_msg;
}

/*
 * Handle an incoming connection with the specified socket and IP address.
 */
void handle_conn(int sock, const char *addr_str) {
  const char *const *request = NULL, *const *request_iter, *selector,
        *err_msg = NULL;
  char *path = NULL, *sanitized_path = NULL, item_type;

  if (!(request_iter = request = (const char *const *) parse_request(sock))) {
    log_perror(addr_str, "Couldn't read or parse request");
    goto cleanup;
  }

  if (!(selector = *request_iter++)) {
    log_error(addr_str, "Request does not contain a selector");
    goto cleanup;
  }

  if (!(path = malloc(strlen(config.srv_path) + strlen(selector) + 2))) {
    log_perror(addr_str, "Couldn't allocate resource path");
    goto cleanup;
  }

  strcpy(path, config.srv_path);
  strcat(path, "/");
  strcat(path, selector);

  if (sanitize_path(path, &sanitized_path)) {
    log_perror(addr_str, "Couldn't sanitize resource path");
    err_msg = RESPONSE_ERR;
    goto cleanup;
  }

  log_info(addr_str, "Accepted request for `%s` (%s)", selector,
      sanitized_path ? sanitized_path : "forbidden");

  if (!sanitized_path) {
    err_msg = RESPONSE_ERR;
    goto cleanup;
  }

  if (!(item_type = get_item_type(sanitized_path))) {
    log_perror(addr_str, "Couldn't determine item type");
    err_msg = RESPONSE_ERR;
    goto cleanup;
  }

  err_msg = (item_type == ITEM_TYPE_DIR)
      ? serve_menu(sanitized_path, sock, addr_str)
      : serve_file(sanitized_path, sock, addr_str,
          item_type == ITEM_TYPE_TXT);

  if (*request_iter) {
    log_warn(addr_str, "Request contains unexpected element");
  }

cleanup:
  if (err_msg) {
    r_write(sock, err_msg, strlen(err_msg));
    r_write(sock, RESPONSE_EOM, sizeof(RESPONSE_EOM));
  }

  free(sanitized_path);
  free(path);
  free_request(request);
}

/*
 * Main worker process code.
 */
int worker_main(int passive_sock) {
  struct sigaction sig = { 0 };

  /* Print a message containing the worker's PID. */
  log_info(NULL, "Spawned worker process");

  /* Ignore SIGPIPE so the worker doesn't die if the client closes the
   * connection prematurely. */
  sig.sa_handler = SIG_IGN;

  if (sigaction(SIGPIPE, &sig, NULL)) {
    log_perror(NULL, "Couldn't ignore SIGPIPE");
    return 1;
  }

  /* Make sure worker processes don't run as root. */
  if (!getuid()) {
    if (drop_privs()) {
      return 1;
    }

    log_info(NULL, "Dropped root privileges; running as %s", config.user);
  }

  /* Process connections until we're asked to terminate cleanly. */
  while (!terminating) {
    int conn_sock;
    struct sockaddr_in addr;
    socklen_t addr_buf = sizeof(addr);
    char addr_str[INET_ADDRSTRLEN];

    /* Accept an incoming connection request. */
    if ((conn_sock = r_accept(passive_sock, (struct sockaddr *)&addr,
            &addr_buf)) == -1) {
      log_perror(NULL, "Couldn't accept connection request");
      return 1;
    }

    /* Format the client's IP address as a string. */
    if (!inet_ntop(AF_INET, &addr.sin_addr, addr_str, sizeof(addr_str))) {
      log_perror(NULL, "Couldn't format remote IP address");
      return 1;
    }

    /* Handle the new client connection. */
    handle_conn(conn_sock, addr_str);

    /* Close the client connection's socket. */
    if (r_close(conn_sock)) {
      log_perror(addr_str, "Couldn't close connection socket");
    }
  }

  return 0;
}

/*
 * Main server process code.
 */
int main(int argc, char **argv) {
  int passive_sock = -1;
  struct sigaction sig = { 0 };
  pid_t *worker_pids = NULL;

  /* Record out PID for future reference. */
  server_pid = getpid();

  /* Set up logging. */
  openlog("seamonster", LOG_PERROR | LOG_PID, LOG_DAEMON);

  /* Set up signal handling. */
  sig.sa_handler = sigterm_handler;

  if (sigaction(SIGTERM, &sig, NULL)) {
    perror("Couldn't set SIGTERM handler\n");
    return 1;
  }

  /* Parse command line arguments. */
  errno = 0;
  if (parse_config(argc, argv)) {
    return !!errno;
  }

  /* If requested, run as a daemon and set up logging. */
  if (config.daemonize && daemonize()) {
    return 1;
  }

  /* Create a passive socket to listen for connection requests. */
  if ((passive_sock = create_passive_sock()) == -1) {
    return 1;
  }

  log_info(NULL, "Listening on port %hd", config.port);

  /* Fork off some children to handle clients. */
  log_info(NULL, "Starting with %lu workers",
      (unsigned long) config.num_workers);

  if (!(worker_pids = create_workers(passive_sock))) {
    return 1;
  }

  /* Kill all workers on when the parent terminates cleanly, and restart any
   * workers that die prematurely. */
  for (;;) {
    size_t i;
    pid_t worker_pid;
    int stat_loc;

    /* On SIGTERM, kill all the workers processes. */
    if (terminating == 1) {
      log_info(NULL, "Killing workers on SIGTERM");

      for (i = 0; i < config.num_workers; ++i) {
        if (worker_pids[i] != -1) {
          kill(worker_pids[i], SIGTERM);
        }
      }

      terminating = 2;
    }

    /* Wait for something to happen to a worker. (If there are no more workers
     * to wait for, then we're done.) */
    if ((worker_pid = wait(&stat_loc)) == -1) {
      if (errno == ECHILD) {
        break;
      }

      if (errno == EINTR) {
        continue;
      }

      log_perror(NULL, "Couldn't wait for workers to die");
      return 1;
    }

    /* If we aren't currently terminating, then we should restart workers when
     * they die. */
    if (!terminating && (WIFEXITED(stat_loc) || WIFSIGNALED(stat_loc))) {
      log_warn(NULL, "Worker %ld died; restarting", (long) worker_pid);

      for (i = 0; i < config.num_workers; ++i) {
        if (worker_pids[i] == worker_pid) {
          if ((worker_pids[i] = start_worker(passive_sock)) == -1) {
            log_perror(NULL, "Couldn't restart worker");
          }

          break;
        }
      }
    }
  }

  return 0;
}
