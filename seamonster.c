#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <grp.h>
#include <magic.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
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

#define REQUEST_BUF_SIZE  256
#define RESPONSE_BUF_SIZE 4096
#define DIRENTRY_BUF_SIZE 592

static const int ONE = 1;

/* Gopher protocol strings: */

#define RESPONSE_EOM      ".\r\n"
#define RESPONSE_ERR_OPEN "3Error opening resource\tinvalid.invalid\t70\r\n"
#define RESPONSE_ERR_READ "3Error reading resource\tinvalid.invalid\t70\r\n"

/* Gopher item type characters: */

#define ITEM_TYPE_TXT      '0'
#define ITEM_TYPE_DIR      '1'
#define ITEM_TYPE_BIN      '9'
#define ITEM_TYPE_GIF      'g'
#define ITEM_TYPE_HTM      'h'
#define ITEM_TYPE_IMG      'I'

/* Command line options: */

#define OPT_HELP           '\0'
#define OPT_VERSION        '\1'
#define OPT_DAEMON         'd'
#define OPT_HOST           'h'
#define OPT_PORT           'p'
#define OPT_BACKLOG        'b'
#define OPT_USER           'u'
#define OPT_WORKERS        'w'
#define OPT_SRV_PATH       's'

#define OPTSTRING          "dh:p:b:u:w:s:"

static const struct option LONGOPTS[] = {
  { "help",     0, NULL, OPT_HELP },
  { "version",  0, NULL, OPT_VERSION },
  { "daemon",   0, NULL, OPT_DAEMON },
  { "host",     1, NULL, OPT_HOST },
  { "port",     1, NULL, OPT_PORT },
  { "backlog",  1, NULL, OPT_BACKLOG },
  { "user",     1, NULL, OPT_USER },
  { "workers",  1, NULL, OPT_WORKERS },
  { "srv-path", 1, NULL, OPT_SRV_PATH },
  { 0 }
};

/* Usage information and help: */

#define USAGE              "Usage: %s [options]\n\n"
#define USAGE_HELP         "Try %s --help for more information\n"

/* Forwards declarations: */

int main(int argc, char **argv);

static int r_close(int fildes);
static int r_open(const char *path, int oflag, ...);
static ssize_t r_read(int fildes, void *buf, size_t nbyte);
static ssize_t r_write(int fildes, const void *buf, size_t nbyte);

static void log_msg(int pri, const char *addr_str, const char *format,
    va_list varargs);
static void log_info(const char *addr_str, const char *format, ...);
static void log_warn(const char *addr_str, const char *format, ...);
static void log_error(const char *addr_str, const char *format, ...);
static void log_perror(const char *addr_str, const char *s);

static void sigterm_handler(int signum);

static int parse_config(int argc, char **argv);
static void free_config();

static int daemonize();

static int create_passive_sock();
static void dispose_passive_sock(int sock);

static int drop_privs();

static pid_t *create_workers(int passive_sock);
static pid_t start_worker(int passive_sock);
static void dispose_workers(const pid_t *pids);

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

static struct {
  int should_daemonize;

  const char *hostname;
  short port;
  int backlog;

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

/*
 * Log a formatted message with the specified priority and optionally the
 * specified IP address.
 */
void log_msg(int pri, const char *addr_str, const char *format,
    va_list varargs) {
  char buf[PIPE_BUF], *buf_next = buf;
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
 * Parse command line arguments into the global config.
 *
 * Returns 0 on success and -1 on error.
 */
int parse_config(int argc, char **argv) {
  int opt;

  config.port = DEFAULT_PORT;
  config.backlog = DEFAULT_BACKLOG;
  config.num_workers = DEFAULT_WORKERS;

  while ((opt = getopt_long(argc, argv, OPTSTRING, LONGOPTS, NULL)) != -1) {
    switch (opt) {
    case OPT_HELP:
      break;

    case OPT_VERSION:
      break;

    case OPT_HOST:
      free((char *) config.hostname);
      if (!(config.hostname = strdup(optarg))) {
        free_config();
        return -1;
      }
      break;

    case OPT_PORT:
      config.port = (short) strtol(optarg, NULL, 10);
      break;

    case OPT_BACKLOG:
      config.backlog = (short) strtol(optarg, NULL, 10);
      break;

    case OPT_USER:
      free((char *) config.user);
      if (!(config.user = strdup(optarg))) {
        free_config();
        return -1;
      }
      break;

    case OPT_DAEMON:
      config.should_daemonize = 1;
      break;

    case OPT_WORKERS:
      config.num_workers = (short) strtol(optarg, NULL, 10);
      break;

    case OPT_SRV_PATH:
      free((char *) config.srv_path);
      if (!(config.srv_path = strdup(optarg))) {
        free_config();
        return -1;
      }
      break;

    default:
      fprintf(stderr, USAGE, argv[0]);
      fprintf(stderr, USAGE_HELP, argv[0]);

      free_config();
      return -1;
    }
  }

  if ((!config.hostname
          && !(config.hostname = strdup(DEFAULT_HOSTNAME)))
      || (!config.user && !(config.user = strdup(DEFAULT_USER)))
      || (!(config.srv_path = realpath(config.srv_path
          ? config.srv_path : DEFAULT_SRV_PATH, NULL)))) {
    free_config();
    return -1;
  }

  return 0;
}

/*
 * Free config global members.
 */
void free_config() {
  free((void *) config.hostname);
  free((void *) config.user);
  free((void *) config.srv_path);
}

/*
 * Run as a daemon.
 *
 * Based on Section 13.3 in _Advanced Programming in the UNIX Environment_ by
 * Stevens.
 */
int daemonize() {
  int i, open_max;

  /* Fork once to make sure we're not a process group leader. */
  switch (fork()) {
  case -1:
    return -1;

  case 0:
    break;

  default:
    _exit(0);
  }

  /* Become the leader of a new session and process group, and change to the
   * root directory. */
  if (setsid() == -1 || chdir("/")) {
    return -1;
  }

  /* Fork again so that we aren't a process group leader anymore, preventing
   * us from acquiring a controlling terminal. */
  switch (fork()) {
  case -1:
    return -1;

  case 0:
    break;

  default:
    _exit(0);
  }

  /* Set a permissive file mode mask. */
  umask(0);

  /* Close all (possibly) open files. */
  errno = 0;
  if ((open_max = (int) sysconf(_SC_OPEN_MAX)) == -1 && errno) {
    return -1;
  }

  for (i = 0; i < ((open_max != -1) ? open_max : OPEN_MAX); ++i) {
    if (r_close(i) == -1 && errno != EBADF) {
      return -1;
    }
  }

  /* Reopen stdin, stdout, and stderr, redirecting them to /dev/null. */
  if (r_open("/dev/null", O_RDONLY) != STDIN_FILENO
      || r_open("/dev/null", O_WRONLY) != STDOUT_FILENO
      || dup(STDOUT_FILENO) != STDERR_FILENO) {
    return -1;
  }

  return 0;
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

  return ((sock = socket(PF_INET, SOCK_STREAM, 0)) != -1 &&
      !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE)) &&
      !bind(sock, (struct sockaddr *) &addr, sizeof(addr)) &&
      !listen(sock, config.backlog)) ? sock : -1;
}

/*
 * Close the specified passive socket.
 */
void dispose_passive_sock(int sock) {
  if (sock != -1) {
    if (r_close(sock)) {
      log_perror(NULL, "Couldn't close passive socket");
    }
  }
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

  return (!(p_passwd = getpwnam(config.user))
      || setgid(p_passwd->pw_gid)
      || setgroups(0, NULL)
      || setuid(p_passwd->pw_uid)) ? -1 : 0;
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
    return NULL;
  }

  for (i = 0; i < config.num_workers; ++i) {
    if ((pids[i] = start_worker(passive_sock)) == -1) {
      for (j = 0; i < i; ++j) {
        kill(pids[j], SIGTERM);
      }
      free(pids);
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
 * Free the specified array of worker PIDs.
 */
void dispose_workers(const pid_t *pids) {
  free((pid_t *) pids);
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
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  while ((data_size = r_read(file, buf, sizeof(buf)))) {
    if (data_size == -1) {
      log_perror(addr_str, "Couldn't read resource");
      err_msg = RESPONSE_ERR_READ;
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
  if (file != -1) {
    if (r_close(file)) {
      log_perror(addr_str, "Couldn't close resource");
    }
  }

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
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  while (num_dirents-- && !err_msg) {
    const char *file_name = p_dirents[num_dirents]->d_name;
    int direntry_size;
    char *file_path = NULL, *sanitized_path = NULL,
         direntry_buf[DIRENTRY_BUF_SIZE];

    if (!(file_path = malloc(strlen(path) + strlen(file_name) + 2))) {
      log_perror(addr_str, "Couldn't allocate file path");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    strcpy(file_path, path);
    strcat(file_path, "/");
    strcat(file_path, file_name);

    if (sanitize_path(file_path, &sanitized_path)) {
      log_perror(addr_str, "Couldn't sanitize file path");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    if (!sanitized_path) {
      goto inner_cleanup;
    }

    if (!(item_type = get_item_type(sanitized_path))) {
      log_perror(addr_str, "Couldn't determine item type");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    if ((direntry_size = snprintf(
            direntry_buf,
            sizeof(direntry_buf),
            "%c%.70s\t%.255s\t%.255s\t%hd\r\n",
            item_type,
            file_name,
            sanitized_path + strlen(config.srv_path) + 1,
            config.hostname,
            config.port)) == -1) {
      log_perror(addr_str, "Couldn't format menu entry");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    if (r_write(sock, direntry_buf, direntry_size) == -1) {
      log_perror(addr_str, "Couldn't send menu entry to client");
      err_msg = RESPONSE_ERR_READ;
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
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  log_info(addr_str, "Accepted request for `%s` (%s)", selector,
      sanitized_path ? sanitized_path : "forbidden");

  if (!sanitized_path) {
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  if (!(item_type = get_item_type(sanitized_path))) {
    log_perror(addr_str, "Couldn't determine item type");
    err_msg = RESPONSE_ERR_OPEN;
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

  /* Restore the default SIGTERM handler, and ignore SIGPIPE so the worker
   * doesn't die if the client closes the connection prematurely. */
  sig.sa_handler = SIG_IGN;

  if (sigaction(SIGPIPE, &sig, NULL)) {
    log_perror(NULL, "Couldn't ignore SIGPIPE");
    return 1;
  }

  /* Process connections until we're asked to terminate cleanly. */
  while (!terminating) {
    int conn_sock;
    struct sockaddr_in addr;
    socklen_t addr_buf = sizeof(addr);
    char addr_str[INET_ADDRSTRLEN];

    /* Accept an incoming connection request. */
    if ((conn_sock = accept(passive_sock, (struct sockaddr *)&addr,
        &addr_buf)) == -1 && errno == EINTR) {
      continue;
    }

    if (conn_sock == -1) {
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
  int exit_status = 0, passive_sock = -1;
  struct sigaction sig = { 0 };
  pid_t *worker_pids = NULL;

  /* Set up logging. */
  openlog("seamonster", LOG_PERROR | LOG_PID, LOG_DAEMON);

  /* Set up signal handling. */
  sig.sa_handler = sigterm_handler;

  if (sigaction(SIGTERM, &sig, NULL)) {
    fprintf(stderr, "Couldn't set SIGTERM handler\n");
    return 1;
  }

  /* Parse command line arguments. */
  errno = 0;
  if (parse_config(argc, argv)) {
    if (errno) {
      fprintf(stderr, "Couldn't parse server configuration\n");
    }
    exit_status = 1;
    goto cleanup;
  }

  /* If requested, run as a daemon and set up logging. */
  if (config.should_daemonize && daemonize()) {
    if (daemonize()) {
      fprintf(stderr, "Couldn't run as a daemon");
      exit_status = 1;
      goto cleanup;
    }
  }

  /* Create a passive socket to listen for connection requests. */
  if ((passive_sock = create_passive_sock()) == -1) {
    log_perror(NULL, "Couldn't open passive socket");
    exit_status = 1;
    goto cleanup;
  }

  log_info(NULL, "Listening on port %hd", config.port);

  /* Make sure we aren't running as root after we bind the passive socket. */
  if (!getuid()) {
    if (drop_privs()) {
      log_perror(NULL, "Couldn't drop root privileges");
      exit_status = 1;
      goto cleanup;
    }

    log_info(NULL, "Dropped root privileges; running as %s", config.user);
  }

  /* Fork off some children to handle clients. */
  log_info(NULL, "Starting with %lu workers",
      (unsigned long) config.num_workers);

  if (!(worker_pids = create_workers(passive_sock))) {
    log_perror(NULL, "Couldn't fork workers to handle connections");
    exit_status = 1;
    goto cleanup;
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
      goto cleanup;
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

  /* Clean up after ourselves. */
cleanup:
  dispose_workers(worker_pids);
  dispose_passive_sock(passive_sock);
  closelog();
  free_config();

  return exit_status;
}
