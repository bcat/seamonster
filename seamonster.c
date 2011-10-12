#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define DEFAULT_HOSTNAME   "localhost"
#define DEFAULT_PORT       7070
#define DEFAULT_BACKLOG    256
#define DEFAULT_WORKERS    4
#define DEFAULT_SRV_PATH   "."

#define REQUEST_BUF_SIZE   256
#define RESPONSE_BUF_SIZE  4096
#define DIRENTRY_BUF_SIZE  592

#define RESPONSE_EOM       ".\r\n"
#define RESPONSE_ERR_OPEN  "3Error opening resource\tinvalid.invalid\t70\r\n"
#define RESPONSE_ERR_READ  "3Error reading resource\tinvalid.invalid\t70\r\n"

#define RESPONSE_TYPE_TEXT "0"
#define RESPONSE_TYPE_MENU "1"

struct config {
  const char *hostname;
  short port;
  int backlog;

  size_t num_workers;

  const char *srv_path;
};

int main(int argc, char **argv);

static int r_close(int fildes);
static ssize_t r_read(int fildes, void *buf, size_t nbyte);
static ssize_t r_write(int fildes, const void *buf, size_t nbytes);

static int worker_printf(pid_t pid, const char *addr_buf, const char *format,
    ...);
static int worker_perror(pid_t pid, const char *addr_buf, const char *s);

static int sanitize_path(const struct config *p_config, const char *in_path,
    char **out_path);

static struct config *parse_config(int argc, char **argv);
static void free_config(const struct config *p_config);

static int create_passive_sock(const struct config *p_config);
static void dispose_passive_sock(int sock);

static pid_t *create_workers(const struct config *p_config, int passive_sock);
static void dispose_workers(pid_t *pids);

static const char **parse_request(int sock);
static void free_request(const char **request);

static const char *serve_text_file(const struct config *p_config,
    const char *path, int sock, pid_t pid, const char *addr_buf);

static int menu_filter(const struct dirent *p_dirent);
static int menu_sort(const struct dirent **pp_dirent1,
    const struct dirent **pp_dirent2);
static const char *serve_menu(const struct config *p_config,
    const char *path, int sock, pid_t pid, const char *addr_buf);

static void handle_conn(const struct config *p_config, int sock, pid_t pid,
    const char *addr_buf);

static int worker_main(const struct config *p_config, int passive_sock,
    pid_t pid);

static const int one = 1;

int r_close(int fildes) {
  int ret;
  while ((ret = close(fildes)) == -1 && errno == EINTR);
  return ret;
}

ssize_t r_read(int fildes, void *buf, size_t nbytes) {
  ssize_t ret;
  while ((ret = read(fildes, buf, nbytes)) == -1 && errno == EINTR);
  return ret;
}

ssize_t r_write(int fildes, const void *buf, size_t nbytes) {
  ssize_t ret;
  do {
    while ((ret = write(fildes, buf, nbytes)) == -1
        && errno == EINTR);
    buf = (const char *) buf + ret;
    nbytes -= ret;
  } while (nbytes && ret != -1);
  return ret;
}

int worker_printf(pid_t pid, const char *addr_buf, const char *format, ...) {
  char buf[50], *buf_next = buf;
  int buf_size = sizeof(buf), str_size;
  va_list varargs;

  if ((str_size = snprintf(buf_next, buf_size, "[%ld] ", (long) pid)) == -1) {
    return -1;
  }
  buf_next += (str_size < buf_size) ? str_size : buf_size;
  buf_size -= (str_size < buf_size) ? str_size : buf_size;

  if (addr_buf) {
    if ((str_size = snprintf(buf_next, buf_size, "%s - ", addr_buf)) == -1) {
      return -1;
    }
    buf_next += (str_size < buf_size) ? str_size : buf_size;
    buf_size -= (str_size < buf_size) ? str_size : buf_size;
  }

  va_start(varargs, format);
  if ((str_size = vsnprintf(buf_next, buf_size, format, varargs)) == -1) {
    return -1;
  }
  va_end(varargs);
  buf_next += (str_size < buf_size) ? str_size : buf_size;

  *buf_next++ = '\n';

  return r_write(STDERR_FILENO, buf, buf_next - buf);
}

int worker_perror(pid_t pid, const char *addr_buf, const char *s) {
  return worker_printf(pid, addr_buf, "%s: %s", s, strerror(errno));
}

int sanitize_path(const struct config *p_config, const char *in_path,
    char **out_path) {
  if (!(*out_path = realpath(in_path, NULL))) {
    return -1;
  }

  if (strstr(*out_path, p_config->srv_path) != *out_path) {
    free(*out_path);
    *out_path = NULL;
  }

  return 0;
}

struct config *parse_config(int argc, char **argv) {
  struct config *p_config;

  if (!(p_config = malloc(sizeof(*p_config)))) {
    return NULL;
  }

  p_config->hostname = DEFAULT_HOSTNAME;
  p_config->port = DEFAULT_PORT;
  p_config->backlog = DEFAULT_BACKLOG;
  p_config->num_workers = DEFAULT_WORKERS;

  if (!(p_config->srv_path = realpath(DEFAULT_SRV_PATH, NULL))) {
    free(p_config);
    return NULL;
  }

  return p_config;
}

void free_config(const struct config *p_config) {
  free((void *) p_config->srv_path);
  free((void *) p_config);
}

int create_passive_sock(const struct config *p_config) {
  int sock;
  struct sockaddr_in addr = { 0 };

  addr.sin_family = AF_INET;
  addr.sin_port = htons(p_config->port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  return ((sock = socket(PF_INET, SOCK_STREAM, 0)) != -1 &&
      !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) &&
      !bind(sock, (struct sockaddr *) &addr, sizeof(addr)) &&
      !listen(sock, p_config->backlog)) ? sock : -1;
}

void dispose_passive_sock(int sock) {
  if (sock != -1) {
    if (r_close(sock)) {
      perror("Couldn't close passive socket");
    }
  }
}

pid_t *create_workers(const struct config *p_config, int passive_sock) {
  size_t i;
  pid_t *pids = malloc(p_config->num_workers * sizeof(pid_t));

  if (!pids) {
    return NULL;
  }

  for (i = 0; i < p_config->num_workers; ++i) {
    switch (pids[i] = fork()) {
    case -1:
      free(pids);
      return NULL;

    case 0:
      exit(worker_main(p_config, passive_sock, getpid()));
    }
  }

  return pids;
}

void dispose_workers(pid_t *pids) {
  free(pids);
}

const char **parse_request(int sock) {
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

  return (const char **) request;
}

void free_request(const char **request) {
  if (request) {
    free((void *) *request);
  }
  free(request);
}

const char *serve_text_file(const struct config *p_config, const char *path,
    int sock, pid_t pid, const char *addr_buf) {
  const char *err_msg = NULL;
  char buf[RESPONSE_BUF_SIZE];
  ssize_t data_size;
  int file;

  while ((file = open(path, O_RDONLY)) == -1 && errno == EINTR);

  if (file == -1) {
    worker_perror(pid, addr_buf, "Couldn't open resource");
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  while ((data_size = r_read(file, buf, sizeof(buf)))) {
    if (data_size == -1) {
      worker_perror(pid, addr_buf, "Couldn't read resource");
      err_msg = RESPONSE_ERR_READ;
      goto cleanup;
    }

    if (r_write(sock, buf, data_size) == -1) {
      worker_perror(pid, addr_buf, "Couldn't send resource to client");
      goto cleanup;
    }
  }

  if (r_write(sock, RESPONSE_EOM, sizeof(RESPONSE_EOM)) == -1) {
    worker_perror(pid, addr_buf, "Couldn't send resource to client");
    goto cleanup;
  }

cleanup:
  if (file != -1) {
    if (r_close(file)) {
      worker_perror(pid, addr_buf, "Couldn't close resource");
    }
  }

  return err_msg;
}

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

int menu_sort(const struct dirent **pp_dirent1,
    const struct dirent **pp_dirent2) {
  const char *name1 = (*pp_dirent1)->d_name, *name2 = (*pp_dirent2)->d_name;

  if (!strcmp(name1, "..")) {
    return !!strcmp(name2, "..");
  } else {
    return strcoll(name1, name2);
  }
}

const char *serve_menu(const struct config *p_config, const char *path,
    int sock, pid_t pid, const char *addr_buf) {
  const char *err_msg = NULL;
  struct dirent **p_dirents = NULL;
  int num_dirents;

  if ((num_dirents = scandir(path, &p_dirents, menu_filter, menu_sort))
      == -1) {
    worker_perror(pid, addr_buf, "Couldn't scan resource directory");
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  while (num_dirents-- && !err_msg) {
    const char *file_name = p_dirents[num_dirents]->d_name;
    int direntry_size;
    struct stat path_stat;
    char *file_path = NULL, *sanitized_path = NULL,
         direntry_buf[DIRENTRY_BUF_SIZE];

    if (!(file_path = malloc(strlen(path) + strlen(file_name) + 2))) {
      worker_perror(pid, addr_buf, "Couldn't allocate file path");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    strcpy(file_path, path);
    strcat(file_path, "/");
    strcat(file_path, file_name);

    if (sanitize_path(p_config, file_path, &sanitized_path)) {
      worker_perror(pid, addr_buf, "Couldn't sanitize file path");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    if (!sanitized_path) {
      goto inner_cleanup;
    }

    if (stat(sanitized_path, &path_stat)) {
      worker_perror(pid, addr_buf, "Couldn't stat file path");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    if ((direntry_size = snprintf(
            direntry_buf,
            sizeof(direntry_buf),
            "%s%s\t%s\t%s\t%hd\r\n",
            S_ISDIR(path_stat.st_mode)
                ? RESPONSE_TYPE_MENU
                : RESPONSE_TYPE_TEXT,
            file_name,
            file_name,
            p_config->hostname,
            p_config->port)) == -1) {
      worker_perror(pid, addr_buf, "Couldn't format menu entry");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

    if (r_write(sock, direntry_buf, direntry_size) == -1) {
      worker_perror(pid, addr_buf, "Couldn't send menu entry to client");
      err_msg = RESPONSE_ERR_READ;
      goto inner_cleanup;
    }

  inner_cleanup:
    free(file_path);
    free(sanitized_path);
    free(p_dirents[num_dirents]);
  }

  if (r_write(sock, RESPONSE_EOM, sizeof(RESPONSE_EOM)) == -1) {
    worker_perror(pid, addr_buf, "Couldn't send resource to client");
    goto cleanup;
  }

cleanup:
  free(p_dirents);

  return err_msg;
}

void handle_conn(const struct config *p_config, int sock, pid_t pid,
    const char *addr_buf) {
  const char **request = NULL, **request_iter, *selector, *err_msg = NULL;
  struct stat path_stat;
  char *path = NULL, *sanitized_path = NULL;

  if (!(request_iter = request = parse_request(sock))) {
    worker_perror(pid, addr_buf, "Couldn't read or parse request");
    goto cleanup;
  }

  if (!(selector = *request_iter++)) {
    worker_printf(pid, addr_buf, "Request does not contain a selector");
    goto cleanup;
  }

  if (!(path = malloc(strlen(p_config->srv_path) + strlen(selector) + 2))) {
    worker_perror(pid, addr_buf, "Couldn't allocate resource path");
    goto cleanup;
  }

  strcpy(path, p_config->srv_path);
  strcat(path, "/");
  strcat(path, selector);

  if (sanitize_path(p_config, path, &sanitized_path)) {
    worker_perror(pid, addr_buf, "Couldn't sanitize resource path");
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  worker_printf(pid, addr_buf, "Accepted request for `%s` (`%s`)",
      selector, sanitized_path);

  if (!sanitized_path) {
    worker_printf(pid, addr_buf, "Selector references forbidden resource");
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  if (stat(sanitized_path, &path_stat)) {
    worker_perror(pid, addr_buf, "Couldn't stat resource path");
    err_msg = RESPONSE_ERR_OPEN;
    goto cleanup;
  }

  err_msg = S_ISDIR(path_stat.st_mode)
      ? serve_menu(p_config, sanitized_path, sock, pid, addr_buf)
      : serve_text_file(p_config, sanitized_path, sock, pid, addr_buf);

  if (*request_iter) {
    worker_printf(pid, addr_buf, "Request contains unexpected element");
    goto cleanup;
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

int worker_main(const struct config *p_config, int passive_sock, pid_t pid) {
  struct sigaction sig = { 0 };

  /* Print a message containing the worker's PID. */
  worker_printf(pid, NULL, "Spawned worker process", (long)pid);

  /* Ignore SIGPIPE so the worker doesn't die if the client closes the
   * connection prematurely. */
  sig.sa_handler = SIG_IGN;

  if (sigaction(SIGPIPE, &sig, NULL)) {
    worker_perror(pid, NULL, "Couldn't ignore SIGPIPE");
    return 1;
  }

  /* Process connections until interrupted the parent is interrupted. */
  for (;;) {
    int conn_sock;
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    char addr_buf[INET_ADDRSTRLEN];

    /* Accept an incoming connection request. */
    while ((conn_sock = accept(passive_sock, (struct sockaddr *)&addr,
        &addr_size)) == -1 && errno == EINTR);

    if (conn_sock == -1) {
      worker_perror(pid, NULL, "Couldn't accept connection request");
      return 1;
    }

    /* Format the client's IP address as a string. */
    if (!inet_ntop(AF_INET, &addr.sin_addr, addr_buf, sizeof(addr_buf))) {
      worker_perror(pid, NULL, "Couldn't format remote IP address");
      return 1;
    }

    /* Handle the new client connection. */
    handle_conn(p_config, conn_sock, pid, addr_buf);

    /* Close the client connection's socket. */
    if (r_close(conn_sock)) {
      worker_perror(pid, addr_buf, "Couldn't close connection socket");
    }
  }
}

int main(int argc, char **argv) {
  int exit_status = 0, passive_sock = -1;
  const struct config *p_config = NULL;
  pid_t *worker_pids = NULL;

  /* TODO: Parse command line arguments. */
  if (!(p_config = parse_config(argc, argv))) {
    perror("Couldn't parse server configuration");
    exit_status = 1;
    goto cleanup;
  }

  /* Create a passive socket to listen for connection requests. */
  if ((passive_sock = create_passive_sock(p_config)) == -1) {
    perror("Couldn't open passive socket");
    exit_status = 1;
    goto cleanup;
  }

  /* Fork off some children to handle clients. */
  if (!(worker_pids = create_workers(p_config, passive_sock))) {
    perror("Couldn't fork workers to handle connections");
    exit_status = 1;
    goto cleanup;
  }

  /* Wait for all our children to die. */
  for (;;) {
    if (wait(NULL) == -1) {
      if (errno == ECHILD) {
        break;
      }

      if (errno != EINTR) {
        perror("Couldn't wait for workers to die");
      }
    }
  }

  /* Clean up after ourselves. */
cleanup:
  dispose_workers(worker_pids);
  dispose_passive_sock(passive_sock);
  free_config(p_config);

  return exit_status;
}
