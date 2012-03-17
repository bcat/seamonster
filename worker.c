/***** Dependencies: *****/

#include "common.h"
#include "worker.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <magic.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

/***** Buffer sizes: *****/

#define REQUEST_BUF_SIZE  PIPE_BUF
#define RESPONSE_BUF_SIZE PIPE_BUF

/***** Gopher protocol strings: *****/

#define RESPONSE_EOM      ".\r\n"
#define RESPONSE_ERR      "3Error reading resource\tinvalid.invalid\t70\r\n" \
                              RESPONSE_EOM

/***** Gopher item type characters: *****/

#define ITEM_TYPE_TXT     '0'
#define ITEM_TYPE_DIR     '1'
#define ITEM_TYPE_BIN     '9'
#define ITEM_TYPE_GIF     'g'
#define ITEM_TYPE_HTM     'h'
#define ITEM_TYPE_IMG     'I'

/***** Request processing functions: *****/

/*
 * Parse a tab-delimited Gopher request.
 *
 * Returns a pointer to an array of strings representing the tab-delimited
 * request fields on success and NULL on error.
 */
static char **parse_request(int sock) {
  int done = 0;
  size_t i, num_chunks = 1;
  char *buf_start = NULL, *buf_next = NULL, *buf_end = NULL, **request;

  do {
    ssize_t recv_size;

    if (buf_next == buf_end) {
      size_t data_size = buf_next - buf_start,
          buf_size = buf_start ? buf_end - buf_start : REQUEST_BUF_SIZE;

      if (!(buf_start = realloc(buf_start, buf_size * 2))) {
        return NULL;
      }

      buf_next = buf_start + data_size;
      buf_end = buf_start + buf_size * 2;
    }

    recv_size = r_read(sock, buf_next, buf_end - buf_next);

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
          if (buf_next != buf_end && *buf_next == '\n') {
            *(buf_next - 1) = '\0';
            done = 1;
          }
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
static void free_request(const char *const *request) {
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
static int sanitize_path(const char *in_path, char **out_path) {
  if (!(*out_path = realpath(in_path, NULL))) {
    return -1;
  }

  if (strstr(*out_path, g_config.srv_path) != *out_path) {
    free(*out_path);
    *out_path = NULL;
  }

  return 0;
}

/***** Response processing functions (general): *****/

/*
 * Return the Gopher protocol item type character associated with the
 * specified path, using the magic library to differentiate text files,
 * images, and arbitrary binary files.
 *
 * Returns a Gopher item type character on success and '\0' on error.
 */
static char get_item_type(const char *path) {
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

/***** Response processing functions (files): *****/

/*
 * Serve a Gopher protocol file response (text or binary, as specified) to the
 * given socket.
 *
 * Returns NULL on success and a Gopher error response on failure.
 */
static const char *serve_file(const char *path, int sock, const char *addr_str,
    int is_txt) {
  const char *err_msg = NULL;
  char buf[RESPONSE_BUF_SIZE];
  ssize_t data_size;
  int file;

  if ((file = r_open(path, O_RDONLY)) == -1) {
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

/***** Response processing functions (directory): *****/

/*
 * scandir filter for generating Gopher menu responses. The current directory
 * entry (.) will be filtered out, as will directory entries whose names
 * contain characters that are not valid in Gopher menu responses.
 */
static int menu_filter(const struct dirent *p_dirent) {
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
static int menu_sort(const struct dirent **pp_dirent1,
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
static const char *serve_menu(const char *path, int sock,
    const char *addr_str) {
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
    int direntry_len;
    char *file_path = NULL, *sanitized_path = NULL, *direntry = NULL;

    if (asprintf(&file_path, "%s/%s", path, file_name) < 0) {
      log_perror(addr_str, "Couldn't allocate file path");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

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

    if ((direntry_len = asprintf(
            &direntry,
            "%c%.70s\t%.255s\t%.255s\t%hd\r\n",
            item_type,
            file_name,
            sanitized_path + strlen(g_config.srv_path),
            g_config.hostname,
            g_config.port)) < 0) {
      log_perror(addr_str, "Couldn't format menu entry");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if (r_write(sock, direntry, direntry_len) == -1) {
      log_perror(addr_str, "Couldn't send menu entry to client");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

  inner_cleanup:
    free(direntry);
    free(sanitized_path);
    free(file_path);
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

/***** Main worker process code: *****/

/*
 * Handle an incoming connection with the specified socket and IP address.
 */
static void handle_conn(int sock, const char *addr_str) {
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

  if (asprintf(&path, "%s/%s", g_config.srv_path, selector) < 0) {
    log_perror(addr_str, "Couldn't allocate resource path");
    goto cleanup;
  }

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
  }

  free(sanitized_path);
  free(path);
  free_request(request);
}

/*
 * Drop root privileges and run as the user specified in the server
 * configuration.
 *
 * Returns 0 on success and -1 on error.
 */
static int drop_privs() {
  struct passwd *p_passwd;

  errno = 0;
  if (!(p_passwd = getpwnam(g_config.user))) {
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

static int worker_main(int passive_sock) {
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

    log_info(NULL, "Dropped root privileges; running as %s", g_config.user);
  }

  /* Process connections until we're asked to terminate cleanly. */
  while (!g_terminating) {
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

pid_t start_worker(int passive_sock) {
  pid_t pid;

  if (!(pid = fork())) {
    exit(worker_main(passive_sock));
  }

  return pid;
}
