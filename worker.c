/*
 *    seamonster / a tiny hack of a gopher server
 *     worker.c / worker thread main loop, connection management
 *
 * copyright © 2011-12 jonathan rascher <jon@bcat.name>.
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

#include "common.h"
#include "conn.h"
#include "fs.h"
#include "req.h"
#include "resfail.h"
#include "resfile.h"
#include "resmenu.h"
#include "worker.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/***** Connection state variables: *****/

struct conn *conns;

struct pollfd *pollfds, *conn_pollfds, *p_passive_pollfd;

struct conn **free_conn_stack, **free_conn_top;

struct conn **pollfd_idxs_to_conns;
size_t num_active_conns;

/***** Startup functions: *****/

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

/*
 * Allocate and initialize connection state arrays.
 *
 * Returns 0 on success and -1 on error.
 */
static int create_conn_state(int passive_sock) {
  int ret = 0;
  size_t num_conns = g_config.conns_per_worker, i;

  /* Allocate memory. */
  conns = NULL;
  pollfds = NULL;
  free_conn_stack = NULL;
  pollfd_idxs_to_conns = NULL;

  if (!(conns = malloc(num_conns * sizeof(*conns)))
      || !(pollfds = malloc((num_conns + 1) * sizeof(*pollfds)))
      || !(free_conn_stack = malloc(num_conns * sizeof(*free_conn_stack)))
      || !(pollfd_idxs_to_conns
          = calloc(num_conns, sizeof(*pollfd_idxs_to_conns)))) {
    log_perror(NULL, "Couldn't allocate connection state arrays");
    ret = -1;
    goto cleanup;
  }

  /* Initialize connection state slots and stack of pointers to free
   * connection slots. */
  free_conn_top = free_conn_stack;

  for(i = 0; i < num_conns; ++i) {
    struct conn *p_conn = conns + i;
    p_conn->conn_idx = i;
    init_conn(p_conn);
    *(free_conn_top++) = p_conn;
  }

  /* Initialize socket pollfds. */
  for (i = 0; i <= num_conns; ++i) {
    struct pollfd *p_pollfd = pollfds + i;
    p_pollfd->fd = -1;
    p_pollfd->events = 0;
    p_pollfd->revents = 0;
  }

  /* Initialize pollfd for passive socket. */
  conn_pollfds = pollfds + 1;
  p_passive_pollfd = pollfds;
  p_passive_pollfd->fd = passive_sock;

cleanup:
  if (ret) {
    free(pollfd_idxs_to_conns);
    free(free_conn_stack);
    free(pollfds);
    free(conns);
  }
  return ret;
}

/***** Connection management functions: *****/

static void handle_conn_delete(struct conn *p_conn, struct pollfd *p_pollfd) {
  struct pollfd *p_last_pollfd = conn_pollfds + --num_active_conns;
  struct conn *p_last_conn = pollfd_idxs_to_conns[num_active_conns];

  /* Log some debug info. */
  log_debug(NULL, "Deallocating pollfd %lu from connection %lu/socket %d",
      (unsigned long) p_conn->pollfd_idx,
      (unsigned long) p_conn->conn_idx,
      p_conn->sock);

  /* Return the connection slot to the free stack. */
  *(free_conn_top++) = p_conn;

  /* Overwrite the connection's pollfd with the last active pollfd, deleting
   * the old pollfd in constant time. */
  memcpy(p_pollfd, p_last_pollfd, sizeof(*p_pollfd));
  p_last_pollfd->fd = -1;
  p_last_pollfd->events = 0;
  p_last_pollfd->revents = 0;

  /* Update the pollfd--connection mappings. */
  pollfd_idxs_to_conns[p_conn->pollfd_idx] = p_last_conn;
  pollfd_idxs_to_conns[num_active_conns] = NULL;
  p_last_conn->pollfd_idx = p_conn->pollfd_idx;

  /* Close the connection socket and free its associated resources. */
  cleanup_conn(p_conn);
}

static void handle_conn_write(struct conn *p_conn, struct pollfd *p_pollfd) {
  int done = 0;
  ssize_t send_size;

  /* Log some debug info. */
  log_debug(NULL, "Writing connection %lu/socket %d (assigned pollfd %lu)",
      (unsigned long) p_conn->conn_idx,
      p_conn->sock,
      (unsigned long) p_conn->pollfd_idx);

  if (p_conn->stage == STAGE_RESPONSE_START) {
    char *selector = p_conn->buf, *raw_path = NULL, *log_msg;

    if (asprintf(&raw_path, "%s/%s", g_config.srv_path, selector) < 0) {
      log_pwarn(p_conn->addr_str, "Couldn't allocate resource path");
      done = 1;
      goto cleanup_response_start;
    }

    errno = 0;
    if (sanitize_path(raw_path, &p_conn->path)) {
      if (errno) {
        switch (errno) {
          case EACCES:
          case EIO:
          case ELOOP:
          case ENAMETOOLONG:
          case ENOENT:
          case ENOTDIR:
            log_msg = "Denied request: %s [%s] - %s";
            p_conn->item_type = ITEM_TYPE_ERR;
            break;

          default:
            log_pwarn(p_conn->addr_str, "Couldn't sanitize resource path");
            done = 1;
            goto cleanup_response_start;
        }
      } else {
        log_msg = "Denied request: %s [%s] - Outside service path";
        p_conn->item_type = ITEM_TYPE_ERR;
      }
    } else {
      log_msg = "Allowed request: %s [%s]";
    }

    log_info(p_conn->addr_str, log_msg, selector,
        p_conn->path ? p_conn->path : raw_path, strerror(errno));

    if (!p_conn->item_type
        && !(p_conn->item_type = get_item_type(p_conn->path))) {
      log_pwarn(p_conn->addr_str, "Could not determine item type");
      done = 1;
      goto cleanup_response_start;
    }

    switch (p_conn->item_type) {
    case ITEM_TYPE_ERR:
      new_fail_response(p_conn);
      break;

    case ITEM_TYPE_DIR:
      new_menu_response(p_conn);
      break;

    default:
      new_file_response(p_conn);
    }

    if (p_conn->init_response(p_conn)) {
      done = 1;
      goto cleanup_response_start;
    }

    p_conn->stage = STAGE_RESPONSE_BODY;

  cleanup_response_start:
    free(raw_path);

    if (done) {
      goto cleanup;
    }
  }

  if (!p_conn->data_size) {
    p_conn->buf_next = p_conn->buf + p_conn->state_size;

    if (p_conn->buffer_response(p_conn)) {
      done = 1;
      goto cleanup;
    }
  }

  if (!p_conn->data_size) {
    done = 1;
    goto cleanup;
  }

  if ((send_size
          = r_write(p_conn->sock, p_conn->buf_next, p_conn->data_size))
      == -1) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      done = 1;
    }

    goto cleanup;
  }

  p_conn->buf_next += send_size;
  p_conn->data_size -= send_size;

cleanup:
  if (done) {
    handle_conn_delete(p_conn, p_pollfd);
  }
}

static void handle_conn_read(struct conn *p_conn, struct pollfd *p_pollfd) {
  /* Log some debug info. */
  log_debug(NULL, "Reading connection %lu/socket %d (assigned pollfd %lu)",
      (unsigned long) p_conn->conn_idx,
      p_conn->sock,
      (unsigned long) p_conn->pollfd_idx);

  /* Parse the next portion of this client's request. */
  switch (parse_request(p_conn)) {
  case -1:
    /* If an error occurred, bail out. */
    handle_conn_delete(p_conn, p_pollfd);

  case 0:
    /* If no error occurred, but the request is not yet complete, try again
     * when there's more data to be read. */
    return;
  }

  /* Otherwise, no errors occurred and we got a complete selector. Now try to
   * serve the requested resource. */
  p_conn->stage = STAGE_RESPONSE_START;
  p_pollfd->events = POLLOUT;
  handle_conn_write(p_conn, p_pollfd);
}

static int handle_conn_new(int passive_sock) {
  int ret = 0;
  struct conn *p_conn = *(free_conn_top - 1);
  struct pollfd *p_pollfd = conn_pollfds + num_active_conns;
  struct sockaddr_in addr;
  socklen_t addr_size = sizeof(addr);

  /* Accept an incoming connection request. */
  if ((p_conn->sock =
        r_accept(passive_sock, (struct sockaddr *)&addr, &addr_size)) == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      ret = 0;
    } else {
      log_perror(NULL, "Couldn't accept connection request");
      ret = -1;
    }
    goto cleanup;
  }

  /* Format the client's IP address as a string. */
  if (!inet_ntop(AF_INET, &addr.sin_addr, p_conn->addr_str,
        sizeof(p_conn->addr_str))) {
    log_perror(NULL, "Couldn't format remote IP address");
    ret = -1;
    goto cleanup;
  }

  /* Set the new connection's socket in nonblocking mode. */
  if (fcntl(p_conn->sock, F_SETFL, O_NONBLOCK) == -1) {
    log_perror(p_conn->addr_str,
        "Couldn't put client socket in nonblocking mode");
    ret = -1;
    goto cleanup;
  }

  /* Update the pollfd--connection mapping table. */
  pollfd_idxs_to_conns[num_active_conns] = p_conn;
  p_conn->pollfd_idx = num_active_conns;

  /* Log some debug info. */
  log_debug(NULL, "Allocating pollfd %lu to connection %lu/socket %d",
      (unsigned long) p_conn->pollfd_idx,
      (unsigned long) p_conn->conn_idx,
      p_conn->sock);

cleanup:
  if (!ret && p_conn->sock != -1) {
    --free_conn_top;
    ++num_active_conns;

    p_conn->stage = STAGE_RESPONSE_START;
    p_pollfd->fd = p_conn->sock;
    p_pollfd->events = POLLIN;
    p_pollfd->revents = 0;
  } else if (ret == -1) {
    cleanup_conn(p_conn);
  }

  return ret;
}

/***** Main worker functions: *****/

/*
 * "main function" for workers processes.
 *
 * Returns 0 on successful termination and a positive exit status on failure.
 */
static int worker_main(int passive_sock) {
  struct sigaction sig = { 0 };

  /* Print a message containing the worker's PID. */
  log_info(NULL, "Spawned worker process");

  /* Make sure worker processes don't run as root. */
  if (!getuid()) {
    if (drop_privs()) {
      return 1;
    }

    log_info(NULL, "Dropped root privileges; running as %s", g_config.user);
  }

  /* Ignore SIGPIPE so the worker doesn't die if the client closes the
   * connection prematurely. */
  sig.sa_handler = SIG_IGN;

  if (sigaction(SIGPIPE, &sig, NULL)) {
    log_perror(NULL, "Couldn't ignore SIGPIPE");
    return 1;
  }

  /* Allocate memory to store connection info. */
  if (create_conn_state(passive_sock)) {
    return 1;
  }

  /* Process connections until we're asked to terminate cleanly. */
  while (!g_terminating) {
    size_t i;

    /* Poll the passive socket if and only if we've got room for another
     * connection. */
    p_passive_pollfd->events = (free_conn_top > free_conn_stack) ? POLLIN : 0;
    p_passive_pollfd->revents = 0;

    /* Wait until something socket-related happens. */
    if (poll(pollfds, num_active_conns + 1, -1) == -1) {
      if (errno == EINTR) {
        continue;
      }

      log_perror(NULL, "Couldn't poll for socket events");
      return 1;
    }

    /* Check for incoming connection requests. */
    if (p_passive_pollfd->revents & POLLIN) {
      if (handle_conn_new(passive_sock)) {
        return 1;
      }
    }

    /* Check the passive socket for error conditions. */
    if (p_passive_pollfd->revents & POLLERR) {
      log_error(NULL, "Poll error on passive socket");
      return 1;
    }

    for (i = 0; i < num_active_conns; ++i) {
      struct pollfd *p_pollfd = conn_pollfds + i;
      struct conn *p_conn = pollfd_idxs_to_conns[i];

      /* Check connected client sockets for IO conditions and/or errors. */
      if (p_pollfd->revents & POLLIN) {
        handle_conn_read(p_conn, p_pollfd);
      }

      if (p_pollfd->revents & POLLOUT) {
        handle_conn_write(p_conn, p_pollfd);
      }

      if (p_pollfd->revents & POLLERR) {
        log_error(p_conn->addr_str, "Poll error on connection socket");
        handle_conn_delete(p_conn, p_pollfd);
      }

      /* Reset socket events. */
      p_pollfd->revents = 0;

      /* Stop monitoring client sockets when requests are served completely or
       * errors occur. */
      if (p_conn->stage == STAGE_FREE) {
        /* If we deleted a connection, then its entry in the pollfds array has
         * been replaced by the last active pollfd. The last active pollfd now
         * lives at pollfds[i], and it might have events waiting. Therefore,
         * we must check pollfds[i] *again* to avoid missing events. */
        --i;
      }
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
