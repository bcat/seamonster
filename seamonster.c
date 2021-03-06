/*
 *    seamonster / a tiny hack of a gopher server
 * seamonster.c / main program, config processing, worker management
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
#include "worker.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>

/***** Default configuration options: *****/

#define DEF_DAEMONIZE        0
#define DEF_PID_FILE         "/var/run/seamonster.pid"
#define DEF_HOSTNAME         "localhost"
#define DEF_PORT             70
#define DEF_BACKLOG          128
#define DEF_USER             "nobody"
#define DEF_WORKERS          4
#define DEF_CONNS_PER_WORKER 250
#define DEF_SRV_PATH         "/srv/gopher"

/***** Magic numbers: *****/

#define PID_FILE_MODE        (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

static const int ONE = 1;

/***** Command line options: *****/

#define OPT_HELP             '\0'
#define OPT_VERSION          '\1'
#define OPT_DAEMONIZE        'd'
#define OPT_PID_FILE         'P'
#define OPT_HOST             'h'
#define OPT_PORT             'p'
#define OPT_BACKLOG          'b'
#define OPT_USER             'u'
#define OPT_WORKERS          'w'
#define OPT_CONNS_PER_WORKER 'c'
#define OPT_SRV_PATH         's'

#define OPTSTRING            "dP:h:p:b:u:w:c:s:"

static const struct option LONGOPTS[] = {
  { "help",             0, NULL, OPT_HELP },
  { "version",          0, NULL, OPT_VERSION },
  { "daemonize",        0, NULL, OPT_DAEMONIZE },
  { "pid-file",         1, NULL, OPT_PID_FILE },
  { "host",             1, NULL, OPT_HOST },
  { "port",             1, NULL, OPT_PORT },
  { "backlog",          1, NULL, OPT_BACKLOG },
  { "user",             1, NULL, OPT_USER },
  { "workers",          1, NULL, OPT_WORKERS },
  { "conns-per-worker", 1, NULL, OPT_CONNS_PER_WORKER },
  { "srv-path",         1, NULL, OPT_SRV_PATH },
  { 0 }
};

/***** Documentation: *****/

#define VERSION              "seamonster 0.1 / a tiny hack of a gopher " \
                                 "server\n" \
                             "copyright (c) / 2011-12 jonathan rascher\n" \
                             "isc-licensed / use, read, hack...\n\n" \
                             "     May your love reach to the sky\n" \
                             "     May your sun be always bright\n" \
                             "     May hope guide you\n" \
                             "     Your best dreams come true\n\n" \
                             "     When we reach out to the sun\n" \
                             "     And when you and I are one\n" \
                             "     My heart is true\n" \
                             "     May love cover you\n\n" \
                             "--- \"Seamonster\" by the violet burning\n"

#define USAGE                "Usage: %s [options]\n\n"
#define USAGE_HELP           "Try %s --help for more information\n"

/***** Global variables: *****/

volatile sig_atomic_t g_terminating;

struct config g_config;

pid_t g_server_pid;

/***** Shutdown functions: *****/

/*
 * Delete PID file (if running as a daemon) when the server exits normally.
 */
static void delete_pid_file(void) {
  if (getpid() == g_server_pid && g_config.daemonize) {
    unlink(g_config.pid_file);
  }
}

/*
 * Respond to SIGTERM by setting a termination flag.
 */
static void sigterm_handler(int signum) {
  if (!g_terminating) {
    g_terminating = 1;
  }
}

/***** Startup functions: *****/

/*
 * Parse command line arguments into the global config.
 *
 * Returns 0 on success and -1 on error or if a help/version option has been
 * provided. If an invalid option is provided, errno will be set to EINVAL.
 */
static int parse_config(int argc, char **argv) {
  int opt;
  long optnum;

  g_config.daemonize        = DEF_DAEMONIZE;
  g_config.port             = DEF_PORT;
  g_config.backlog          = DEF_BACKLOG;
  g_config.num_workers      = DEF_WORKERS;
  g_config.conns_per_worker = DEF_CONNS_PER_WORKER;

  while ((opt = getopt_long(argc, argv, OPTSTRING, LONGOPTS, NULL)) != -1) {
    switch (opt) {
    case OPT_HELP:
      /* TODO: Print out help documentation. */
      return -1;

    case OPT_VERSION:
      fprintf(stderr, "%s", VERSION);
      return -1;

    case OPT_HOST:
      free((char *) g_config.hostname);
      if (!(g_config.hostname = strdup(optarg))) {
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

      g_config.port = (in_port_t) optnum;
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

      g_config.backlog = (int) strtol(optarg, NULL, 10);
      break;

    case OPT_USER:
      free((char *) g_config.user);
      if (!(g_config.user = strdup(optarg))) {
        perror("Couldn't allocate user string");
        return -1;
      }
      break;

    case OPT_DAEMONIZE:
      g_config.daemonize = 1;
      break;

    case OPT_PID_FILE:
      free((char *) g_config.pid_file);
      if (!(g_config.pid_file = strdup(optarg))) {
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

      g_config.num_workers = (size_t) optnum;
      break;

    case OPT_CONNS_PER_WORKER:
      errno = 0;
      optnum = strtol(optarg, NULL, 10);
      if (errno) {
        perror("Couldn't parse number of connections per worker");
        return -1;
      }

      if (optnum < 0 || optnum > SIZE_MAX) {
        fprintf(stderr, "Number of connections per worker is out of range\n");
        errno = EINVAL;
        return -1;
      }

      g_config.conns_per_worker = (size_t) optnum;
      break;

    case OPT_SRV_PATH:
      free((char *) g_config.srv_path);
      if (!(g_config.srv_path = strdup(optarg))) {
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

  if ((!g_config.pid_file && !(g_config.pid_file = strdup(DEF_PID_FILE)))
      || (!g_config.hostname && !(g_config.hostname = strdup(DEF_HOSTNAME)))
      || (!g_config.user && !(g_config.user = strdup(DEF_USER)))) {
    perror("Couldn't copy default configuration string");
    return -1;
  }

  if (!(g_config.srv_path = realpath(g_config.srv_path
          ? g_config.srv_path : DEF_SRV_PATH, NULL))) {
    perror("Couldn't find absolute service path");
    return -1;
  }

  return 0;
}

/*
 * Run as a daemon. Based on Section 13.3 in _Advanced Programming in the
 * UNIX Environment_ by Stevens.
 *
 * Returns 0 on success and -1 on error.
 */
static int daemonize() {
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
  g_server_pid = getpid();

  /* Set a permissive file mode mask. */
  umask(0);

  /* Create a PID file, and prepare to delete it on exit. */
  if ((pid_fd = r_open(g_config.pid_file, O_WRONLY | O_CREAT | O_EXCL,
          PID_FILE_MODE)) == -1) {
    log_perror(NULL, "Couldn't create PID file for writing");
    ret = -1;
    goto cleanup;
  }

  if (asprintf(&pid_str, "%ld\n", (long) g_server_pid) < 0) {
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
    unlink(g_config.pid_file);
  }

  return ret;
}

/*
 * Create a passive socket to listen for incoming connections.
 *
 * Returns the socket's file descriptor on success and -1 on error.
 */
static int create_passive_sock() {
  int sock;
  struct sockaddr_in addr = { 0 };

  addr.sin_family = AF_INET;
  addr.sin_port = htons(g_config.port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    log_perror(NULL, "Couldn't create passive socket");
    return -1;
  }

  if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
    log_perror(NULL, "Couldn't put passive socket in nonblocking mode");
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

  if (listen(sock, g_config.backlog)) {
    log_perror(NULL, "Couldn't put passive socket in listening mode");
    return -1;
  }

  return sock;
}

/*
 * Start the number of worker processes requested in the server
 * configuration.
 *
 * Returns a pointer to an array of PIDs on success and NULL on error.
 */
static pid_t *create_workers(int passive_sock) {
  size_t i, j;
  pid_t *pids = malloc(g_config.num_workers * sizeof(pid_t));

  if (!pids) {
    log_perror(NULL, "Couldn't allocate array to store worker PIDs");
    return NULL;
  }

  for (i = 0; i < g_config.num_workers; ++i) {
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

/***** Main server process code: *****/

int main(int argc, char **argv) {
  int passive_sock = -1;
  struct sigaction sig = { 0 };
  pid_t *worker_pids = NULL;

  /* Record out PID for future reference. */
  g_server_pid = getpid();

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
  if (g_config.daemonize && daemonize()) {
    return 1;
  }

  /* Create a passive socket to listen for connection requests. */
  if ((passive_sock = create_passive_sock()) == -1) {
    return 1;
  }

  log_info(NULL, "Listening on port %hu", g_config.port);

  /* Fork off some children to handle clients. */
  log_info(NULL, "Starting with %lu worker%s",
      (unsigned long) g_config.num_workers,
      g_config.num_workers != 1 ? "s" : "");
  log_info(NULL, "Serving %lu connection%s each",
      (unsigned long) g_config.conns_per_worker,
      g_config.conns_per_worker != 1 ? "s" : "");

  if (!(worker_pids = create_workers(passive_sock))) {
    return 1;
  }

  /* Kill all workers on when the parent terminates cleanly, and restart any
   * workers that die prematurely. */
  for (;;) {
    size_t i;
    pid_t worker_pid;
    int stat_loc;

    /* On SIGTERM, kill all worker processes. */
    if (g_terminating == 1) {
      log_info(NULL, "Killing workers on SIGTERM");

      for (i = 0; i < g_config.num_workers; ++i) {
        if (worker_pids[i] != -1) {
          kill(worker_pids[i], SIGTERM);
        }
      }

      g_terminating = 2;
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
    if (!g_terminating && (WIFEXITED(stat_loc) || WIFSIGNALED(stat_loc))) {
      log_warn(NULL, "Worker %ld died; restarting", (long) worker_pid);

      for (i = 0; i < g_config.num_workers; ++i) {
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
