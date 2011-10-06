#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/wait.h>

#define DEFAULT_PORT    7070
#define DEFAULT_BACKLOG 4
#define DEFAULT_WORKERS 8

int main(int argc, char **argv);

static int create_passive_sock(short port, int backlog);
static void dispose_passive_sock(int sock);

static pid_t *fork_workers(size_t num);
static void dispose_workers(pid_t *pids, size_t num);

pid_t *fork_workers(size_t num) {
  size_t i;
  pid_t *pids = malloc(num * sizeof(pid_t));

  if (!pids) {
    return NULL;
  }

  for (i = 0; i < num; ++i) {
    switch (pids[i] = fork()) {
      case -1:
        free(pids);
        return NULL;

      case 0:
        /* TODO: Implement worker functionality. */
        exit(0);
    }
  }

  return pids;
}

void dispose_workers(pid_t *pids, size_t num) {
  if (pids) {
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

    free(pids);
  }
}

int create_passive_sock(short port, int backlog) {
  int sock;
  struct sockaddr_in addr = { 0 };

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
    return -1;
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    return -1;
  }

  if (listen(sock, backlog) == -1) {
    return -1;
  }

  return sock;
}

void dispose_passive_sock(int sock) {
  if (sock != -1) {
    int ret;

    while ((ret = close(sock)) == -1 && errno == EINTR);

    if (ret == -1) {
      perror("Couldn't close passive socket");
    }
  }
}

int main(int argc, char **argv) {
  int ret, exit_status = 0, passive_sock = -1;
  pid_t *worker_pids = NULL;

  /* Fork off some children to handle clients. */
  if (!(worker_pids = fork_workers(DEFAULT_WORKERS))) {
    perror("Couldn't fork workers to handle connections");
    exit_status = 1;
    goto cleanup;
  }

  /* Create a passive socket to listen for connection requests. */
  if ((passive_sock =
        create_passive_sock(DEFAULT_PORT, DEFAULT_BACKLOG)) == -1) {
    perror("Couldn't open passive socket");
    exit_status = 1;
    goto cleanup;
  }

  /* Accept new connections until interrupted. */
  for (;;) {
    int conn_sock;

    while ((conn_sock = accept(passive_sock, NULL, NULL)) == -1
        && errno == EINTR);

    if (conn_sock == -1) {
      perror("Couldn't accept connection request");
      exit_status = 1;
      goto cleanup;
    }

    while ((ret = close(conn_sock) == -1 && errno == EINTR));

    if (ret == -1) {
      perror("Couldn't close connection socket");
    }
  }

  /* Clean up after ourselves. */
cleanup:
  dispose_passive_sock(passive_sock);
  dispose_workers(worker_pids, DEFAULT_WORKERS);

  return exit_status;
}
