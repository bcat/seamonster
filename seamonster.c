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

static pid_t *create_workers(size_t num_workers, int passive_sock);
static void dispose_workers(pid_t *pids);

static int worker_main(int passive_sock);

static void handle_request(int sock);

int create_passive_sock(short port, int backlog) {
  int one = 1, sock;
  struct sockaddr_in addr = { 0 };

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
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

pid_t *create_workers(size_t num_workers, int passive_sock) {
  size_t i;
  pid_t *pids = malloc(num_workers * sizeof(pid_t));

  if (!pids) {
    return NULL;
  }

  for (i = 0; i < num_workers; ++i) {
    switch (pids[i] = fork()) {
      case -1:
        free(pids);
        return NULL;

      case 0:
        exit(worker_main(passive_sock));
    }
  }

  return pids;
}

void dispose_workers(pid_t *pids) {
  free(pids);
}

int worker_main(int passive_sock) {
  /* Process connections until interrupted the parent is interrupted. */
  for (;;) {
    int ret, conn_sock;

    /* Accept an incoming connection request. */
    while ((conn_sock = accept(passive_sock, NULL, NULL)) == -1
        && errno == EINTR);

    if (conn_sock == -1) {
      perror("Couldn't accept connection request");
      return 1;
    }

    /* Handle the new client connection. */
    handle_request(conn_sock);

    /* Close the client connection's socket. */
    while ((ret = close(conn_sock) == -1 && errno == EINTR));

    if (ret == -1) {
      perror("Couldn't close connection socket");
    }
  }
}

void handle_request(int sock) {
  char msg[] = "iHello, world of Gopher!\n.\n";
  send(sock, msg, sizeof(msg), 0);
}

int main(int argc, char **argv) {
  int exit_status = 0, passive_sock = -1;
  pid_t *worker_pids = NULL;

  /* Create a passive socket to listen for connection requests. */
  if ((passive_sock =
        create_passive_sock(DEFAULT_PORT, DEFAULT_BACKLOG)) == -1) {
    perror("Couldn't open passive socket");
    exit_status = 1;
    goto cleanup;
  }

  /* Fork off some children to handle clients. */
  if (!(worker_pids = create_workers(DEFAULT_WORKERS, passive_sock))) {
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

  return exit_status;
}
