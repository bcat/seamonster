#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/wait.h>

#define DEFAULT_PORT     7070
#define DEFAULT_BACKLOG  4
#define DEFAULT_WORKERS  8

#define REQUEST_BUF_SIZE 128

int main(int argc, char **argv);

static int create_passive_sock(short port, int backlog);
static void dispose_passive_sock(int sock);

static pid_t *create_workers(size_t num_workers, int passive_sock);
static void dispose_workers(pid_t *pids);

static int worker_main(int passive_sock);

static void handle_conn(int sock);

static const char **parse_request(int sock);
static void free_request(const char **request);

static const int one = 1;

int create_passive_sock(short port, int backlog) {
  int sock;
  struct sockaddr_in addr = { 0 };

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  return ((sock = socket(PF_INET, SOCK_STREAM, 0)) != -1 &&
      !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) &&
      !bind(sock, (struct sockaddr *) &addr, sizeof(addr)) &&
      !listen(sock, backlog)) ? sock : -1;
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

    while ((recv_size = recv(sock, buf_next, buf_end - buf_next, 0)) == -1
        && errno == EINTR);

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

void handle_conn(int sock) {
  const char **request, **request_iter;

  if (!(request = parse_request(sock))) {
    perror("Couldn't read or parse request");
    return;
  }

  for (request_iter = request; *request_iter; ++request_iter) {
    send(sock, "i", 1, 0);
    send(sock, *request_iter, strlen(*request_iter), 0);
    send(sock, "\r\n", 2, 0);
  }

  free_request(request);
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
    handle_conn(conn_sock);

    /* Close the client connection's socket. */
    while ((ret = close(conn_sock) == -1 && errno == EINTR));

    if (ret == -1) {
      perror("Couldn't close connection socket");
    }
  }
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
