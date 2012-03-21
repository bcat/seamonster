#ifndef WORKER_H
#define WORKER_H

/***** Dependencies: *****/

#include <sys/wait.h>

/***** Main worker functions: *****/

/*
 * Fork a new worker process to handle connections to the specified passive
 * socket.
 *
 * Returns the PID of the new worker on success and -1 on error.
 */
pid_t start_worker(int passive_sock);

#endif /* WORKER_H */
