#ifndef RESFILE_H
#define RESFILE_H

/***** Dependencies: *****/

#include "conn.h"

/***** Response processing functions: *****/

/*
 * Incrementally send a Gopher failure file over the specified client
 * connection. The connection's item type determines whether a text- or
 * binary-mode transfer shall occur.
 */
RH_DECLARE(file)

#endif /* RESFILE_H */
