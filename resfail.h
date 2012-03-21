#ifndef RESFAIL_H
#define RESFAIL_H

/***** Dependencies: *****/

#include "conn.h"

/***** Response processing functions: *****/

/*
 * Incrementally send a Gopher failure response over the specified client
 * connection. At present, only one catch-all error message is supported.
 */
RH_DECLARE(fail)

#endif /* RESFAIL_H */
