#ifndef REQ_H
#define REQ_H

/***** Dependencies: *****/

#include "conn.h"

/***** Request processing functions: *****/

int parse_request(struct conn *p_conn);

#endif /* REQ_H */
