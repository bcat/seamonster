/***** Dependencies: *****/

#include "resfail.h"

#include <errno.h>
#include <string.h>

/***** Gopher protocol strings: *****/

#define ERR_MSG       "Resource not found, access denied, or IO error " \
                      "occurred"
#define RESPONSE      "3" ERR_MSG "\tinvalid.invalid\t70\r\n"
#define RESPONSE_SIZE (sizeof(RESPONSE) - 1)

/***** Response processing implementation: *****/

RH_BEGIN(fail)
  RH_BEGIN_STATE
    int done;
  RH_END_STATE

  RH_BEGIN_INIT
    RH_STATE(done) = 0;
    return 0;
  RH_END_INIT

  RH_BEGIN_BUFFER
    if (!RH_STATE(done)) {
      memcpy(RH_CONN(buf_next), RESPONSE, RESPONSE_SIZE);
      RH_CONN(data_size) = RESPONSE_SIZE;
      RH_STATE(done) = 1;
    } else {
      RH_CONN(data_size) = 0;
    }

    return 0;
  RH_END_BUFFER

  RH_BEGIN_CLEANUP
  RH_END_CLEANUP
RH_END
