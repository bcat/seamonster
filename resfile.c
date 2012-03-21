/***** Dependencies: *****/

#include "resfile.h"

#include <errno.h>
#include <fcntl.h>

/***** Response processing implementation: *****/

RH_BEGIN(file)
  RH_BEGIN_STATE
    int file;
  RH_END_STATE

  RH_BEGIN_INIT
    if ((RH_STATE(file) = r_open(RH_CONN(path), O_RDONLY)) == -1) {
      log_pwarn(RH_CONN(addr_str), "Couldn't open requested file");
      return -1;
    }

    return 0;
  RH_END_INIT

  RH_BEGIN_BUFFER
    char *buf_next = RH_CONN(buf_next);
    size_t buf_size = sizeof(RH_CONN(buf)) - RH_CONN(state_size);
    ssize_t read_size;

    do {
      if ((read_size = r_read(RH_STATE(file), buf_next, buf_size)) == -1) {
        log_pwarn(RH_CONN(addr_str), "Error reading requested file");
        return -1;
      }
    } while (buf_next += read_size, (buf_size -= read_size) && read_size);

    RH_CONN(data_size) = buf_next - RH_CONN(buf_next);

    return 0;
  RH_END_BUFFER

  RH_BEGIN_CLEANUP
    if (r_close(RH_STATE(file))) {
      log_pwarn(RH_CONN(addr_str), "Couldn't close requested file");
    }
  RH_END_CLEANUP
RH_END
