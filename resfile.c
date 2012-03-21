/*
 *    seamonster / a tiny hack of a gopher server
 *    resfile.c / response handler for simple files
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
