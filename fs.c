/*
 *    seamonster / a tiny hack of a gopher server
 *         fs.c / filesystem metadata access
 *
 * Copyright © 2011-12 Jonathan Rascher <jon@bcat.name>.
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

#include "common.h"
#include "fs.h"

#include <magic.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>

int sanitize_path(const char *in_path, char **p_out_path) {
  if (!(*p_out_path = realpath(in_path, NULL))) {
    return -1;
  }

  if (strstr(*p_out_path, g_config.srv_path) != *p_out_path) {
    return -1;
  }

  return 0;
}

/***** Item type determination functions: *****/

int is_item_type_textual(char item_type) {
  return item_type == ITEM_TYPE_TXT || item_type == ITEM_TYPE_DIR
    || item_type == ITEM_TYPE_ERR || item_type == ITEM_TYPE_HTM;
}

char get_item_type(const char *path) {
  char item_type = ITEM_TYPE_BIN;
  const char *mime_type = NULL;
  struct stat path_stat;
  magic_t cookie = NULL;

  if (stat(path, &path_stat)) {
    item_type = '\0';
    goto cleanup;
  }

  if (S_ISDIR(path_stat.st_mode)) {
    item_type = ITEM_TYPE_DIR;
    goto cleanup;
  }

  if (!(cookie = magic_open(MAGIC_MIME_TYPE))
      || magic_load(cookie, NULL)
      || !(mime_type = magic_file(cookie, path))) {
    item_type = '\0';
    goto cleanup;
  }

  if (strstr(mime_type, "text/") == mime_type) {
    item_type = !strcmp(mime_type + sizeof("text/") - 1, "html")
        ? ITEM_TYPE_HTM
        : ITEM_TYPE_TXT;
  } else if (strstr(mime_type, "image/") == mime_type) {
    item_type = !strcmp(mime_type + sizeof("image/") - 1, "gif")
        ? ITEM_TYPE_GIF
        : ITEM_TYPE_IMG;
  }

cleanup:
  if (cookie) {
    magic_close(cookie);
  }

  return item_type;
}
