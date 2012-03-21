/***** Dependencies: *****/

#include "resmenu.h"

/***** Response processing implementation: *****/

RH_BEGIN(menu)
  RH_BEGIN_STATE
    char dummy;
  RH_END_STATE

  RH_BEGIN_INIT
    return 0;
  RH_END_INIT

  RH_BEGIN_BUFFER
    RH_CONN(data_size) = 0;
    return 0;
  RH_END_BUFFER

  RH_BEGIN_CLEANUP
  RH_END_CLEANUP
RH_END

#if 0
/*
 * scandir filter for generating Gopher menu responses. The current directory
 * entry (.) will be filtered out, as will directory entries whose names
 * contain characters that are not valid in Gopher menu responses.
 */
static int menu_filter(const struct dirent *p_dirent) {
  const char *name = p_dirent->d_name;
  char ch;

  if (name[0] == '.' && name[1] == '\0') {
    return 0;
  }

  while ((ch = *name++)) {
    if (ch == '\t' || ch == '\r' || ch == '\n') {
      return 0;
    }
  }

  return 1;
}

/*
 * scandir sort function for generating Gopher menu responses. The parent
 * directory entry (..) is always sorted first, and the remaining directory
 * entries are ordered according to strcoll.
 */
static int menu_sort(const struct dirent **pp_dirent1,
    const struct dirent **pp_dirent2) {
  const char *name1 = (*pp_dirent1)->d_name, *name2 = (*pp_dirent2)->d_name;

  if (!strcmp(name1, "..")) {
    return !!strcmp(name2, "..");
  } else {
    return strcoll(name1, name2);
  }
}

/*
 * Serve a Gopher protocol menu response to the given socket.
 *
 * Returns NULL on success and a Gopher error response on failure.
 */
static const char *serve_menu(const char *path, int sock,
    const char *addr_str) {
  const char *err_msg = NULL;
  char item_type;
  struct dirent **p_dirents = NULL;
  int num_dirents;

  if ((num_dirents = scandir(path, &p_dirents, menu_filter, menu_sort))
      == -1) {
    log_perror(addr_str, "Couldn't scan resource directory");
    err_msg = RESPONSE_ERR;
    goto cleanup;
  }

  while (num_dirents-- && !err_msg) {
    const char *file_name = p_dirents[num_dirents]->d_name;
    int direntry_len;
    char *file_path = NULL, *sanitized_path = NULL, *direntry = NULL;

    if (asprintf(&file_path, "%s/%s", path, file_name) < 0) {
      log_perror(addr_str, "Couldn't allocate file path");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if (sanitize_path(file_path, &sanitized_path)) {
      log_perror(addr_str, "Couldn't sanitize file path");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if (!sanitized_path) {
      goto inner_cleanup;
    }

    if (!(item_type = get_item_type(sanitized_path))) {
      log_perror(addr_str, "Couldn't determine item type");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if ((direntry_len = asprintf(
            &direntry,
            "%c%.70s\t%.255s\t%.255s\t%hd\r\n",
            item_type,
            file_name,
            sanitized_path + strlen(g_config.srv_path),
            g_config.hostname,
            g_config.port)) < 0) {
      log_perror(addr_str, "Couldn't format menu entry");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

    if (r_write(sock, direntry, direntry_len) == -1) {
      log_perror(addr_str, "Couldn't send menu entry to client");
      err_msg = RESPONSE_ERR;
      goto inner_cleanup;
    }

  inner_cleanup:
    free(direntry);
    free(sanitized_path);
    free(file_path);
    free(p_dirents[num_dirents]);
  }

  if (r_write(sock, RESPONSE_EOM, sizeof(RESPONSE_EOM)) == -1) {
    log_perror(addr_str, "Couldn't send resource to client");
    goto cleanup;
  }

cleanup:
  free(p_dirents);

  return err_msg;
}
#endif
