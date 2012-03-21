/*
 *    seamonster / a tiny hack of a gopher server
 *         fs.h / filesystem metadata access
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

#ifndef FILE_H
#define FILE_H

/***** Gopher item type characters: *****/

#define ITEM_TYPE_TXT '0'
#define ITEM_TYPE_DIR '1'
#define ITEM_TYPE_ERR '3'
#define ITEM_TYPE_BIN '9'
#define ITEM_TYPE_GIF 'g'
#define ITEM_TYPE_HTM 'h'
#define ITEM_TYPE_IMG 'I'

/***** Security functions: *****/

/*
 * Sanitize the given path by converting it to an absolute path which must be
 * rooted in the path specified in the server configuration.
 *
 * If the path referred to by in_path lies within the srv_path hierarchy, then
 * *p_out_path will be reassigned to point to reference the sanitized
 * (absolute) path, and 0 will be returned. If in_path refers to an invalid
 * location, then *p_out_path will be assigned as before, but -1 will be
 * returned. Finally, if an error occurs, then *p_out_path may be assigned a
 * NULL pointer, and -1 will be returned.
 */
int sanitize_path(const char *in_path, char **p_out_path);

/***** Item type determination functions: *****/

/*
 * Returns 1 if the specified Gopher protocol item type character mandates a
 * text response and 0 if it mandates a binary response.
 */
int is_item_type_textual(char item_type);

/*
 * Return the Gopher protocol item type character associated with the
 * specified path, using the magic library to differentiate text files,
 * images, and arbitrary binary files.
 *
 * Returns a Gopher item type character on success and '\0' on error.
 */
char get_item_type(const char *path);

#endif /* FILE_H */
