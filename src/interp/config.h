/*
 *  config's claims (test/expect/system-config.md, "Grammars"): which
 *  grammar keys a file, by its absolute path. A second claim: the file's
 *  own interpreter explains it as well (CF-6).
 */
#ifndef BELAY_INTERP_CONFIG_H
#define BELAY_INTERP_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

enum config_grammar { CONFIG_NONE, CONFIG_NGINX, CONFIG_SSHD, CONFIG_INI, CONFIG_KEYVALUE, CONFIG_NAMEVALUE };

enum config_grammar config_grammar(const char *abs, size_t n);

/* systemd.c: a unit file or a drop-in of a unit directory, as systemd
 * names them (system-interpreters.md, systemd). */
bool systemd_unit_file_path(const char *abs, size_t n);

#endif
