#include <sys/stat.h>

#pragma once

extern bool parse_mode(const char *spec, mode_t *mode_out);
extern bool parse_owner_spec(const char *spec, uid_t *uid_out, gid_t *gid_out);
