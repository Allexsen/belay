#pragma once
#include <stddef.h>

#define SESH_UPPER "upper"
#define SESH_WORK "work"
#define SESH_TEMPROOT "temproot"

int construct_sesh_dir(char *out, size_t outsz);
int create_sesh_layout(const char *curr_sesh_dir);
int sesh_layout_path(char *out, size_t outsz, const char *sesh_dir, const char *subdir);
int sesh_entry_path(char *out, size_t outsz, const char *sesh_dir, const char *subdir, const char *entrydir);