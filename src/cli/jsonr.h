/*
 *  A small JSON reader for the CLI: one line of diff.v1, one checkpoint's
 *  meta.json. Bounded (depth, size), no recursion past JSONR_DEPTH; values
 *  point into a copy the caller frees with jsonr_free.
 */
#ifndef BELAY_CLI_JSONR_H
#define BELAY_CLI_JSONR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSONR_DEPTH 8

enum jtype { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };

struct jval {
    enum jtype t;
    bool b;
    double num;
    int64_t i;              /* J_NUM written as an integer */
    char *s;                /* J_STR: decoded, NUL-terminated; s_len bytes */
    size_t s_len;
    struct jval *kids;      /* J_ARR, J_OBJ: n of them */
    char **keys;            /* J_OBJ: one per kid */
    size_t n;
};

/* Parses `text` (len bytes) into *out. 0, or -1 (malformed, too deep). */
int jsonr_parse(const char *text, size_t len, struct jval *out);
void jsonr_free(struct jval *v);

/* The member `key` of an object, or NULL. */
const struct jval *jget(const struct jval *obj, const char *key);
/* Its string, or "" ; its integer, or `def`. */
const char *jstr(const struct jval *obj, const char *key);
int64_t jint(const struct jval *obj, const char *key, int64_t def);

#endif
