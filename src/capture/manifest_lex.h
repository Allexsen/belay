/*
 *  The manifest's lexical layer: bytes to objects. It knows the grammar and
 *  nothing about fields. Used by the reader only.
 *
 *  A STRICT PARSER for exactly the language the writer emits -- not a JSON
 *  reader, and not a key-searcher. Every line is consumed byte by byte against
 *  the grammar below, and anything else is rejected:
 *
 *    line    := object                     (then end of line)
 *    object  := '{' pair (',' pair)* '}'
 *    pair    := key ':' value              (no whitespace anywhere)
 *    key     := '"' [a-z0-9_]+ '"'
 *    value   := string | integer | 'true' | '[' string (',' string)* ']'
 *    string  := '"' (byte >= 0x20 except '"' '\' | escape)* '"'
 *    escape  := '\"' | '\\' | '\b' | '\f' | '\n' | '\r' | '\t'
 *             | '\u00' hex hex   -- lowercase, only for control bytes that
 *                                   have no short form
 *    integer := '0' | '-'? [1-9][0-9]*     (canonical: no '+', no leading 0)
 *
 *  Why a parser: an earlier version searched each line for the keys it wanted.
 *  Everything it did not look at -- whitespace, junk between fields, junk after
 *  the closing brace, bytes after an embedded NUL -- was silently accepted, so
 *  a flag could be hidden where the search never reached. Independent review
 *  and the defect-class sweep found nineteen such instances between them. A
 *  grammar closes the class instead of the instances: the reader's accepted
 *  language is now exactly the writer's output language, plus unknown keys
 *  (whose values must still be well formed) so the format can grow.
 *
 */
#ifndef BELAY_CAPTURE_MANIFEST_LEX_H
#define BELAY_CAPTURE_MANIFEST_LEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* The writer's longest possible line is under 50 KB (two 4095-byte fields at
 * six bytes per escaped byte, plus fixed fields). Anything longer is not a
 * manifest line, and refusing it bounds the reader's memory. */
#define LINE_MAX_BYTES (64u * 1024u)
#define MAX_PAIRS      32

enum vkind { V_STR, V_INT, V_TRUE, V_ARR };

struct pair {
    const char *key;  size_t klen;
    enum vkind kind;
    const char *val;  size_t vlen;     /* raw span: string body, digits, or array body */
    size_t nelem;                      /* V_ARR: number of strings */
};

struct obj {
    struct pair p[MAX_PAIRS];
    size_t n;
};

/* Sets BELAY_ERR_CORRUPT "manifest: <msg>"; returns -1. */
int lex_corrupt(const char *msg);

/* One line of `f` into `line` (LINE_MAX_BYTES + 1), newline stripped:
 * 1 a line, 0 end of file, -1 an error. *lineno counts lines read. */
int lex_line(FILE *f, char *line, size_t *len, size_t *lineno);

/* One whole line into `o`, by the grammar above. Duplicate keys rejected. */
int lex_object(const char *s, size_t len, struct obj *o);

/* Known keys in the order of `order`; unknown keys only after every known one. */
int lex_order(const struct obj *o, const char *const *order, size_t n);

/* The pair with this key, or NULL. */
const struct pair *lex_get(const struct obj *o, const char *key);

/* A scanned string body, unescaped into `out` (no NUL appended). */
int lex_decode_string(const char *s, size_t n, char *out, size_t cap, size_t *outlen);

bool lex_is_lhex(char c);
int  lex_hexv(char c);

#endif
