#include "belay/path.h"
#include "belay/error.h"

#include <string.h>

/*
 *  Lexical only. See belay/path.h and BELAY_DESIGN.md §5.1.1.
 *
 *  Byte-transparent throughout: filesystem paths are bytes, not text. Nothing
 *  here inspects encoding, case-folds, or assumes UTF-8.
 */

int belay_path_normalize(char *out, size_t outsz, const char *in) {
    if (out == NULL || in == NULL || outsz == 0) {
        belay_err_set(BELAY_ERR_INVALID, 0, "normalize: null argument");
        return -1;
    }
    if (in[0] == '\0') {
        belay_err_set(BELAY_ERR_INVALID, 0, "normalize: empty path");
        return -1;
    }

    const int absolute = (in[0] == '/');
    size_t w = 0;

    /* Leading "/" is preserved exactly. Note POSIX allows an implementation
     * to treat a leading "//" specially; we collapse it, which is the
     * behaviour every Linux and macOS filesystem actually has. */
    if (absolute) {
        if (w + 1 >= outsz) {
            belay_err_set(BELAY_ERR_RANGE, 0, "normalize: result exceeds %zu bytes", outsz);
            return -1;
        }
        out[w++] = '/';
    }

    const char *p = in;
    int wrote_component = 0;

    while (*p != '\0') {
        /* Skip any run of separators. */
        while (*p == '/') p++;
        if (*p == '\0') break;

        /* Component spans [p, q). */
        const char *q = p;
        while (*q != '\0' && *q != '/') q++;
        const size_t len = (size_t)(q - p);

        if (len == 1 && p[0] == '.') {
            p = q;
            continue;               /* "." contributes nothing */
        }
        if (len == 2 && p[0] == '.' && p[1] == '.') {
            /* Rejected, not resolved: unsound under symlinks. */
            belay_err_set(BELAY_ERR_INVALID, 0,
                          "normalize: \"..\" is not permitted in a scope path");
            return -1;
        }

        /* Separator before every component except the first written one, and
         * never doubling the leading "/" of an absolute path. */
        if (wrote_component) {
            if (w + 1 >= outsz) {
                belay_err_set(BELAY_ERR_RANGE, 0, "normalize: result exceeds %zu bytes", outsz);
                return -1;
            }
            out[w++] = '/';
        }

        if (w + len >= outsz) {
            belay_err_set(BELAY_ERR_RANGE, 0, "normalize: result exceeds %zu bytes", outsz);
            return -1;
        }
        memcpy(out + w, p, len);
        w += len;
        wrote_component = 1;

        p = q;
    }

    /* Input that was only separators and/or "." components. "/" normalizes to
     * "/"; a relative "./" has no meaningful normal form, so it is "." . */
    if (!wrote_component) {
        if (absolute) {
            out[w] = '\0';          /* already holds "/" */
            return 0;
        }
        if (outsz < 2) {
            belay_err_set(BELAY_ERR_RANGE, 0, "normalize: result exceeds %zu bytes", outsz);
            return -1;
        }
        out[0] = '.';
        out[1] = '\0';
        return 0;
    }

    out[w] = '\0';
    return 0;
}

int belay_path_within_lexical(const char *root, const char *path) {
    if (root == NULL || path == NULL) {
        belay_err_set(BELAY_ERR_INVALID, 0, "within: null argument");
        return -1;
    }

    /* PATH_MAX is a convention rather than a hard kernel limit, so these
     * buffers bound what belay accepts as a scope argument, deliberately. */
    char nroot[4096];
    char npath[4096];

    if (belay_path_normalize(nroot, sizeof nroot, root) == -1) return -1;
    if (belay_path_normalize(npath, sizeof npath, path) == -1) return -1;

    /* Mixing an absolute root with a relative path (or vice versa) is not a
     * question this function can answer — it would depend on the cwd, which
     * is exactly the kind of hidden state §5.1.1 rules out. */
    if ((nroot[0] == '/') != (npath[0] == '/')) {
        belay_err_set(BELAY_ERR_INVALID, 0,
                      "within: cannot compare absolute and relative paths");
        return -1;
    }

    const size_t rlen = strlen(nroot);
    const size_t plen = strlen(npath);

    /* "." is the cwd, which contains every relative path. normalize() maps
     * every cwd spelling ("." "./" "././") to ".", so without this a scope of
     * "." -- the most natural way to spell "this directory" -- would reject
     * every file inside it. Mirrors the absolute case below. Must precede the
     * plen < rlen test so short paths do not fall through first. */
    if (rlen == 1 && nroot[0] == '.') return 1;

    if (plen < rlen) return 0;
    if (memcmp(npath, nroot, rlen) != 0) return 0;
    if (plen == rlen) return 1;                 /* identical */

    /* Component-wise, not string-prefix: "/ab" must not count as within "/a".
     * When root is "/" its trailing slash is already the separator. */
    if (rlen == 1 && nroot[0] == '/') return 1;
    return npath[rlen] == '/' ? 1 : 0;
}

/*
 *  Advisory only (§5.1.1): does a RELATIVE link target leave the scope,
 *  judged lexically from the link's own directory? ".." pops a component;
 *  popping above the scope root means outside. Symlinks along the way are
 *  not followed, so this can be wrong in both directions -- which is why it
 *  is an annotation and never an input to a decision. Previously only
 *  absolute targets were analysed, so a relative escape such as "../../etc"
 *  carried no annotation at all.
 */
static bool rel_target_escapes(const char *link_path, size_t link_len,
                               const char *target, size_t tlen) {
    /* depth = number of directory components above the link, inside scope */
    long depth = 0;
    for (size_t i = 0; i < link_len; i++) if (link_path[i] == '/') depth++;

    size_t i = 0;
    while (i < tlen) {
        size_t j = i;
        while (j < tlen && target[j] != '/') j++;
        const size_t n = j - i;
        if (n == 2 && target[i] == '.' && target[i + 1] == '.') {
            if (--depth < 0) return true;
        } else if (!(n == 0 || (n == 1 && target[i] == '.'))) {
            depth++;
        }
        i = j + 1;
    }
    return false;
}

bool belay_link_target_outside(const char *scope, const char *link_path, size_t link_len,
                               const char *target, size_t tlen) {
    if (tlen > 0 && target[0] == '/') {
        const int within = belay_path_within_lexical(scope, target);
        if (within == -1) belay_err_clear();
        return within != 1;
    }
    return rel_target_escapes(link_path, link_len, target, tlen);
}
