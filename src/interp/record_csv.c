#include "record_csv.h"

#include "belay/error.h"

#include <stdbool.h>
#include <string.h>

struct field { char b[RECORD_FIELD_MAX + 1]; size_t n; };

static int put(struct field *f, char c, size_t line) {
    if (f->n == RECORD_FIELD_MAX) {
        belay_err_set(BELAY_ERR_CORRUPT, 0, "RECORD: line %zu: a field over %u bytes", line,
                      RECORD_FIELD_MAX);
        return -1;
    }
    f->b[f->n++] = c;
    return 0;
}

int record_each(const char *buf, size_t len, record_fn fn, void *ctx) {
    static _Thread_local struct field fld[3];
    size_t i = 0, line = 1;
    while (i < len) {
        const size_t row_line = line;
        int nf = 0;
        bool blank_row = true;
        for (int k = 0; k < 3; k++) fld[k].n = 0;
        for (;;) {                                      /* one field */
            if (nf == 3) {
                belay_err_set(BELAY_ERR_CORRUPT, 0, "RECORD: line %zu: more than three fields", row_line);
                return -1;
            }
            struct field *f = &fld[nf++];
            if (i < len && buf[i] == '"') {
                blank_row = false;
                i++;
                for (;;) {
                    if (i == len) {
                        belay_err_set(BELAY_ERR_CORRUPT, 0, "RECORD: line %zu: unterminated quote", row_line);
                        return -1;
                    }
                    const char c = buf[i++];
                    if (c == '"') {
                        if (i < len && buf[i] == '"') { i++; if (put(f, '"', row_line)) return -1; continue; }
                        break;
                    }
                    if (c == '\n') line++;
                    if (put(f, c, row_line)) return -1;
                }
                if (i < len && buf[i] != ',' && buf[i] != '\n' && buf[i] != '\r') {
                    belay_err_set(BELAY_ERR_CORRUPT, 0, "RECORD: line %zu: text after a quoted field", row_line);
                    return -1;
                }
            } else {
                while (i < len && buf[i] != ',' && buf[i] != '\n' && buf[i] != '\r') {
                    if (buf[i] == '"') {
                        belay_err_set(BELAY_ERR_CORRUPT, 0, "RECORD: line %zu: a quote inside a field", row_line);
                        return -1;
                    }
                    blank_row = false;
                    if (put(f, buf[i++], row_line)) return -1;
                }
            }
            if (i < len && buf[i] == ',') { i++; blank_row = false; continue; }
            break;                                       /* end of row */
        }
        if (i < len && buf[i] == '\r') i++;
        if (i < len && buf[i] == '\n') { i++; line++; }
        else if (i < len) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "RECORD: line %zu: a carriage return mid-row", row_line);
            return -1;
        }
        if (blank_row && nf == 1) continue;
        if (nf != 3) {
            belay_err_set(BELAY_ERR_CORRUPT, 0, "RECORD: line %zu: %d fields, not three", row_line, nf);
            return -1;
        }
        for (int k = 0; k < 3; k++) fld[k].b[fld[k].n] = '\0';
        const struct record_row r = { fld[0].b, fld[1].b, fld[2].b, fld[0].n, fld[1].n, fld[2].n, row_line };
        const int rc = fn(&r, ctx);
        if (rc != 0) return rc;
    }
    return 0;
}
