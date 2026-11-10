/*
 *  Which inode-flag changes are a privilege change (test/expect/inode-flags.md):
 *  one rule, for the protect spec's no_write (PS-M1), policy.v1's
 *  privilege_changed and the receipt's privilege section.
 */
#ifndef BELAY_SCHEMA_IFLAGS_H
#define BELAY_SCHEMA_IFLAGS_H

#include <stdbool.h>
#include <stdint.h>

/* An entry's side of a diff: there or not, its type, its inode flags when
 * they were read. */
struct iflags_side {
    bool present;       /* the side records the entry */
    int type;           /* any number that is equal exactly when two sides' types are */
    bool dir;           /* that type is a directory */
    bool has;           /* its inode flags were read */
    uint64_t flags;
};

/* Whether the two sides' inode flags differ in a way that counts:
 *   IF-3  an entry added or removed: only when it holds a locking flag
 *         (immutable, append-only);
 *   IF-4  an entry whose type changed: judged as before the pin, any
 *         difference, flags that one side has and the other has not
 *         included (a file replaced by a symlink: a symlink has none);
 *   IF-5  one type at both ends, flags read on one side only: never (the
 *         diff says `unknown`, `iflags_unknown`);
 *   IF-2  a directory at both ends: only when a locking flag is set or
 *         cleared (ext4 sets a directory's hashed-index flag by itself);
 *   IF-4  anything else at both ends: any change.
 * The policy model's author read IF-4 and IF-5 the same way, from the pin
 * alone (scripts/policy-model/model.py, P56 and P57). */
bool iflags_change_counts(const struct iflags_side *before, const struct iflags_side *after);

#endif
