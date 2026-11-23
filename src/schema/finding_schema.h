/*
 *  diff.v1's findings, defined once (pin: test/expect/finding-kinds.md;
 *  event records: test/expect/diff-events.md). Every kind an interpreter may
 *  emit: its fields and their types, where it may appear, and the template
 *  its text is rendered from. Interpreters give field values only; the core
 *  validates them against this table and renders the text, so a finding's
 *  text is always its template's. The spec's table is generated from here.
 */
#ifndef BELAY_SCHEMA_FINDING_SCHEMA_H
#define BELAY_SCHEMA_FINDING_SCHEMA_H

#include <stdbool.h>
#include <stddef.h>

/* 0 is no kind: a finding that was never set fails (audit R1). */
enum finding_kind {
    FK_UNSET,
    FK_COULD_NOT_INTERPRET, FK_INVALID_FINDING, FK_AND_MORE, FK_CONTENT_UNAVAILABLE,
    FK_TEXT_CHANGED, FK_TEXT_REWRITTEN, FK_TEXT_ADDED, FK_TEXT_REMOVED,
    FK_PIP_INSTALLED, FK_PIP_REMOVED, FK_PIP_UPGRADED, FK_PIP_DOWNGRADED, FK_PIP_VERSION_CHANGED,
    FK_PIP_REINSTALLED,
    FK_DPKG_INSTALLED, FK_DPKG_REMOVED, FK_DPKG_UPGRADED, FK_DPKG_DOWNGRADED, FK_DPKG_STATE_CHANGED,
    FK_GIT_HEAD_CHANGED, FK_GIT_REF_CREATED, FK_GIT_REF_DELETED, FK_GIT_REF_MOVED,
    FK_GIT_HOOK_ADDED, FK_GIT_HOOK_REMOVED, FK_GIT_HOOK_CHANGED, FK_GIT_HOOK_EXECUTABLE_CHANGED,
    FK_GIT_INDEX_CHANGED, FK_GIT_REFLOG_APPENDED, FK_GIT_REFLOG_MOVE, FK_GIT_REFLOG_REWRITTEN,
    FK_GIT_REFLOG_LINES_IGNORED,
    FK_GIT_HEAD_SWITCHED, FK_GIT_BRANCH_CREATED, FK_GIT_BRANCH_DELETED, FK_GIT_BRANCH_RENAMED,
    FK_GIT_COMMITS_ADDED, FK_GIT_HISTORY_REWRITTEN, FK_GIT_BRANCH_MOVED,
    /* The system interpreters (test/expect/system-interpreters.md). */
    FK_USER_ADDED, FK_USER_REMOVED, FK_USER_CHANGED, FK_USER_PASSWORD_IN_PASSWD, FK_GROUP_ADDED,
    FK_GROUP_REMOVED, FK_GROUP_MEMBERS_CHANGED, FK_PASSWORD_ENTRY_ADDED, FK_PASSWORD_ENTRY_REMOVED,
    FK_PASSWORD_ENTRY_CHANGED,
    FK_SUDO_RULE_ADDED, FK_SUDO_RULE_REMOVED, FK_SUDO_LINE_ADDED, FK_SUDO_LINE_REMOVED,
    FK_SUDOERS_FILE_NOT_READ_BY_SUDO,
    FK_CRON_JOB_ADDED, FK_CRON_JOB_REMOVED, FK_CRON_ENV_CHANGED, FK_CRON_SCRIPT_ADDED,
    FK_CRON_SCRIPT_REMOVED, FK_CRON_SCRIPT_CHANGED, FK_CRON_FILE_NOT_RUN,
    FK_UNIT_LINKED, FK_UNIT_UNLINKED, FK_UNIT_MASKED, FK_UNIT_UNMASKED, FK_UNIT_FILE_ADDED,
    FK_UNIT_FILE_REMOVED, FK_UNIT_FILE_CHANGED, FK_UNIT_OVERRIDES_PACKAGED, FK_UNIT_ALIAS_ADDED,
    FK_UNIT_ALIAS_REMOVED, FK_INIT_SCRIPT_ADDED, FK_INIT_SCRIPT_REMOVED, FK_INIT_SCRIPT_CHANGED,
    FK_TIMER_FILE_ADDED, FK_TIMER_FILE_REMOVED,
    FK_SSH_KEY_ADDED, FK_SSH_KEY_REMOVED, FK_SSH_CA_ADDED, FK_SSH_CA_REMOVED,
    FK_TRUST_ANCHOR_ADDED, FK_TRUST_ANCHOR_REMOVED,
    FK_CONFIG_KEY_ADDED, FK_CONFIG_KEY_REMOVED, FK_CONFIG_KEY_CHANGED, FK_CONFIG_NOT_KEYED,
    /* The kernel record (test/expect/kernel-record.md K13). */
    FK_TOUCHED,
    FK_COUNT
};

/* FT_BYTES: up to FINDING_BYTES_MAX bytes, written "<name>" when UTF-8 and
 * "<name>_b64" otherwise, as the manifest writes bytes (decision 2026-10-31, b). */
enum field_type { FT_UNSET, FT_INT, FT_STRING, FT_BOOL, FT_BYTES, FT_LIST };
/* FT_LIST: a JSON array of at most FINDING_LIST_MAX strings, each as a
 * string field is; joined by ", " in the text (finding-kinds.md, "Types of
 * the system interpreters' fields"). */
#define FINDING_LIST_MAX 256u

#define LV_PATH  1u
#define LV_EVENT 2u
#define FINDING_FIELDS_MAX 8
#define FINDING_STRING_MAX 1024u        /* bytes of a string field, and of the text */
#define FINDING_BYTES_MAX 4095u         /* bytes of a bytes field: addendum A4's link target */
#define FINDINGS_PER_RECORD 4096u       /* then one and_more (decision Q4) */
#define EVENTS_PER_INTERP 65536u        /* then one and_more (diff-events E5) */

/* Which interpreters may emit a kind: a mask of 1 << belay_interp_id.
 * IN_CORE is none: the core's own kinds (decision P5). */
#define IN_CORE 0u

/* optional: absent exactly when the kind's meaning says (`?` in the pin).
 * nullable: the value may be JSON null (`/null` in the pin); no template
 * names such a field. */
struct finding_field { const char *name; enum field_type type; bool optional; bool nullable; };

struct finding_kind_def {
    const char *name;
    unsigned interps;                     /* IN_* mask */
    unsigned levels;                      /* LV_* mask */
    struct finding_field field[FINDING_FIELDS_MAX];   /* in order; name NULL ends */
    const char *text;                     /* the template: {field} is replaced */
    const char *meaning;                  /* the spec's table (generated) */
    const char *text_partial;             /* the template when an optional field is absent */
};

extern const struct finding_kind_def FINDING_KINDS[FK_COUNT];

/* The rules of event records (diff-events.md), by id ("E1 placement"). */
#define EVENT_RULE_COUNT 13
struct event_rule { const char *id, *statement; };
extern const struct event_rule EVENT_RULES[EVENT_RULE_COUNT];

/* The number of fields of `k`. */
size_t finding_nfields(enum finding_kind k);

#endif
