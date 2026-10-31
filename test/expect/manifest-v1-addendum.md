# Pin addendum: facts already true of the frozen manifest format, version 1

**What this is.** Facts true of v1 as it was frozen that `manifest-v1.md` (immutable) does not
state: limits and constants of the writer and the reader. Each was true of the code when its row
was added, established by running it (`test_addendum` checks each row against the code, in both
directions: every row has a check, every check a row). A limit that isn't pinned can be changed
with every pin test passing; these rows close that.

**Changing it.** Append-only: a row is added at the end, in its own PR, with the author's explicit
OK, and no existing row ever changes. CI fails when one does (`scripts/check-addendum.sh`, in the
`dco` job). A row that stops being true needs a format version bump, as `manifest-v1.md` does.

| id | fact | stated in | checked by |
|---|---|---|---|
| A1 | An inline `xattrs` array body is at most 8192 bytes. A larger set is recorded only as `xattrs_sha256`, and a reader rejects a longer inline body. | the Entries table, `xattrs` (generated) | `inline_xattrs_are_at_most_8192_bytes` |
| A2 | A manifest line is at most 65536 bytes; a reader rejects a longer line. | nowhere | `a_line_is_at_most_65536_bytes` |
| A3 | A `path` is at most 4095 bytes; a reader rejects a longer one. | nowhere | `a_path_is_at_most_4095_bytes` |
| A4 | A `link_target` is at most 4095 bytes; a reader rejects a longer one. | nowhere | `a_link_target_is_at_most_4095_bytes` |
| A5 | `caps` is 2 to 128 hex digits, an even number; a reader rejects anything else. | the Entries table, `caps` (generated), for "raw value, lowercase hex" only | `caps_is_at_most_128_hex_digits` |
| A6 | Every hex digit in a manifest is lowercase (`sha256`, `stored`, `caps`, `xattrs_sha256`, the digests in `xattrs`); a reader rejects an uppercase one. | the Entries table, `sha256` and `caps` (generated), not for the others | `hex_digits_are_lowercase` |
| A7 | A directory at depth 128 below the scope root (128 path components) is listed; one at depth 129 is recorded `unreadable`, with nothing below it. | the Entries table, `unreadable`: "beyond the depth limit (128)" (generated) | `the_depth_limit_is_128` |
| A8 | `mtime_ns` and `ctime_ns` saturate at the int64 bounds: a time after 2262 is recorded as 9223372036854775807. | the Entries table, `mtime_ns` (generated) | `timestamps_saturate_at_the_int64_bounds` |
