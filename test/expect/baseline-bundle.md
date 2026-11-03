# Pin: the baseline bundle

**What this is.** What `belay baseline export` writes at reset, before the policy runs, and
`belay verify --baseline` reads after the episode: the baseline capture, the stored copies its
diff needs, and what each installed package's own database said of its files at reset. It leaves
the sandbox with its digest and is judged against by digest only (BELAY_DESIGN §6, 1 and 5). One
file, which belay writes and reads itself, uncompressed. Written by hand from the M2 structure the
author approved on 2026-11-03 (decisions 145-150), before any code (decision 151); approved by the
author 2026-11-03 (decision 157), with dpkg's MD5 checked at export (Q3, decision 158).

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. Any change a
reader of version 1 would misread is `belay_bundle` 2.

## Layout

| id | rule |
|---|---|
| B-1 | A bundle is a sequence of members, with nothing before, between or after them. A member is a header line followed by exactly `size` bytes of content (none when `size` is 0). The line is one JSON object in the manifest's canonical encoding (manifest-v1.md), keys in the order shown below, ending in `\n`, at most 65,536 bytes. |
| B-2 | The members come in this order: `bundle`, `manifest`, the `copy` members in ascending `sha256` order (none included), `packages`, `end`. Every other member is present exactly once. |

## Members

| id | member | header line | content |
|---|---|---|---|
| B-3 | `bundle` | `{"belay_bundle": 1, "size": 0, "created_ns": int, "belay_version": string, "scopes": [string], "hash_max_bytes": int, "protect_sha256": string or null}` | None. `belay_bundle` is the format version: a reader refuses any other. `scopes` (`scopes_b64` when not UTF-8) and `hash_max_bytes` are the manifest's, the latter raised when exported with a spec (protect-spec PS-C3). `protect_sha256` is the spec's digest when exported with one (protect-spec PS-R3), else `null`. |
| B-4 | `manifest` | `{"member": "manifest", "size": int, "sha256": string}` | The baseline manifest's bytes, all of them: manifest v2, from a full `check` (its trailer's `trusted` 0, `read_all` `check`). `sha256` is the digest of those bytes, which `verify`'s diff gives as `before_sha256`. |
| B-5 | `copy` | `{"member": "copy", "size": int, "sha256": string}` | One stored copy's bytes. There is one `copy` for each distinct `stored` key the manifest names, and none other; `sha256` is the key, and the bytes' digest. |
| B-6 | `packages` | `{"member": "packages", "size": int, "sha256": string, "outside_scope": int}` | NDJSON in the canonical encoding: one line per file a package database in the baseline lists (Package lines, below), sorted by `db`, then `package`, then path bytes; empty when no database is there. `outside_scope`: the files the databases list outside the scope -- counted, never checked, never silent. |
| B-7 | `end` | `{"member": "end", "size": 0, "members": int}` | None. `members` is the number of members before it. |

## Package lines (the `packages` member)

| id | key | type | value |
|---|---|---|---|
| B-P1 | `db` | string | `dpkg` or `pip`. |
| B-P2 | `package` | string | dpkg: `<package>:<arch>`, as its status stanza names it. pip: the distribution's name, as its dist-info directory names it. |
| B-P3 | `version` | string | The package's version, as its database gives it. |
| B-P4 | `path` / `path_b64` | string | The file, relative to the scope, written as the manifest writes paths. dpkg's paths are relative to its root, the directory above `var/lib/dpkg`; pip's are relative to the dist-info's parent, resolved lexically (`..` included). |
| B-P5 | `conffile` | bool | dpkg only, and only when `true`: listed in its stanza's `Conffiles`, not in `md5sums`. |
| B-P6 | `at_reset` | string | What the database said of the file at reset: `match` or `mismatch` (its hash against the file's bytes); `missing` (not in the manifest); `not_a_file`; `unverified` (in the manifest without a hash); `no_hash` (the database gives none: a pip row with an empty hash). dpkg's hash is MD5, which the manifest does not record: export computes it in the same read as the file's sha256, and that sha256 must be the manifest's (else the export fails: the file changed while it was exported). pip compares its RECORD's sha256 with the manifest's own, with no read (decision 158). |

## Its digest, and reading it

| id | rule |
|---|---|
| B-R1 | The bundle's digest is the sha256 of its bytes, all of them, as `sha256sum` prints it. `baseline export` prints it; the orchestrator keeps it outside the sandbox. |
| B-R2 | `verify` takes it as `--baseline-sha256 HEX` and refuses a bundle without it, or whose bytes hash to anything else (exit 3): it never reads a bundle the policy could have written. |
| B-R3 | A bundle with the right digest that breaks any row is refused as corrupt (exit 4). That covers an unknown member or key, a member out of order or missing, content shorter or longer than its `size`, a copy whose bytes do not hash to its key, a stored key with no copy or a copy no entry names, a manifest a strict reader refuses, package lines unsorted or repeated, and any byte after `end`. |
| B-R4 | `belay baseline export --scope DIR --out FILE [--protect SPEC] [--json]` refuses an `--out` inside the scope (exit 3). It reports every package line whose `at_reset` is not `match` as a baseline-integrity finding: what was already so at reset, never an episode flag (decision 158). With `--json` its output is one line, `{"bundle": <the file's path>, "sha256": <the digest>, "baseline_integrity": [{"db", "package", "version", "path" or "path_b64", "at_reset"}, ...]}`, the findings in the `packages` member's order. |
| B-R5 | `verify`'s capture leaves out exactly what the bundle's manifest's header lists as user excludes -- never the scope's configured excludes, which are state a policy could have changed -- so both sides walk the same paths; with `--to`, the checkpoint's own (decision 174). |
