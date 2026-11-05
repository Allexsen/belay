# Pin: the protect spec, version 2

**What this is.** Version 2 of the protect spec: `no_write` also forbids deleting the path. Deleting is a
write to the file's existence. Replaying 2,115 published agent runs found two where a file a task said not
to write was deleted, and a spec of `no_write` alone said nothing. A version 2 spec is a version 1 spec --
`protect-spec.md`, which stays as the record of version 1 -- with exactly the changes below. Everything
not listed here is as `protect-spec.md` says.

`protect-spec.md` says changing a key's meaning is `belay_protect` 2. Version 1 is dropped, not kept beside
it (author, 2026-11-05): one meaning of `no_write` in the code, and no spec that keeps the gap.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

| id | rule |
|---|---|
| PV2-1 | `belay_protect` is `2`. A reader refuses any other value, `1` included: nothing is judged (exit 2, as PS-R2), and the message names what to do: `belay_protect is not 2 (version 1 specs are refused: no_write now forbids deleting; say 2)`. |
| PV2-2 | `no_write`: as PS-M1, and also a path matched before whose outcome is `removed`. That is `protected_path_deleted`, not `protected_path_written`. |
| PV2-3 | `no_delete` is unchanged (PS-M2) and stays valid: alone, it forbids deleting and allows writing. With `no_write` it adds nothing. A path gives one `protected_path_deleted`, whichever modes ask for it. |
| PV2-4 | `protected_path_deleted`'s text is `{path}: protected by {rule}, removed`, for both modes. Its `rule` is the pattern of the first rule that matches the path and has `no_write` or `no_delete`. Its fields, level and place in the flags' order are as policy-v1 says; this row replaces that row's text and its source. `belay_policy` stays 1: no key changes. |
| PV2-5 | PS-M5's "a side its modes read": `no_write` reads the before side for deletion too. V4-S2 already covers a one-sided `unknown` path. A path flagged at reset (`unreadable`, `unverified`) and then removed gives both `protected_path_deleted` and `protected_path_unverifiable`, as under `no_delete`. |
| PV2-6 | The bundle format does not change. A bundle holds its spec's digest, not its meaning: a bundle exported with a version 1 spec can only be verified with that spec, which is refused (PV2-1), so it must be exported again. A bundle exported without a spec is unaffected. |

## Example

```json
{"belay_protect": 2,
 "protect": [{"path": "tests/**", "mode": ["no_write", "no_create"]},
             {"path": "grader/check.py", "mode": ["no_write"],
              "expected_sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}]}
```
