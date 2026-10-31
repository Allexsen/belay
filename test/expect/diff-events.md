# Pin: event records (diff.v1)

**What this is.** The shape of diff.v1's event records, written by hand for the author's approval
(decision 2026-10-31, Q5). A path record carries findings about its own path only; a fact about a
package -- installed, removed, upgraded, downgraded, reinstalled -- is an event record, emitted by
the interpreter's end hook once every path has been seen, listing the paths it was derived from.
An event never decides an outcome: every path it lists has its own record, or is unchanged.

**Changing it.** In its own PR, presented as a table, after the author's explicit OK.

| rule | statement |
|---|---|
| E1 placement | Event records come after the last path record and before the trailer. A diff with none has none. |
| E2 shape | `{"event": "<kind>", "interp": "<interpreter>", <the kind's fields, in finding-kinds.md's order>, "text": "<its template>", "provisional": true, "paths": [...]}`. The kind is an `event`-level kind of finding-kinds.md. `provisional` is present, and `true`, exactly when a path the event was derived from has the outcome `unknown` (decision P7): the event may not hold. |
| E3 paths | The paths it was derived from, relative to the scope as in path records, sorted bytewise, each once, at least one (except `and_more`). `paths_b64` instead -- every element base64 -- when any is not valid UTF-8. |
| E4 order | By interpreter, in the order text, pip, dpkg, git; within one, as the interpreter defines it in finding-kinds.md's terms: pip by normalized name, then kind; dpkg by Package, then Architecture, then kind. The same inputs give the same bytes. |
| E5 bound | At most 65,536 event records per interpreter per diff: past that, the 65,536th is `{"event": "and_more", "interp": ..., "n": <that one and the rest>, "text": "and {n} more", "paths": []}`. An interpreter's per-diff state is bounded to match. |
| E6 failure | An interpreter whose end hook fails emits `{"event": "could_not_interpret", "interp": ..., "text": "could not interpret", "paths": [...], "paths_truncated": <n>}` and no other event: `paths` the first 1,024 of the paths it had claimed (bytewise), `paths_truncated` the number of the rest, present only when not 0 (decision P4). The diff does not fail. |
| E7 trailer | The trailer gains `events`: the number of event records. `belay_diff_end` still counts path records only. |
| E8 forward | A consumer ignores an event kind it does not know, as it ignores an unknown finding kind or field. |
| E9 invalid | An event an interpreter adds that breaks its kind's row -- a kind not its own, not event-level, or the core's; a field missing, extra, or not a string field's value; text over 1,024 bytes -- is replaced, in its place, by `{"event": "invalid_finding", "interp": ..., "text": "invalid finding", "paths": [<its paths>]}`; the interpreter's other events stand (decisions P1, P5). |
| E10 a file not interpreted | A file an interpreter claims and cannot interpret gives one `{"event": "could_not_interpret", "interp": ..., "text": "could not interpret", "paths": [<the files>]}` (and its path record `could_not_interpret`); the interpreter's other events stand: pip, a dist-info that cannot be named, a RECORD it must read that cannot be parsed, a name with RECORDs added and removed other than one of each; dpkg, a status that cannot be parsed (the class of decision P1). |
