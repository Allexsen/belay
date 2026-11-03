# Pin: manifest version 3

**What this is.** Version 3 of the manifest format: where a capture came from (decision 187, M3's
answers: "the manifest's `source` key: a pin PR, as a table"). A v3 manifest is a v2 manifest --
`manifest-v2.md`, and through it `manifest-v1.md` and its addendum, which stay as they are -- with
exactly the changes below. Everything not listed here is as v2 says, byte for byte. A new header key
is a new version, not a v2 addendum row: v2's readers reject an unknown key and v2 has no optional
key (V2-R2), and v0.1.0-alpha and alpha.2 already wrote v2 manifests that a reader must keep reading.
Written by hand; approved by the author 2026-11-03 (decision 198).

**Changing it.** In its own PR, presented as a table, after the author's explicit OK. Rules added
to v3 later go in `manifest-v3-addendum.md`, append-only, as v1's do.

## Lines

| id | line | key | type | value | when |
|---|---|---|---|---|---|
| V3-1 | header | `belay_manifest` | int | `3` | always |
| V3-2 | header | `source` | null or object | `null`: the scope was walked where belay ran (the walker; in-sandbox mode included). A container capture by the host reader (host-reader.md): `{"docker": string, "image": string}`, the container's full id and its image's id as the Docker daemon gives them (`docker inspect`'s `Id`, 64 lowercase hex digits, and `Image`, `sha256:` and 64 lowercase hex digits) | always (`null` included: never ambiguous) |
| V3-3 | header | `scopes` | (as v1) | With a `source` that is not `null`: the path inside the container, absolute, resolved in the container's merged view (host-reader.md, H-C3), never a host path. Otherwise as v1: the resolved scope root on the machine belay ran on | always |

Key order within each line: v2's keys in v2's order, then `source`. No key is optional.

## Readers and writers

| id | rule |
|---|---|
| V3-R1 | A reader that knows only v1 and v2 rejects a v3 manifest, loudly (an unknown `belay_manifest` value is rejected). |
| V3-R2 | A reader that knows v3 accepts `1`, `2` and `3`, each by its own key set, strictly: a v3 line missing a v3 key, or a v1 or v2 line carrying one, is rejected, as is any unknown key. A `source` object with any other key, a key missing, or a value of another form is rejected. |
| V3-R3 | belay writes v3 only, from the release that adds it. A v1 or v2 manifest already written stays valid and readable, and its source is `null`: the walker was the only capture those versions had. |
| V3-R4 | Two manifests compare only when their sources are equal (`null` and `null`, or the same container): otherwise `diff` and `verify` refuse (exit 3), as they refuse manifests of different scopes (manifest-v1, "Refuse to compare manifests of different scopes"). A host-reader capture's `dev` and `ino` are those of its layer files (host-reader.md, H-U7), which a walk inside the container does not see, and a different container is a different tree. |
| V3-R5 | Equal sources compare as v2's do; `source` decides nothing else in a diff. The diff header does not carry it: provenance in the diff stays V2-R4's versions and V2-R7's exclusions, and `source` is in the manifests, whose digests the trailer names. |

## Example

A container capture:

```
{"belay_manifest":3,"created_ns":1762000000000000000,"scopes":["/workspace"],"hash":"sha256","hash_max_bytes":67108864,"store_max_bytes":65536,"excluded":[],"walk_start_ns":1761999999990000000,"source":{"docker":"4f1c0e8a9b7d6c5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e","image":"sha256:91ef0af61f39ece4d6710e465df5ed6ca12112358344fd51ae6a3b886634148b"}}
...entries, as v1...
{"belay_manifest_end":1840,"vanished":0,"unreadable":0,"unstable":0,"mounts":1,"raced":0,"trusted":0,"reference":"none","read_all":"check"}
```
