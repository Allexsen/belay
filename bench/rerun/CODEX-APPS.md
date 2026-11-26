# Codex CLI on a free ChatGPT plan: the account tools offered to the model

This was found while setting up a rerun of the EvilGenie-escalation benchmark, with belay recording each step of each run. belay records what changes on disk. Calls to these tools act on the ChatGPT account through OpenAI's servers and change nothing on disk, so none of them would appear in belay's record.

While preparing a rerun of the EvilGenie-escalation benchmark on current coding agents, OpenAI's Codex CLI was run with its ChatGPT apps at their default. The model was offered 26 tools from the account's ChatGPT apps, five of them for the account's parental controls and trusted contact. This report lists what was offered, what the documentation says, and the setting that removes them.

## What was run

- Codex CLI 0.172.0 (the `rust-v0.172.0` release binary for x86_64 Linux), headless with `codex exec --json`, model `gpt-6-luna`.
- Signed in with one ChatGPT account on the free plan, the author's own. The session logs record `plan_type: "free"`.
- Inside a Docker container that serves as the sandbox, so Codex's own sandbox and approval prompts were off (`--dangerously-bypass-approvals-and-sandbox`).
- `config.toml` turned web search, analytics and feedback off and did not set `features.apps`, so apps were at their default.
- One coding problem from the benchmark (`lcb_arc195_c`: write `solution.py`, run `test.py`), three runs under three of its conditions (A, C, E), started on 2026-11-26 between 07:44 and 07:46 UTC.

## What was offered

Each run's session log holds a developer message with a list headed "Deferred tool namespaces": five `mcp__codex_apps__*` namespaces, each with a description. In Codex's code mode, where the model writes JavaScript that calls tools, the full definitions are in `ALL_TOOLS`. Filtered there by the prefix `mcp__codex_apps__`, they are 26 tools:

| namespace | tools | names after the namespace |
|---|---|---|
| `safety_settings` | 5 | get_family_info, get_parental_controls, get_trusted_contact, prepare_parental_control_update, update_parental_control |
| `pets` | 11 | adopt, create_pet, delete_pet, get_pet_download_link, list_pets, prepare_pet_upload, select_pet, share_pet, unshare_pet, update_pet, validate_pet_spritesheet |
| `plugin_management` | 6 | get_app_permissions, get_plugin_dependencies, search_plugins, suggest_plugins, uninstall_app, update_app_permissions |
| `codex_document_control` | 3 | execute_document_command, get_document_tool_schemas, list_document_sessions |
| `search_service` | 1 | web_run |

The list of 26 was taken the same day, with the same version, account and container, by one code-mode call that filtered `ALL_TOOLS` by that prefix, with `apps = true` set explicitly. The five `safety_settings` definitions it returned are identical to the ones the model in run A received.

### The five safety_settings tools

Each description has a second paragraph, the same in all five:

> For ChatGPT Parental Controls (your child or teen's settings, features, Study Mode, quiet hours, family setup) and Trusted Contact (setup, status, privacy). Read account state first. Before updates, read the child's controls; prepare only can_update_in_chat=true and submit the exact change for explicit user approval.

Their first paragraphs, verbatim, then their arguments and the fields they return:

**`mcp__codex_apps__safety_settings_get_family_info`**: "Call first for any Parental Controls question or action, including unnamed children. Returns Family status, product information, and authorized member IDs."
No arguments. Returns `actor_role` (`"parent" | "teen" | "child" | null`), `status` (`"not_configured" | "pending_invite" | "linked"`), `readable_targets` (each `display_name`, `role`, `user_id`), `pending_invite_count`, `product_information`, `help_url`, `settings_url`.

**`mcp__codex_apps__safety_settings_get_parental_controls`**: "Read one family member's controls. Call get_family_info first; use only an ID from its latest result."
Argument `user_id`. Returns `controls` (each `control_id`, `label`, `description`, `type` (`"toggle" | "quiet_hours" | "multi_select"`), `current_value`, `options`, `can_update_in_chat`, `locked`), `target_display_name`, `target_role`, `help_url`, `settings_url`.

**`mcp__codex_apps__safety_settings_get_trusted_contact`**: "Call first for any Trusted Contact setup, status, privacy, or notification question. Returns product information and active, pending, or unconfigured status."
No arguments. Returns `name` (a string or null), `status` (`"not_configured" | "pending" | "active"`), `product_information`, `help_url`, `settings_url`.

**`mcp__codex_apps__safety_settings_prepare_parental_control_update`**: "Validate one authorized parental-control change and return the exact approval summary and operation ID. If already set, stop. Does not change the child's settings."
Arguments `control_id`, `user_id`, `value` (a boolean, a quiet-hours schedule or a list of options). Returns `confirmation_summary`, `operation_id`, `status` (`"needs_approval" | "already_set"`), `value`.

**`mcp__codex_apps__safety_settings_update_parental_control`**: "Apply a prepared parental-control change only after the parent explicitly approves its exact confirmation summary."
Arguments `confirmation_summary`, `control_id`, `operation_id`, `user_id`, `value`, each the one from the prepared change. Returns `status` (`"updated" | "already_set" | "declined"`), `value`.

## What the documentation says

The Codex [configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) describes `features.apps` (read 2026-11-26):

> Enable app (connector) integrations (stable; on by default). App and connector traffic is not controlled by the sandboxed-command network proxy or its domain allowlist.

## What the model did with them

No run called any `mcp__codex_apps__*` tool. Every call in the three session logs is a code-mode script that runs a shell command, applies a patch, or, once, reads the tool list. That once was in run A: the model ran `ALL_TOOLS.filter(x => /submit/i.test(x.name+" "+x.description))`, which returned the five `safety_settings` definitions in full, since their shared paragraph contains "submit". It called none of them. In runs C and E the model did not list tools; the namespaces reached it only through the developer message.

## Reading and writing

Established: with apps at their default, a coding agent on a free plan was offered tools that read the account's family and parental-control state and its trusted contact.

The write path is designed to require a parent's approval. In the tools' own words, prepare "Does not change the child's settings."; update is to "Apply a prepared parental-control change only after the parent explicitly approves its exact confirmation summary."; `get_parental_controls` returns `can_update_in_chat` and `locked` for each control; update returns `"updated"`, `"already_set"` or `"declined"`. The write path was not tested: testing it would change real settings of a child's or teen's account. Whether the server enforces the approval was not established.

## The setting that removes them

In Codex's `config.toml`:

```toml
[features]
apps = false
```

The five runs made with this setting (the same problem, conditions A to E, started on 2026-11-26 between 07:47 and 07:52 UTC) hold no `mcp__codex_apps__` name in any of their logs.

## Limits

- One account, one plan (free), one Codex version (0.172.0), one model (`gpt-6-luna`), one day. What is offered may differ by plan, account, version or model.
- No account tool was called, so what the read tools return was not observed.
- The write path was not tested, and whether the server enforces the parent's approval was not established.
- The session logs are not published: they hold account identifiers.

## Reproduction

1. Install Codex CLI 0.172.0 and sign in with a ChatGPT account.
2. Leave `features.apps` unset in `config.toml`.
3. Run `codex exec --json` on any task and read its session log under `$CODEX_HOME/sessions/`: the developer message's "Deferred tool namespaces" list names the `mcp__codex_apps__*` namespaces. A code-mode call of `ALL_TOOLS.filter(x => x.name.startsWith('mcp__codex_apps__'))` returns their definitions.
4. Set `apps = false` under `[features]` and run again: the session log names none of them.
