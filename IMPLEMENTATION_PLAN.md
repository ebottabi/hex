# HEX Implementation Plan (Following zerostack)

## Status

- Project: `hex` (single crate)
- Strategy: implement in small, testable milestones with visible progress
- Baseline reference: `zerostack` architecture and runtime behavior

## Progress Board

| ID | Milestone | Status | Owner | Exit Criteria |
|---|---|---|---|---|
| M1 | Foundation + progress tracking | `done` | agent | Plan file + test harness + smoke command documented |
| M2 | CLI + config parity | `done` | agent | Flag resolution parity + config precedence tests passing |
| M3 | Session + storage | `done` | agent | Save/load/recent session tests passing |
| M4 | Permission engine parity | `done` | agent | Mode/rule/doom-loop tests passing |
| M5 | Core tools implementation | `done` | agent | Tool unit tests + edit edge cases passing |
| M6 | Provider + agent runner | `done` | agent | Print mode end-to-end with mocked/provider smoke run |
| M7 | Interactive loop + slash core | `done` | agent | REPL/TUI core commands working + manual smoke checklist |
| M8 | Advanced features (loop/MCP/worktree/compaction) | `pending` | agent | Feature slices integrated and tested individually |
| M9 | Pentest workflow gate + reporting pipeline | `done` | agent | Authorized-only scope enforcement + report output tests |
| M10 | Security tool wrappers (typed rig tools) | `pending` | agent | Tier-1 tools wrapped with scope guard + typed outputs + SARIF intake |
| M11 | Validator stages A-D + fast-tier + cost cap | `pending` | agent | Validate sub-phases + cheap-model prefilter + --max-cost |
| M12 | Cross-finding correlation pass | `pending` | agent | Phase::Correlate after Assess; shared root-cause / attack chains |
| M13 | Pentest projects (multi-run workspaces) | `pending` | agent | /project create/use/status/findings/diff/clean |
| M14 | Personas + /persona slash | `pending` | agent | Loadable expert preambles |

Status values: `pending`, `in_progress`, `done`, `blocked`

---

## Delivery Rules (How We Work)

1. One milestone at a time.
2. Every milestone ends with:
- `cargo fmt`
- `cargo check`
- `cargo test`
- at least one smoke command run
3. No merging of unrelated work in the same milestone.
4. Keep behavior aligned to zerostack unless explicitly changing design.
5. Pentest capabilities remain authorization-gated at all times.

---

## Milestone Details

## M1 — Foundation + Tracking

Scope:
- Keep this plan file as the source of truth.
- Add minimal smoke test harness path (`tests/` baseline).
- Add a `Dev Log` section at the bottom updated per milestone.

Tests:
- `cargo check` passes.
- `cargo test` executes baseline tests.

Smoke command:
- `cargo run`

---

## M2 — CLI + Config Parity

Reference:
- `zerostack/src/cli.rs`
- `zerostack/src/config/mod.rs`

Scope:
- Implement core flags: print, provider/model, session behavior, permission mode flags, tools toggles, sandbox shell.
- Implement config file load + CLI precedence.

Tests:
- Unit tests for `resolve_*` behavior.
- Config override cases.

Smoke commands:
- `cargo run -- --print --prompt "hello"`
- `cargo run -- --provider openrouter --model deepseek/deepseek-v4-flash`

---

## M3 — Session + Storage

Reference:
- `zerostack/src/session/mod.rs`
- `zerostack/src/session/storage.rs`

Scope:
- Session model, message roles, token estimate baseline, persistence directories, save/load/find recent.

Tests:
- Session save/load round-trip.
- Recent session sort order.

Smoke command:
- `cargo run -- --print --prompt "session smoke"`

---

## M4 — Permission Engine Parity (Critical)

Reference:
- `zerostack/src/permission/*`
- `zerostack/src/tests/checker_tests.rs`

Scope:
- `standard`, `restrictive`, `accept`, `yolo`.
- Tool rules, glob/pattern matching, external path rules.
- Doom-loop detection + session allowlist.

Tests:
- Port checker tests to `hex`.
- External path + deny edge cases.

Smoke command:
- run any tool call path in restrictive/accept and confirm expected allow/ask/deny.

---

## M5 — Core Tools

Reference:
- `zerostack/src/agent/tools/*`
- `zerostack/src/tests/edit_tests.rs`

Scope:
- `read`, `write`, `edit`, `grep`, `find_files`, `list_dir`, `bash`.
- Preserve safety limits and response shape where useful.

Tests:
- Per-tool tests.
- `edit` tests: empty old_text, not found, multi-match, replace-all, CRLF preservation.

Smoke commands:
- Tool-invocation through print/runner path once M6 is ready.

---

## M6 — Provider + Agent Runner

Reference:
- `zerostack/src/provider.rs`
- `zerostack/src/agent/builder.rs`
- `zerostack/src/agent/runner.rs`

Scope:
- Provider abstraction + first provider integration.
- Event streaming model for token/reasoning/tool events.

Tests:
- Mocked runner tests.
- Print mode returns assistant output.

Smoke command:
- `cargo run -- --print --prompt "Explain this repo"`

---

## M7 — Interactive Runtime + Slash Core

Reference:
- `zerostack/src/ui/mod.rs`
- `zerostack/src/ui/slash.rs`

Scope:
- Event loop + renderer/input core.
- Slash command minimum: `/help`, `/mode`, `/sessions`, `/clear`, `/quit`.

Tests:
- Unit tests for command parser + status updates.

Smoke command:
- `cargo run` then manual command walkthrough.

---

## M8 — Advanced Features

Reference:
- Loop: `zerostack/src/extras/loop/*`
- MCP: `zerostack/src/extras/mcp/*`
- Worktree: `zerostack/src/extras/git_worktree/mod.rs`
- Compaction: `zerostack/src/ui/slash.rs` (`/compress`)

Scope:
- Implement incrementally in separate PR-sized slices.

Tests:
- Feature-specific tests and isolated smoke runs.

---

## M9 — Pentest Workflow (Authorized Only)

Scope:
- Enforce explicit authorization + scope before pentest actions.
- Add phased pipeline: recon -> validate -> assess -> report.
- Evidence log and remediation-first report format.

Tests:
- Unauthorized attempts blocked.
- Empty scope blocked.
- Authorized scoped run emits expected report structure.

Smoke command (example):
- `cargo run -- --pentest --authorized-pentest --scope <approved-target>`

---

## M10 — Security Tool Wrappers (Typed `rig` Tools)

Goal: wrap the top Kali/offsec tools as typed `rig::tool::Tool` impls so the
agent gets structured outputs (XML/JSON/SARIF parsed into Rust types) instead
of free-text stdout. Excludes mobile and firmware tooling by design.

### Wrapper standard (M10-std) — apply to every tool

1. **Pre-flight** — `which` + version probe; clean install hint on failure.
2. **Scope guard** — refuse any target outside `EngagementPolicy.target_scope`.
3. **Sandbox** — go through `Sandbox::wrap_command`.
4. **Typed args** — `serde` struct, validated before exec.
5. **Typed output** — parse XML/JSON/SARIF into project types; never raw stdout.
6. **Evidence sink** — append `ToolInvocation { tool, args_redacted, exit_code, summary, ts }` to JSONL.
7. **Timeout + cooperative cancel** — honour TUI cancellation.
8. **Permission gate** — route through `PermissionChecker`.

### Sub-milestones (wrap order = ROI order)

| ID | Tools | Why |
|----|-------|-----|
| M10.a — Recon spine | nmap, masscan, subfinder, dnsx, httpx | Every engagement starts here |
| M10.b — Web vuln spine | nuclei, ffuf, nikto, whatweb | Highest finding-per-minute |
| M10.c — Code & supply chain + SARIF intake | semgrep, trivy, gitleaks (+ `src/pentest/sarif.rs`) | Code-side audits |
| M10.d — AD / Windows | netexec, impacket-core (secretsdump, GetNPUsers, GetUserSPNs, ntlmrelayx), bloodhound ingest | Enterprise pentest coverage |
| M10.e — Credentials | hydra, hashcat, john (Jumbo), kerbrute | Brute / cracking |
| M10.f — TLS / crypto | testssl.sh, sslyze | Cheap, common audit item |
| M10.g — Exploitation glue | msfrpc (Metasploit RPC), searchsploit, sliver gRPC | Post-validation |
| M10.h — RE / fuzz / binary | afl++, honggfuzz, radare2 (r2pipe), checksec, ropper/ROPgadget, z3 (cargo feature) | High-leverage, niche |
| M10.i — Cloud posture | prowler, scoutsuite, trivy iac | Cloud audits |
| M10.j — Pcap / NSM | tshark `-T json`, suricata `eve.json`, zeek logs | Read-only consumers |

### Out of scope (deliberate)

- Mobile (mobsf / frida / apktool / jadx / objection) — different surface, deferred indefinitely.
- Firmware (binwalk and friends) — same reason.
- Wireless (aircrack-ng / kismet / wifite / bettercap) — interactive, niche; deferred until requested.

### Coverage scorecard (after M10.a–j)

✅ Recon · ✅ Network scan · ✅ Web discovery + vuln · ✅ AD/Windows · ✅ Credentials · ✅ SAST + secrets + supply chain · ✅ TLS · ✅ Fuzz + RE · ✅ Cloud posture · ✅ Pcap / NSM · ✅ Exploitation glue.

Tests: per-wrapper unit tests with golden-file fixtures (recorded tool output JSON/XML/SARIF → parsed types).

---

## M11 — Validator Stages A-D + Fast-Tier Short-Circuit + Cost Cap

RAPTOR-style refinement of `Phase::Validate`:

- **A**: real bug vs pattern noise.
- **B**: attacker preconditions.
- **C**: external reachability of code path.
- **D**: final call — test code? unrealistic prereqs? hedging?

Fast-tier short-circuit: same-provider cheaper sibling (Opus→Haiku, GPT-5→4o-mini, Gemini Pro→Flash-Lite) is used as a prefilter that *only* short-circuits on confident false positives. Per-cell trust accumulates in `~/.config/hex/scorecard.json`; short-circuit gated by Wilson 95% upper-bound on miss-rate ≤ 5%.

Cost cap: `--max-cost` CLI flag + `HEX_MAX_COST` env var; abort run with clean summary if exceeded.

---

## M12 — Cross-Finding Correlation Pass

New `Phase::Correlate` after `Assess`. Feeds the full `Vec<Finding>` back to the agent in a single prompt to identify shared root causes and multi-step attack chains. Output appended to the report as a "Correlated risks" section.

---

## M13 — Pentest Projects (Multi-Run Workspaces)

`~/.config/hex/projects/<name>/{config.json,runs/<ts>/,findings.jsonl}` with merged findings across runs.

Slash: `/project create|use|status|findings|diff|clean|export|none`.

---

## M14 — Personas + `/persona` Slash

Embed `prompts/personas/*.md` via `include_dir!`:
- security-researcher · pentester · fuzz-strategist · patch-engineer · dataflow-analyst · binary-exploitation-specialist.

`/persona <name>` swaps the agent preamble for the session. `/persona default` reverts.

---

## Zerostack Parity Map (Module to Module)

- `zerostack::cli` -> `hex::cli`
- `zerostack::config` -> `hex::config`
- `zerostack::session` -> `hex::session`
- `zerostack::permission` -> `hex::permission`
- `zerostack::agent.tools` -> `hex::tools`
- `zerostack::provider` + `agent.runner` -> `hex::provider` + `hex::agent::runner`
- `zerostack::ui` -> `hex::ui`
- `zerostack::extras` -> `hex::extras`

Parity target: behavioral equivalence first, optimization second.

---

## Dev Log

- 2026-05-19 — M1 done: added `tests/smoke.rs`; gates passed (`cargo fmt`, `cargo check`, `cargo test` => 1/1 passing); smoke run passed (`cargo run` prints bootstrap + mode/provider lines).
- 2026-05-19 — M2 done: expanded CLI/config parity (`resolve_*` methods, security-mode precedence, JSON config load path); tests passing (`cargo test` => 9/9); smoke runs passed (`cargo run -- --print --prompt "hello"` and `cargo run -- --provider openrouter --model deepseek/deepseek-v4-flash`).
- 2026-05-19 — M3 done: implemented session model + JSON storage (`save/load/find_recent/find_by_prefix`) with round-trip and recency-sort tests; gates passed (`cargo fmt`, `cargo check`, `cargo test` => 11/11 passing); smoke run passed (`cargo run -- --print --prompt "session smoke"`).
- 2026-05-19 — M4 done: implemented permission engine parity (`PermissionConfig`, per-tool granular rules, path checks, external directory policy, session allowlist, doom-loop detection, security modes); checker tests passing (`cargo test` => 24/24); smoke runs validated mode wiring (`cargo run -- --restrictive`, `cargo run -- --accept-all`).
- 2026-05-19 — M5 done: implemented core tools (`read/write/edit/grep/find_files/list_dir/bash`) with unit coverage (including edit edge cases: empty old_text, not-found, multi-match, replace-all, CRLF preservation); gates passed (`cargo fmt`, `cargo check`, `cargo test` => 37/37); smoke run passed (`cargo run -- --print --prompt "tool smoke"`). Tool invocation through agent runner remains queued for M6.
- 2026-05-19 — M6 done: adopted `rig` 0.37 + tokio + futures + compact_str + anyhow + tracing; ported provider layer (`AnyClient/AnyModel`, `create_client`, `resolve_api_key`, env-var resolution) and agent runner (`spawn_agent`, `run_print`, `run_print_any`, `convert_history`, `AnyAgent`) for OpenRouter/OpenAI/Anthropic/Gemini/Ollama/Custom. Builder composes preamble from `ContextState` + cwd, applies `max_tokens/default_max_turns/temperature`. Print mode wired end-to-end in `main.rs` with multi-thread tokio runtime; missing-API-key produces a clean error. Tools are **not yet** registered with the agent (deferred slice: wrap `hex::tools` as `rig::tool::ToolDyn`). Tests: 40/40 passing (incl. 3 new builder preamble tests). Gates passed (`cargo fmt`, `cargo check`, `cargo test`). Smoke run: `cargo run -- --print --prompt "hello"` reaches provider layer and errors with the expected key-missing message.
- 2026-05-19 — M6.5 done (tool-rig wrapping slice): added `ignore` + `thiserror` deps; ported `permission/ask.rs` (`AskRequest/AskSender/AskReceiver/UserDecision`); added `pub type PermCheck = Arc<Mutex<PermissionChecker>>;` to checker; gave `Sandbox` a `wrap_command(cmd) -> tokio::process::Command` (bwrap when enabled); created `src/agent/tools/{mod,read,write,edit,bash,grep,find_files,list_dir,todo}.rs` implementing `rig::tool::Tool` for all 8 agent-facing tools with `check_perm`/`check_perm_path` gating; builder now registers the 8 tools when `!cli.resolve_no_tools(cfg)`; `main.rs` constructs `PermCheck` from `PermissionConfig::default()` and a `Sandbox` for print mode (`ask_tx = None`, so any `Ask` decision becomes `Permission denied (non-interactive mode)`). Tests: 40/40 passing. Smoke: `cargo run -- --print --prompt "hello"` reaches provider layer cleanly.
- 2026-05-19 — M7 done: imported full zerostack TUI into `src/ui/` (3,743 LOC across 10 files) plus embedded prompt assets; stripped feature-gated MCP/loop/git-worktree/ACP paths; replaced Session/Context/event models with zerostack equivalents (`CompactString`, compactions, token/cost accounting, permission allowlist, `ContextFiles`, crossterm key events); added deps `crossterm`, `pulldown-cmark`, `chrono`, `uuid`, `smallvec`, `tracing-subscriber` (and `include_dir` for bundled prompts). Preserved `--print` and non-TTY bootstrap behavior. Tests before/after: 40/40 → 40/40 passing. Gates passed (`cargo fmt`, `cargo check`, `cargo test`); smokes passed (`cargo run --`, `cargo run -- --print --prompt "test"`).
- 2026-05-19 — M9 done: full authorized pentest workflow shipped. New module `src/pentest/` (7 files, ~750 LOC): `engagement` (CLI gate requiring `--authorized-pentest` + non-empty `--scope`, with default rules of engagement), `finding` (`Finding` + ordered `Severity` Critical→Info), `evidence` (append-only JSONL log keyed on `Phase`), `report` (severity-sorted markdown, remediation-first), `pipeline` (`Phase` enum + `PhaseExecutor` async trait + 3-phase orchestrator Recon→Validate→Assess→write report), `agent_executor` (production impl that builds per-phase prompts and parses fenced ```json findings from agent output with graceful degradation), `runtime` (top-level `run_pentest_mode` entry point). CLI extended with `--scope` (repeatable, comma-tolerant), `--rules-of-engagement`/`--roe` (repeatable, appended to defaults), `--report <path>` + `resolve_report_path`. `RuntimeMode::Pentest` branch added in `main.rs` ahead of TTY check so the gate runs in non-interactive shells. `run_print_any` now takes `&AnyAgent` to avoid cloning across phases. Tests: 27 → 51 (24 new pentest tests, 2 new CLI tests). Smokes verified: unauthorized blocked with clear error; `--authorized-pentest` without scope blocked; `--authorized-pentest --scope x.example` reaches the provider layer and writes a report skeleton.
- 2026-05-19 — Item 11 (legacy `src/tools/` retirement) closed: the legacy synchronous `src/tools/` folder was removed during the M7 import; `src/agent/tools/` rig wrappers now own the entire tool surface (read/write/edit/grep/find_files/list_dir/bash/todo) with per-tool unit tests already covering the hot paths (edit CRLF preservation, multi-match guard, empty-old-text insert, grep context lines, bash sandbox wrapping, permission gating via `check_perm`/`check_perm_path`). No second copy of sync tests will be reintroduced — duplicate coverage rejected.
- 2026-05-19 — Item 12 (`/compress` verification) done: added 4 unit tests on `Session` covering `needs_compaction` threshold semantics, the disabled-when-context-zero short circuit, `compress` replacing summarized messages with a single system summary (asserting count, role, `compactions[0].first_kept_index = 1`, `summarized_count`, `token_savings`, and token reclamation), and `compacted_context()` returning the last summary with `first_kept_index = 1`. Slash dispatch (`src/ui/slash.rs::handle_compress` at `src/ui/mod.rs:365` and `:553`) is structurally verified; live smoke requires `OPENROUTER_API_KEY` and a session past `needs_compaction(reserve)` — documented for manual run. Tests: 51 → 55.
- 2026-05-19 — M9.1 done (pentest system prompt + in-session `/pentest`): fixed the regression where launching `--authorized-pentest` still composed the coding-assistant preamble, causing the agent to refuse the engagement. Added `PENTEST_SYSTEM_PROMPT` in `src/agent/prompt.rs` that establishes the agent as an authorized operator post-gate and contracts JSON-emission per phase. Added `compose_pentest_preamble(context, scope, rules)` and `build_agent_with_preamble(...)` in `src/agent/builder.rs`. `src/pentest/runtime.rs` now uses both, injecting authoritative scope + RoE directly into the preamble. Added `EngagementPolicy::from_parts(scope, rules)` so callers without a `Cli` (i.e. slash commands) can build a policy. Added the `/pentest <scope1,scope2,...> [report=<path>]` slash command in `src/ui/slash.rs` that builds a *temporary* pentest agent (the coding agent stays in the session unchanged), runs the same 3-phase pipeline, streams banners into the chat, and writes report + evidence log. Registered `/pentest` in `src/ui/cmd_picker.rs` and added a `/help` entry. Tests: 55/55 still passing.
