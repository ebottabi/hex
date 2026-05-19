# hex-agent

> An autonomous coding + offensive-security agent in Rust.
> Multi-provider LLM, typed tool wrappers, streaming agent loop, hardened pentest pipeline.

```
                       ┌─────────────────────────────┐
                       │           USER              │
                       │  (TTY · ACP · CLI · script) │
                       └─────────────┬───────────────┘
                                     │
                                     ▼
                       ┌─────────────────────────────┐
                       │        hex (Rust bin)       │
                       │ ╔═════════════════════════╗ │
                       │ ║  AGENT LOOP (rig 0.37)  ║ │
                       │ ╚═════════════════════════╝ │
                       └──┬──────────────────────┬───┘
                          │                      │
              ┌───────────▼─────────┐  ┌─────────▼──────────┐
              │   LLM PROVIDERS     │  │   TOOLS REGISTRY   │
              │  groq · openai      │  │  read · grep · bash│
              │  anthropic · gemini │  │  nmap · nuclei ·   │
              │  ollama · openrouter│  │  hydra · 31 sec... │
              │  custom (any OAI)   │  │  + MCP (planned)   │
              └─────────────────────┘  └────────────────────┘
```

---

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [Anatomy of the agent loop](#anatomy-of-the-agent-loop)
- [How LLMs are called](#how-llms-are-called)
- [How tools are dispatched](#how-tools-are-dispatched)
- [Security tools registry (31 typed wrappers)](#security-tools-registry-31-typed-wrappers)
- [Pentest pipeline](#pentest-pipeline)
- [Validator & Scorecard](#validator--scorecard)
- [Cost budget](#cost-budget)
- [Sessions, context & compaction](#sessions-context--compaction)
- [Permission model & sandbox](#permission-model--sandbox)
- [Provider / model switching](#provider--model-switching)
- [Configuration](#configuration)
- [Slash commands](#slash-commands)
- [Deployment (GitOps)](#deployment-gitops)
- [Repo layout](#repo-layout)
- [Testing](#testing)

---

## Features

- **6 LLM providers**, one runtime: OpenRouter · OpenAI · Anthropic · Gemini · Groq · Ollama · any OpenAI-compatible endpoint.
- **Streaming agent loop** built on `rig` — token, reasoning, tool-call, and tool-result events flow through a `tokio::mpsc` channel.
- **31 typed security-tool wrappers** (nmap, nuclei, ffuf, hydra, hashcat, impacket, bloodhound, prowler, …) that return structured JSON instead of raw text.
- **Authorized pentest pipeline** with hard scope guards, evidence log, Validator A–D, Scorecard (Wilson lower-bound), and cost budget.
- **Slash commands** for in-session control: `/provider`, `/model`, `/mode`, `/compress`, `/pentest`, `/sessions`, etc.
- **Persistent sessions** under `~/.local/share/hex/sessions/` with token-aware auto-compaction.
- **Hardened systemd deployment** + GitHub Actions GitOps pipeline.

---

## Quick start

```bash
# 1. install (Linux, Ubuntu 22.04+)
sudo ./install-tools.sh             # 40+ security tools, idempotent
cargo build --release
sudo install -m 0755 target/release/hex /usr/local/bin/

# 2. set a key (any one)
export GROQ_API_KEY=...
# export OPENAI_API_KEY=... / ANTHROPIC_API_KEY=... / GEMINI_API_KEY=...

# 3. run
hex                                          # interactive coding assistant
hex --provider groq --model llama-3.3-70b-versatile

# 4. authorized pentest
hex --provider groq --model llama-3.3-70b-versatile \
    --authorized-pentest --scope example.com \
    --report ./report.md --max-cost 5.00
```

---

## Anatomy of the agent loop

The loop is **driven by `rig`'s `stream_chat().multi_turn(N)`**: the LLM yields a stream of events; tool calls are auto-dispatched to registered tools; results are fed back as new messages until the model emits `FinalResponse` (or `max_turns` is hit).

```
                                ┌────────────────────────────────────────┐
                                │                USER PROMPT             │
                                └──────────────────┬─────────────────────┘
                                                   │
              ┌────────────────────────────────────▼───────────────────────────────────┐
              │                          AGENT LOOP (rig)                              │
              │                                                                        │
              │   ╔══════════════ multi_turn(N) ══════════════════════════╗            │
              │   ║                                                       ║            │
              │   ║   ┌────────────┐    ┌───────────┐    ┌────────────┐   ║            │
              │   ║   │  PREAMBLE  │──►│  HISTORY  │──►│  LLM CHAT  │    ║            │
              │   ║   │ (system    │   │ (Session  │   │ (provider) │    ║            │
              │   ║   │  prompt)   │   │  msgs)    │   │  streaming │    ║            │
              │   ║   └────────────┘   └───────────┘   └──────┬─────┘    ║            │
              │   ║                                            │          ║            │
              │   ║                  ┌─────────────────────────▼────────┐ ║            │
              │   ║                  │  STREAM EVENTS (per delta):      │ ║            │
              │   ║                  │   • Token            (text)      │ ║            │
              │   ║                  │   • Reasoning        (CoT)       │ ║            │
              │   ║                  │   • ToolCall   ◄── parsed JSON   │ ║            │
              │   ║                  │   • ToolResult ◄── from registry │ ║            │
              │   ║                  │   • FinalResponse   (break)      │ ║            │
              │   ║                  └─────────────────┬────────────────┘ ║            │
              │   ║                                    │                  ║            │
              │   ║                       if ToolCall:                    ║            │
              │   ║                                    ▼                  ║            │
              │   ║   ┌────────────────────────────────────────────────┐  ║            │
              │   ║   │             TOOL DISPATCHER                    │  ║            │
              │   ║   │   permission check ──► sandbox ──► run         │  ║            │
              │   ║   │   serialize result ──► back to LLM as message  │  ║            │
              │   ║   └────────────────────────────────────────────────┘  ║            │
              │   ║                                    │                  ║            │
              │   ║                          (loop next turn)             ║            │
              │   ╚═══════════════════════════════════════════════════════╝            │
              │                                                                        │
              └────────────────────┬───────────────────────────────────────────────────┘
                                   ▼
                              ┌──────────┐
                              │  STDOUT  │  (UI: tokens streamed live, tool calls
                              │ + SESSION│   summarised, reasoning toggled, errors
                              │  STORE   │   coloured, permission prompts inline)
                              └──────────┘
```

**Event types** (`src/event.rs`): `AgentEvent::{Token, Reasoning, ToolCall, ToolResult, Done, Error}`. Consumed by either:
- `run_print` (one-shot CLI) — prints to stdout directly.
- `spawn_agent` (interactive UI) — channels events to the renderer.

---

## How LLMs are called

Provider abstraction in `src/provider/mod.rs`:

```
                  CLI flags (--provider, --model, --api-key)
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │   ProviderKind       │
                       │   ::from_str(...)    │
                       └──────────┬───────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │   create_client()    │
                       │   resolves API key   │
                       │   from env/CLI       │
                       └──────────┬───────────┘
                                  │
                  ┌───────────────┼───────────────┐
                  ▼               ▼               ▼
            ┌──────────┐    ┌──────────┐    ┌──────────┐
            │AnyClient │    │AnyClient │    │AnyClient │
            │::OpenAI  │    │::Groq    │    │::Ollama  │
            │(OAI v1)  │    │(OAI-cmpt)│    │(local)   │
            └─────┬────┘    └─────┬────┘    └─────┬────┘
                  └────────────┬──┴───────────────┘
                               ▼
                       ┌──────────────┐
                       │  AnyModel    │   ← typed completion model
                       └──────┬───────┘
                              ▼
                       ┌──────────────┐
                       │  AnyAgent    │   ← rig::Agent + tools + preamble
                       │  ::run_print │
                       │  ::spawn_runner
                       └──────────────┘
```

Every provider — Groq, gpt-oss-via-Groq, OpenRouter, local Ollama — funnels into the **same `AnyAgent` enum**, so the agent loop is provider-agnostic.

| Provider | Endpoint | Env var | Default model |
|---|---|---|---|
| openai | `api.openai.com/v1` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| anthropic | `api.anthropic.com` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5` |
| gemini | Google AI | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| groq | `api.groq.com/openai/v1` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| openrouter | `openrouter.ai/api/v1` | `OPENROUTER_API_KEY` | (any) |
| ollama | `localhost:11434` | — | `llama3.2` |
| custom | `$CUSTOM_BASE_URL` | `CUSTOM_API_KEY` | (any) |

---

## How tools are dispatched

Tools are registered into `rig::AgentBuilder` at build time. When the LLM emits a `tool_call`, `rig` looks up the tool by name, parses the JSON args into the typed input struct, invokes the async handler, and re-injects the (serialised) output as a `tool_result` message.

```
                       LLM emits tool_call(name, args_json)
                                       │
                                       ▼
                         ┌────────────────────────────┐
                         │   Tool dispatcher (rig)    │
                         │   - lookup tool by name    │
                         │   - parse args -> struct   │
                         └──────────────┬─────────────┘
                                        │
                          ┌─────────────┼─────────────┐
                          ▼             ▼             ▼
                  ┌────────────┐ ┌────────────┐ ┌────────────┐
                  │ permission │ │  sandbox   │ │  evidence  │
                  │ check      │ │  (cwd,     │ │  log       │
                  │ (allow/ask)│ │  net?, ro?)│ │  (pentest) │
                  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
                        │              │              │
                        └──────────────┼──────────────┘
                                       ▼
                         ┌────────────────────────────┐
                         │  Tool::call(input) -> Out  │
                         │  (typed Result<Out, Err>)  │
                         └──────────────┬─────────────┘
                                        ▼
                                  Output → JSON
                                        │
                                        ▼
                       LLM receives tool_result, continues
```

Each tool is a Rust struct implementing `rig::tool::Tool` with `INPUT` and `OUTPUT` types — all serde-typed, so the LLM never sees raw stdout unless the wrapper chooses to surface it.

---

## Security tools registry (31 typed wrappers)

Located in `src/agent/tools/sec/`. Each wrapper:
- Validates target against the **EngagementPolicy** (scope guard).
- Shells out to the binary with sanitized args (no shell expansion of LLM input).
- Parses output into a typed struct.
- Appends a record to `evidence.jsonl`.

```
recon ─── nmap · masscan · subfinder · dnsx · httpx · whatweb · naabu · amass*
web ───── nuclei · ffuf · nikto · whatweb · semgrep · trivy · gitleaks
creds ─── hydra · hashcat · john · kerbrute
AD ────── nxc · impacket · bloodhound_python
TLS ───── testssl · sslyze
RE/bin ── checksec · ropper · r2 · afl_fuzz
cloud ─── prowler · scoutsuite
NSM ───── tshark · suricata_eve · zeek_log
exploit ─ searchsploit
```

`*` = installed by `install-tools.sh` but not yet a typed wrapper — reachable via `bash` tool.

---

## Pentest pipeline

Authorized-only. Activated by either `--pentest` CLI mode or the `/pentest` slash. Gated by `--authorized-pentest` + non-empty `--scope`.

```
                       ┌─────────────────────────────────────┐
                       │   EngagementPolicy (immutable)      │
                       │   • target_scope:    [hosts/CIDRs]  │
                       │   • rules_of_engagement: [strings]  │
                       │   • authorized: true                │
                       └────────────────┬────────────────────┘
                                        │
                                        ▼
        ╔════════════════════════════════════════════════════════════════╗
        ║                       PIPELINE PHASES                          ║
        ║                                                                ║
        ║   ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌─────────┐   ║
        ║   │  RECON  │──►│ VALIDATE │──►│  ASSESS  │──►│ REPORT  │    ║
        ║   │ nmap+   │   │ status+  │   │ severity │   │ .md +    │    ║
        ║   │ recon   │   │ probes   │   │ ranking  │   │ evidence │    ║
        ║   └────┬────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘    ║
        ║        │             │              │              │          ║
        ║        ▼             ▼              ▼              ▼          ║
        ║   ┌──────────────────────────────────────────────────────┐    ║
        ║   │  evidence.jsonl   (append-only audit trail)          │    ║
        ║   └──────────────────────────────────────────────────────┘    ║
        ║                                                                ║
        ║   Between Validate & Assess:                                   ║
        ║                                                                ║
        ║         ┌──────────────────────────────────────────────┐       ║
        ║         │ VALIDATOR A → B → C → D  (per finding)       │       ║
        ║         │  • Drop  → finding removed                   │       ║
        ║         │  • Hedge → caveat appended                   │       ║
        ║         │  • Keep  → continue                          │       ║
        ║         └──────────────────────────────────────────────┘       ║
        ║                                                                ║
        ╚════════════════════════════════════════════════════════════════╝
                                        │
                                        ▼
                              ┌───────────────────┐
                              │ Markdown report   │
                              │ (severity-sorted) │
                              └───────────────────┘
```

Source: `src/pentest/{pipeline,engagement,evidence,validator,scorecard,cost,report}.rs`

---

## Validator & Scorecard

Each finding produced by the LLM passes through 4 validator stages before being recorded:

```
                       ┌──────────┐
   raw finding ───────►│ Stage A  │  heuristic: is target in scope?
                       └────┬─────┘
                            │ pass
                            ▼
                       ┌──────────┐
                       │ Stage B  │  evidence cross-ref (does evidence.jsonl
                       └────┬─────┘  support the claim?)
                            │ pass
                            ▼
                       ┌──────────┐
                       │ Stage C  │  severity calibration (CVSS-ish sanity)
                       └────┬─────┘
                            │ pass
                            ▼
                       ┌──────────┐
                       │ Stage D  │  LLM-reviewer pass (optional, gated by cost)
                       └────┬─────┘
                            │ pass
                            ▼
                       ┌──────────┐
                       │   KEPT   │  written to report
                       └──────────┘

   Verdicts:  Drop  ──► finding deleted
              Hedge ──► caveat string appended ("Hedged by validator: ...")
              Keep  ──► continue
```

### Scorecard (`~/.config/hex/scorecard.json`)

Per-rule **Wilson lower bound** on miss-rate. When `samples >= min_samples` (30) **and** Wilson upper bound on the miss-rate is below `miss_cap` (0.05) → a Drop verdict from the fast tier short-circuits the rest of the chain. Hedge / Keep always fall through.

```
   samples=42 misses=1  →  Wilson upper = 0.118  >  0.05  ──► do not short-circuit
   samples=42 misses=0  →  Wilson upper = 0.082  >  0.05  ──► do not short-circuit
   samples=200 misses=2 →  Wilson upper = 0.036  <  0.05  ──► short-circuit on Drop
```

---

## Cost budget

`src/pentest/cost.rs` — atomic micro-dollars (`AtomicU64`, 1 USD = 1_000_000) to avoid float drift. Every LLM call charges its tokens × per-1k price. When the budget hits zero, all subsequent calls return `BudgetExhausted`.

```
   --max-cost 5.00         HEX_MAX_COST=5.00          (default: ∞)
        │                          │                        │
        └────────────┬─────────────┘                        │
                     ▼                                      │
        ┌────────────────────────┐                          │
        │   CostBudget(usd)      │ ◄────────────────────────┘
        │   atomic micro-USD     │
        └───────────┬────────────┘
                    │ .charge(tokens_in, tokens_out, model)
                    ▼
            true  → continue
            false → BudgetExhausted error → pipeline stops cleanly
```

---

## Sessions, context & compaction

```
   ┌────────────────────────────────────────────────────────┐
   │                       Session                          │
   │  ┌──────────┬──────────┬────────────┬──────────────┐   │
   │  │ messages │ context  │ token est. │ compactions  │   │
   │  │ Vec<Msg> │ window   │ (running)  │  Vec<C>      │   │
   │  └────┬─────┴─────┬────┴──────┬─────┴──────┬───────┘   │
   │       │           │           │            │           │
   │       ▼           ▼           ▼            ▼           │
   │  on-disk JSON at  ~/.local/share/hex/sessions/<id>     │
   └────────────────────────────────────────────────────────┘

   When estimated_tokens > window − reserve:
        ──► auto-compact
            ──► summarise oldest N messages via current model
            ──► replace them with [system] summary message
            ──► keep last `keep_recent` tokens verbatim
```

Manual: `/compress` or `/compact [instructions]`.

---

## Permission model & sandbox

```
   Security modes:
     standard     ── ask on dangerous ops (write, edit, bash)
     restrictive  ── ask on everything, deny by default
     accept       ── auto-allow known-safe tools, ask on rest
     yolo         ── auto-allow everything (use with care)

   Per-tool flow:
         tool.call(args)
              │
              ▼
       PermCheck::evaluate(tool, args)
              │
        ┌─────┼─────┐
        ▼     ▼     ▼
      Allow  Ask  Deny
              │
              ▼
       UserDecision  (allowlist persisted to session)
```

Sandbox restricts `bash` and file tools to the session cwd by default; network is permitted but the **EngagementPolicy** intercepts every security-tool target.

---

## Provider / model switching

In-session, mid-conversation:

```
   /model llama-3.1-8b-instant
       ──► rebuild agent with new model on same provider

   /provider groq
       ──► resolve GROQ_API_KEY, build new client + agent,
           use ProviderKind::default_model() if no model given

   /provider anthropic claude-sonnet-4-5
       ──► full provider + model switch
```

CLI flags `--provider <name> --model <id>` set the initial state.

---

## Configuration

| Source | Path / mechanism |
|---|---|
| CLI flags | `hex --help` |
| Env vars | `OPENAI_API_KEY`, `GROQ_API_KEY`, `HEX_MAX_COST`, `RUST_LOG`, … |
| Config file | `~/.config/hex/config.toml` |
| Context files | `AGENTS.md`, `prompts/*.md` |
| Sessions | `~/.local/share/hex/sessions/` |
| Scorecard | `~/.config/hex/scorecard.json` |

---

## Slash commands

```
   /model [name]            show or switch model
   /provider [name] [m]     show or switch provider
   /sessions [id|delete id] list / load / delete sessions
   /reasoning  /thinking    toggle LLM reasoning trace
   /mode [m]                standard | restrictive | accept | yolo
   /compress [instructions] summarise old messages
   /pentest <scope> [report=path]   run authorized pentest in-session
   /prompt <name>           activate a named prompt from prompts/
   /history                 show global chat history
   /undo  /retry  /clear  /quit  /help
```

---

## Deployment (GitOps)

```
   git push main / tag v*
            │
            ▼
   ┌─────────────────────────┐
   │ GitHub Actions: build   │  fmt · clippy · test · release build · strip
   │ (ubuntu-latest)         │     │
   └────────────┬────────────┘     ▼  bundle.tar.gz + SHA256SUMS
                │
                ▼
   ┌─────────────────────────┐
   │ GitHub Actions: deploy  │  ssh deploy@server
   │ (env=production)        │     │
   └────────────┬────────────┘     ▼  scp bundle  →  sha256sum -c  →  deploy.sh
                                   │
                                   ▼
                       ┌─────────────────────────┐
                       │ Ubuntu server:          │
                       │  • install /usr/local/bin/hex
                       │  • run install-tools.sh  (40+ tools)
                       │  • install systemd unit  (hex-agent.service)
                       │  • systemctl restart     (oneshot health gate)
                       └─────────────────────────┘
```

See [`deploy/README.md`](deploy/README.md).

---

## Repo layout

```
hex-agent/
├── Cargo.toml
├── README.md                  ← this file
├── ARCHITECTURE.md            ← deep dive
├── install-tools.sh           ← Kali toolset installer (Ubuntu)
├── deploy/                    ← systemd + remote deploy script
│   ├── deploy.sh
│   ├── hex-agent.service
│   └── README.md
├── .github/workflows/
│   └── build-deploy.yml       ← GitOps pipeline
├── prompts/                   ← named system prompts (ask, code, debug, ...)
├── src/
│   ├── main.rs                ← entry, mode dispatch
│   ├── cli.rs                 ← arg parsing, RuntimeMode
│   ├── provider/              ← AnyClient/AnyModel/AnyAgent abstraction
│   ├── agent/
│   │   ├── builder.rs         ← preamble + tools + AgentBuilder
│   │   ├── runner.rs          ← stream_chat loop, AgentEvent emission
│   │   ├── prompt.rs          ← SYSTEM / PENTEST / COMPACTION prompts
│   │   └── tools/             ← typed tool wrappers
│   │       ├── (fs, bash, grep, find, list, todo, ...)
│   │       └── sec/           ← 31 security tool wrappers
│   ├── pentest/
│   │   ├── pipeline.rs        ← phase orchestration + validator integration
│   │   ├── engagement.rs      ← scope + ROE policy
│   │   ├── evidence.rs        ← append-only JSONL log
│   │   ├── validator.rs       ← stages A–D
│   │   ├── scorecard.rs       ← Wilson bound persistence
│   │   ├── cost.rs            ← atomic USD budget
│   │   ├── report.rs          ← markdown generator
│   │   └── runtime.rs         ← assembles executor + reviewer agents
│   ├── session/               ← persistent multi-turn sessions
│   ├── ui/                    ← TTY renderer, slash commands, input editor
│   ├── permission/            ← security modes + ask flow
│   ├── sandbox/               ← cwd / network gating
│   ├── config.rs              ← TOML config
│   └── context.rs             ← AGENTS.md / prompt loader
└── tests/                     ← integration + smoke tests
```

---

## Testing

```bash
cargo test                 # 142 unit + 1 smoke
cargo test --release
cargo clippy --all-targets
cargo fmt --all -- --check
```

CI runs all four on every push.

---

## License

TBD. Internal until first public release.

---

## Acknowledgements

- [`rig`](https://github.com/0xPlaygrounds/rig) — agentic LLM framework that powers the loop.
- `zerostack` — reference implementation hex-agent was ported from.
- Kali Linux + the wider offensive-security community for the tooling we wrap.
