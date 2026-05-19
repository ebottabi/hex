# HEX Architecture (Single Crate)

## Purpose

`hex` is a single-crate Rust agent architecture for:
- coding workflows (read/edit/write/run/test)
- authorized pentesting workflows (scoped recon, validation, reporting)

The runtime is designed to keep these two capabilities in one engine with strict permission and scope controls.

## Single-Crate Layout

```text
src/
  main.rs
  cli.rs
  config/
    mod.rs
  context/
    mod.rs
  event.rs
  provider/
    mod.rs
  agent/
    mod.rs
    builder.rs
    runner.rs
  tools/
    mod.rs
    read.rs
    write.rs
    edit.rs
    bash.rs
    grep.rs
    find_files.rs
    list_dir.rs
  permission/
    mod.rs
    checker.rs
  sandbox.rs
  session/
    mod.rs
    storage.rs
  ui/
    mod.rs
    renderer.rs
    input.rs
  extras/
    mod.rs
    loop/
      mod.rs
  pentest/
    mod.rs
```

## Subsystem Responsibilities

- `main.rs`
  - bootstrap flow: CLI -> config -> provider/mode selection.

- `cli.rs`
  - runtime mode and safety flags (`--pentest`, `--authorized-pentest`).

- `config/`
  - default provider/model/context window/sandbox settings.

- `context/`
  - system prompt and mode prompt composition state.

- `provider/`
  - model/provider abstraction boundary.

- `agent/`
  - builds executable agent profile and drives streaming run loop.

- `tools/`
  - structured contracts for file/system tooling.

- `permission/`
  - action policy and security mode enforcement (`standard/restrictive/accept/yolo` baseline).

- `sandbox.rs`
  - command execution isolation boundary.

- `session/`
  - conversation state and persistence abstraction.

- `ui/`
  - terminal interaction model (renderer + input state).

- `extras/loop/`
  - long-running iterative execution state.

- `pentest/`
  - engagement policy and phased plan model for authorized testing.

## Pentest Safety Contract

Any pentesting flow must require:
1. Explicit authorization signal (`authorized == true`)
2. Scope declaration (`target_scope` non-empty)
3. Rules of engagement attached to session context

Without these, the pentest subsystem should stay in deny mode.

## Next Build Steps

1. Add typed config file loading and env overrides.
2. Implement permission checker with per-tool pattern rules.
3. Implement concrete tools and sandboxed command execution.
4. Add provider clients and agent streaming integration.
5. Build the interactive TUI loop (events + renderer + slash commands).
6. Add scoped pentest workflows (recon -> validate -> report) with audit trail.
