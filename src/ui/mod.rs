mod cmd_picker;
mod events;
pub(crate) mod input;
mod markdown;
pub(crate) mod picker;
mod renderer;
mod slash;
mod status;
mod terminal;

use std::io;

use compact_str::CompactString;
use crossterm::event;
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEventKind};
use crossterm::style::Color;
use tokio::sync::mpsc;

use crate::cli::Cli;
use crate::config::Config;
use crate::context::ContextFiles;
use crate::event::{AgentEvent, UserEvent};
use crate::permission::ask::{AskReceiver, AskSender, UserDecision};
use crate::permission::checker::PermCheck;
use crate::provider::{AnyAgent, AnyClient};
use crate::sandbox::Sandbox;
use crate::session::{MessageRole, PermissionAllowEntry, Session};
use crate::ui::events::{render_session, sanitize_output};
use crate::ui::input::InputEditor;
use crate::ui::renderer::{Renderer, copy_to_clipboard};
use crate::ui::slash::{handle_compress, handle_slash};
use crate::ui::status::StatusLine;
use crate::ui::terminal::TerminalGuard;

const C_AGENT: Color = Color::White;
const C_ERROR: Color = Color::Red;
const C_TOOL: Color = Color::Yellow;
const C_PERM: Color = Color::Magenta;

#[inline]
pub(crate) fn resolve_color(color: Color, monochrome: bool) -> Color {
    if monochrome {
        let _ = color;
        Color::Reset
    } else {
        color
    }
}

/// Formats a tool call showing only the primary file/command parameter.
/// - read/write/edit → path
/// - grep → pattern (and path if both present)
/// - find_files → pattern
/// - list_dir → path
/// - bash → command (truncated to 60 chars)
/// - others → first string arg or nothing
fn format_tool_call_summary(name: &str, args: &serde_json::Value) -> String {
    let obj = match args {
        serde_json::Value::Object(map) => map,
        _ => return name.to_string(),
    };

    // Determine which key(s) to show based on tool name
    let primary_keys: &[&str] = match name {
        "read" | "write" | "edit" | "list_dir" => &["path"],
        "grep" => &["pattern", "path"],
        "find_files" => &["pattern"],
        "bash" => &["command"],
        _ => &[],
    };

    let mut shown = Vec::new();
    for key in primary_keys {
        if let Some(serde_json::Value::String(val)) = obj.get(*key) {
            let truncated = if val.len() > 60 {
                format!("\"{}...\"", &val[..57])
            } else {
                format!("\"{}\"", val)
            };
            shown.push(truncated);
        }
    }

    if shown.is_empty() {
        // fallback: show first string value if any
        if let Some((_, serde_json::Value::String(val))) = obj.iter().next() {
            let truncated = if val.len() > 60 {
                format!("\"{}...\"", &val[..57])
            } else {
                format!("\"{}\"", val)
            };
            format!("{} {}", name, truncated)
        } else {
            name.to_string()
        }
    } else {
        format!("{} {}", name, shown.join(" "))
    }
}

enum ToolResultSummary {
    Ok(String),
    Err(String),
}

/// Always produce a one-line indicator of what a tool returned so the user can
/// see whether each step actually accomplished anything (instead of staring at
/// a wall of `◈ httpx` lines while the model thrashes on empty results).
fn summarize_tool_result(output: &str, show_full: bool) -> ToolResultSummary {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return ToolResultSummary::Ok("empty result".to_string());
    }

    // Most failures bubble up as serialized ToolError JSON like
    // {"error":"tool 'searchsploit' not found in PATH..."} or as plain text
    // starting with "error" / "Error". Detect either shape and surface it.
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(err) = val
            .get("error")
            .and_then(|v| v.as_str())
            .or_else(|| val.get("Err").and_then(|v| v.as_str()))
            .or_else(|| val.get("err").and_then(|v| v.as_str()))
        {
            return ToolResultSummary::Err(first_line(err, 200).into_owned());
        }

        let mut bits: Vec<String> = Vec::new();
        if let Some(code) = val.get("exit_code").and_then(|v| v.as_i64()) {
            if code != 0 {
                let tail = val
                    .get("stderr_tail")
                    .and_then(|v| v.as_str())
                    .or_else(|| val.get("stderr").and_then(|v| v.as_str()))
                    .map(|s| first_line(s, 200).into_owned())
                    .unwrap_or_default();
                let msg = if tail.is_empty() {
                    format!("exit {}", code)
                } else {
                    format!("exit {} — {}", code, tail)
                };
                return ToolResultSummary::Err(msg);
            }
            bits.push(format!("exit {}", code));
        }
        if let Some(n) = val.get("findings").and_then(|v| v.as_array()) {
            bits.push(format!("{} finding(s)", n.len()));
        }
        if let Some(n) = val.get("hosts").and_then(|v| v.as_array()) {
            bits.push(format!("{} host(s)", n.len()));
        }
        if let Some(n) = val.get("subdomains").and_then(|v| v.as_array()) {
            bits.push(format!("{} subdomain(s)", n.len()));
        }
        if let Some(n) = val.get("urls").and_then(|v| v.as_array()) {
            bits.push(format!("{} url(s)", n.len()));
        }
        if let Some(n) = val.get("exploits").and_then(|v| v.as_array()) {
            bits.push(format!("{} exploit(s)", n.len()));
        }
        if let Some(n) = val.get("entries").and_then(|v| v.as_array()) {
            bits.push(format!("{} entry(ies)", n.len()));
        }
        if let Some(scope) = val.get("active_scope").and_then(|v| v.as_array()) {
            let names: Vec<String> = scope
                .iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect();
            if !names.is_empty() {
                bits.push(format!("scope: {}", names.join(",")));
            }
        }
        if !bits.is_empty() {
            return ToolResultSummary::Ok(bits.join(" · "));
        }
        // structured but unrecognised — fall through to byte-size summary.
        let len = trimmed.chars().count();
        return ToolResultSummary::Ok(format!("{} chars", len));
    }

    // Plain-text result.
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("error") || lower.starts_with("err:") {
        return ToolResultSummary::Err(first_line(trimmed, 200).into_owned());
    }
    if show_full {
        let head: String = trimmed.chars().take(200).collect();
        let len = trimmed.chars().count();
        if len > 200 {
            ToolResultSummary::Ok(format!("{}... ({} chars)", head, len))
        } else {
            ToolResultSummary::Ok(head)
        }
    } else {
        let head: String = first_line(trimmed, 120).into_owned();
        let len = trimmed.chars().count();
        if len > head.chars().count() {
            ToolResultSummary::Ok(format!("{} ({} chars)", head, len))
        } else {
            ToolResultSummary::Ok(head)
        }
    }
}

fn first_line(s: &str, max_chars: usize) -> std::borrow::Cow<'_, str> {
    let line = s.lines().next().unwrap_or("").trim();
    let count = line.chars().count();
    if count <= max_chars {
        std::borrow::Cow::Borrowed(line)
    } else {
        let truncated: String = line.chars().take(max_chars).collect();
        std::borrow::Cow::Owned(format!("{}…", truncated))
    }
}

fn refresh_display(
    renderer: &mut Renderer,
    input: &InputEditor,
    session: &Session,
    is_running: bool,
    loop_label: Option<&str>,
    prompt_name: Option<&str>,
    perm_mode: Option<&str>,
) -> io::Result<()> {
    renderer.render_viewport()?;
    let status = StatusLine::render(session, is_running, 0, loop_label, prompt_name, perm_mode);
    renderer.draw_bottom(&input.buffer, input.cursor, &status, is_running)?;
    if let Some(ref picker) = input.picker {
        picker.draw()?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_interactive(
    mut client: AnyClient,
    mut agent: AnyAgent,
    cli: &Cli,
    cfg: &Config,
    session: &mut Session,
    context: &mut ContextFiles,
    permission: Option<PermCheck>,
    ask_tx: Option<AskSender>,
    mut ask_rx: Option<AskReceiver>,
    sandbox: Sandbox,
) -> anyhow::Result<()> {
    let _guard = TerminalGuard::new()?;

    let mut renderer = Renderer::new()?;
    renderer.set_monochrome(cli.no_color);
    let mut input = InputEditor::new();
    input.set_monochrome(cli.no_color);
    input.set_prompt_names(context.prompts.keys().cloned().collect());
    input.load_global_history();
    let mut is_running = false;
    let mut agent_rx: Option<mpsc::Receiver<AgentEvent>> = None;
    let mut agent_line_started = false;
    let mut response_buf = String::new();
    let mut response_start_line: Option<usize> = None;
    let mut show_reasoning = true;
    let mut reasoning_enabled = true;
    let mut was_reasoning = false;
    let mut todo_tools_enabled = false;
    #[allow(unused_mut)]
    let mut loop_label: Option<String> = None;

    let perm_mode = || -> Option<String> {
        permission.as_ref().map(|p| {
            p.lock()
                .unwrap_or_else(|e| e.into_inner())
                .mode()
                .to_string()
        })
    };

    render_session(&mut renderer, session, cli, cfg, context)?;
    refresh_display(
        &mut renderer,
        &input,
        session,
        false,
        None,
        context.current_prompt_name.as_deref(),
        perm_mode().as_deref(),
    )?;

    let (user_tx, mut user_rx) = mpsc::channel::<UserEvent>(64);
    let user_tx_clone = user_tx.clone();
    std::thread::spawn(move || {
        loop {
            match event::read() {
                Ok(event::Event::Key(key)) => {
                    if user_tx_clone.blocking_send(UserEvent::Key(key)).is_err() {
                        break;
                    }
                }
                Ok(event::Event::Mouse(m)) => match m.kind {
                    MouseEventKind::ScrollUp => {
                        if user_tx_clone.blocking_send(UserEvent::ScrollUp).is_err() {
                            break;
                        }
                    }
                    MouseEventKind::ScrollDown => {
                        if user_tx_clone.blocking_send(UserEvent::ScrollDown).is_err() {
                            break;
                        }
                    }
                    MouseEventKind::Down(MouseButton::Left) => {
                        let _ = user_tx_clone.blocking_send(UserEvent::MouseDown {
                            row: m.row,
                            col: m.column,
                        });
                    }
                    MouseEventKind::Drag(MouseButton::Left) => {
                        let _ = user_tx_clone.blocking_send(UserEvent::MouseDrag {
                            row: m.row,
                            col: m.column,
                        });
                    }
                    MouseEventKind::Up(MouseButton::Left) => {
                        let _ = user_tx_clone.blocking_send(UserEvent::MouseUp {
                            row: m.row,
                            col: m.column,
                        });
                    }
                    _ => {}
                },
                Ok(event::Event::Paste(s)) => {
                    if user_tx_clone.blocking_send(UserEvent::Paste(s)).is_err() {
                        break;
                    }
                }
                Ok(event::Event::Resize(cols, rows)) => {
                    let _ = user_tx_clone.blocking_send(UserEvent::Resize(cols, rows));
                }
                Err(_) => break,
                _ => {}
            }
        }
    });

    loop {
        tokio::select! {
            Some(ev) = user_rx.recv() => {
                match ev {
                    UserEvent::Resize(cols, rows) => {
                        let _ = (cols, rows);
                        renderer.resize();
                        refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                        continue;
                    }
                    UserEvent::ScrollUp => {
                        renderer.scroll_line_up();
                        refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                        continue;
                    }
                    UserEvent::ScrollDown => {
                        renderer.scroll_line_down();
                        refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                        continue;
                    }
                    UserEvent::MouseDown { row, col: _ } => {
                        if row < renderer.visible_lines() as u16
                            && let Some(idx) = renderer.buffer_line_at_row(row) {
                                renderer.selection_active = true;
                                renderer.selection_start = Some(idx);
                                renderer.selection_end = Some(idx);
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                            }
                        continue;
                    }
                    UserEvent::MouseDrag { row, col: _ } => {
                        if renderer.selection_active
                            && let Some(idx) = renderer.buffer_line_at_row(row) {
                                renderer.selection_end = Some(idx);
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                            }
                        continue;
                    }
                    UserEvent::MouseUp { row, col: _ } => {
                        if renderer.selection_active {
                            if let Some(idx) = renderer.buffer_line_at_row(row) {
                                renderer.selection_end = Some(idx);
                            }
                            if let Some(text) = renderer.selected_text() {
                                copy_to_clipboard(&text);
                            }
                            renderer.clear_selection();
                            refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                        }
                        continue;
                    }
                    UserEvent::Paste(s) => {
                        input.insert_str(&s);
                        refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                        continue;
                    }
                    UserEvent::Key(key) => {
                        let is_ctrl_c = key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL);
                        let is_ctrl_d = key.code == KeyCode::Char('d')
                            && key.modifiers.contains(KeyModifiers::CONTROL);
                        if is_ctrl_c || is_ctrl_d {
                            if is_running {
                                is_running = false;
                                agent_rx = None;
                                renderer.write_line("interrupted", C_ERROR)?;
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                            } else {
                                break;
                            }
                            continue;
                        }

                        if renderer.selection_active && key.code == KeyCode::Char('y') {
                            if let Some(text) = renderer.selected_text() {
                                copy_to_clipboard(&text);
                                renderer.write_line("copied selection", Color::Green)?;
                            }
                            renderer.clear_selection();
                            refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                            continue;
                        }
                        if renderer.selection_active && key.code == KeyCode::Esc {
                            renderer.clear_selection();
                            refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                            continue;
                        }

                        let ctrl_r = key.code == KeyCode::Char('r')
                            && key.modifiers.contains(KeyModifiers::CONTROL);
                        if ctrl_r {
                            show_reasoning = !show_reasoning;
                            renderer.write_line(
                                &format!("reasoning visibility: {}", if show_reasoning { "on" } else { "off" }),
                                Color::White,
                            )?;
                            refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                            continue;
                        }

                        match key.code {
                            KeyCode::PageUp => {
                                renderer.scroll_page_up();
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                                continue;
                            }
                            KeyCode::PageDown => {
                                renderer.scroll_page_down();
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                                continue;
                            }
                            KeyCode::Home => {
                                renderer.scroll_to_top();
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                                continue;
                            }
                            KeyCode::End => {
                                renderer.scroll_to_bottom()?;
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                                continue;
                            }
                            _ => {}
                        }

                        if input.picker.as_ref().is_some_and(|p| p.active())
                            && input.handle_picker_key(key) {
                                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                                continue;
                            }

                        if let Some(text) = input.handle_key(key) {
                            if renderer.is_scrolling() {
                                renderer.scroll_to_bottom()?;
                            }
                            if text.starts_with('/') {
                                for line in text.lines() {
                                    let safe_line = sanitize_output(line);
                                    renderer.write_line(&format!("> {}", safe_line), Color::Green)?;
                                }
                                renderer.write_line("", Color::White)?;
                                let result = handle_slash(&text, &mut agent, &mut client, &mut renderer, session, cli, cfg, context, &mut show_reasoning, &mut reasoning_enabled, &mut is_running, &mut input, &permission, &ask_tx, &mut todo_tools_enabled, &sandbox).await;
                                match result {
                                Err(e) if e.to_string().starts_with("DEFER_COMPRESS:") => {
                                    let err_msg = e.to_string();
                                    let instructions = err_msg.strip_prefix("DEFER_COMPRESS:").and_then(|s| {
                                        let s = s.trim();
                                        if s.is_empty() || s == "(none)" { None } else { Some(s.to_string()) }
                                    });
                                        let compress_result = handle_compress(
                                            instructions.as_deref(),
                                            &mut agent, &client, &mut renderer, session, cli, cfg, context,
                                            reasoning_enabled,
                                            &permission, &ask_tx, &sandbox,
                                        ).await;
                                        if let Err(e) = compress_result {
                                            renderer.write_line(&format!("compress error: {}", e), C_ERROR)?;
                                        }
                                        let _ = crate::session::storage::save_session(session);
                                    }
                                    Err(e) => {
                                        if e.downcast_ref::<std::io::Error>().is_some_and(|e: &std::io::Error| e.kind() == std::io::ErrorKind::Interrupted) {
                                            break;
                                        }
                                        renderer.write_line(&format!("error: {}", e), C_ERROR)?;
                                    }
                                    Ok(_) => {
                                        if !cli.no_session
                                            && let Err(e) = crate::session::storage::save_session(session)
                                        {
                                            renderer.write_line(
                                                &format!("warning: failed to save session: {}", e),
                                                C_ERROR,
                                            )?;
                                        }
                                    }
                                }
                                if !cli.no_session
                                    && let Err(e) = crate::session::storage::save_session(session)
                                {
                                    renderer.write_line(
                                        &format!("warning: failed to save session: {}", e),
                                        C_ERROR,
                                    )?;
                                }
                            } else {
                                for line in text.lines() {
                                    let safe_line = sanitize_output(line);
                                    renderer.write_line(&format!("> {}", safe_line), Color::Green)?;
                                }
                                let _ = renderer.scroll_to_bottom();
                                renderer.write_line("", Color::White)?;

                                let history = crate::agent::runner::convert_history(session);
                                let runner = agent.clone().spawn_runner(
                                    text.to_string(),
                                    history,
                                );
                                agent_rx = Some(runner.event_rx);
                                is_running = true;

                                session.add_message(MessageRole::User, &text);
                                if !cli.no_session {
                                    let _ = crate::session::chat_history::append_entry(
                                        &crate::session::chat_history::ChatHistoryEntry {
                                            content: text.to_string(),
                                            timestamp: session.updated_at.clone(),
                                        },
                                    );
                                }
                            }
                        }
                        refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
                    }
                }
            }
            Some(event) = async {
                if let Some(rx) = &mut agent_rx {
                    rx.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                // Always snap the viewport to the bottom before applying an
                // agent event. Without this, if the user scrolls up while a
                // stream is in flight, `write_line` / `replace_from` mutate the
                // buffer while the viewport stays parked — when the user later
                // scrolls back down (or the stream finishes) the screen and
                // the tracked row counter desync and the UI corrupts.
                let _ = renderer.scroll_to_bottom();
                match event {
                    AgentEvent::Reasoning(text) => {
                        if !show_reasoning {
                            continue;
                        }
                        if !agent_line_started {
                            renderer.write("< ", Color::DarkMagenta)?;
                            agent_line_started = true;
                        }
                        let safe = sanitize_output(&text);
                        renderer.write(&safe, Color::DarkMagenta)?;
                        was_reasoning = true;
                    }
                    AgentEvent::Token(text) => {
                        if was_reasoning {
                            renderer.write_line("", Color::White)?;
                            agent_line_started = false;
                            was_reasoning = false;
                            response_buf.clear();
                            response_start_line = None;
                        }
                        let safe = sanitize_output(&text);
                        response_buf.push_str(&safe);

                        if response_buf.is_empty() {
                            continue;
                        }

                        let max_width = renderer.line_width();
                        let mut styled =
                            crate::ui::markdown::markdown_to_styled(&response_buf, max_width);

                        if !styled.is_empty() {
                            styled[0].text =
                                CompactString::from(format!("< {}", styled[0].text));
                        }

                        if let Some(start) = response_start_line {
                            renderer.replace_from(start, styled);
                        } else {
                            let start = renderer.buffer_len();
                            response_start_line = Some(start);
                            renderer.replace_from(start, styled);
                        }
                        renderer.render_viewport()?;
                        agent_line_started = true;
                    }
                    AgentEvent::ToolCall { name, args } => {
                        was_reasoning = false;
                        if agent_line_started {
                            renderer.write_line("", Color::White)?;
                            agent_line_started = false;
                        }
                        response_buf.clear();
                        response_start_line = None;
                        let line = format!("◈ {}", format_tool_call_summary(&name, &args));
                        renderer.write_line(&sanitize_output(&line), C_TOOL)?;
                    }
                    AgentEvent::ToolResult { output } => {
                        let show_details = cfg.show_tool_details.unwrap_or(false);
                        let summary = summarize_tool_result(&output, show_details);
                        let (line, color) = match summary {
                            ToolResultSummary::Ok(s) => (format!("  └ {}", s), Color::DarkGrey),
                            ToolResultSummary::Err(s) => (format!("  └ ✗ {}", s), C_ERROR),
                        };
                        renderer.write_line(&sanitize_output(&line), color)?;
                    }
                    AgentEvent::Done { response, tokens, cost } => {
                        was_reasoning = false;

                        if !response_buf.is_empty() {
                            let max_width = renderer.line_width();
                            let mut styled = crate::ui::markdown::markdown_to_styled(
                                &response_buf,
                                max_width,
                            );
                            if !styled.is_empty() {
                                styled[0].text =
                                    CompactString::from(format!("< {}", styled[0].text));
                            }
                            if let Some(start) = response_start_line {
                                renderer.replace_from(start, styled);
                                renderer.render_viewport()?;
                            }
                        } else if !agent_line_started {
                            renderer.write("< ", C_AGENT)?;
                        }

                        renderer.write_line("", Color::White)?;
                        renderer.write_line("", Color::White)?;
                        session.add_message(MessageRole::Assistant, &response);
                        session.total_tokens = session.total_tokens.saturating_add(tokens);
                        session.total_cost += cost;
                        agent_line_started = false;
                        response_buf.clear();
                        response_start_line = None;

                        let loop_running = false;

                        if !loop_running
                            && cfg.resolve_compact_enabled()
                            && session.needs_compaction(cfg.resolve_reserve_tokens())
                            && !cli.no_session
                        {
                            renderer.write_line("auto-compacting...", Color::DarkGrey)?;
                            let compress_result = handle_compress(
                                None,
                                &mut agent, &client, &mut renderer, session, cli, cfg, context,
                                reasoning_enabled,
                                &permission, &ask_tx, &sandbox,
                            ).await;
                            if let Err(e) = compress_result {
                                renderer.write_line(&format!("auto-compact error: {}", e), C_ERROR)?;
                            }
                        }

                        if !cli.no_session
                            && let Err(e) = crate::session::storage::save_session(session)
                        {
                            renderer.write_line(
                                &format!("warning: failed to save session: {}", e),
                                C_ERROR,
                            )?;
                        }
                        is_running = false;
                        agent_rx = None;
                    }
                    AgentEvent::Error(e) => {
                        was_reasoning = false;
                        let safe = sanitize_output(&e);
                        renderer.write_line(&format!("error: {}", safe), C_ERROR)?;
                        is_running = false;
                        agent_rx = None;
                        agent_line_started = false;
                        response_buf.clear();
                        response_start_line = None;
                    }
                }
                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
            }
            Some(ask_req) = async {
                if let Some(rx) = &mut ask_rx {
                    rx.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                was_reasoning = false;
                if agent_line_started {
                    renderer.write_line("", Color::White)?;
                    agent_line_started = false;
                }

                renderer.write_line(
                    &format!("[permission] {}: {}", ask_req.tool, ask_req.input),
                    C_PERM,
                )?;
                renderer.write_line(
                    "  (y) allow once  (a) allow always  (n) deny  (ESC) abort",
                    C_PERM,
                )?;

                let decision = loop {
                    tokio::select! {
                        Some(ev) = user_rx.recv() => {
                            if let UserEvent::Key(key) = ev {
                                match key.code {
                                    KeyCode::Char('y') => break UserDecision::AllowOnce,
                                    KeyCode::Char('a') => {
                                        let pattern = suggest_pattern(&ask_req.tool, &ask_req.input);
                                        renderer.write_line(
                                            &format!("  -> will allow: {}", pattern),
                                            Color::Green,
                                        )?;
                                        break UserDecision::AllowAlways(pattern);
                                    }
                                    KeyCode::Char('n') | KeyCode::Esc => break UserDecision::Deny,
                                    _ => {}
                                }
                            }
                        }
                    }
                };

                let allow_pattern = match &decision {
                    UserDecision::AllowAlways(p) => Some(p.clone()),
                    _ => None,
                };
                let _ = ask_req.reply.send(decision);

                if let Some(pattern) = allow_pattern {
                    session.permission_allowlist.push(PermissionAllowEntry {
                        tool: ask_req.tool.clone(),
                        pattern: pattern.clone(),
                    });
                    if !cli.no_session {
                        let _ = crate::session::storage::save_session(session);
                    }
                    renderer.write_line(
                        &format!("  allowed {} {} (saved to session)", ask_req.tool, pattern),
                        Color::Green,
                    )?;
                }

                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(200)), if is_running => {
                refresh_display(&mut renderer, &input, session, is_running, loop_label.as_deref(), context.current_prompt_name.as_deref(), perm_mode().as_deref())?;
            }
            else => {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }

    Ok(())
}

fn suggest_pattern(tool: &str, input: &str) -> String {
    match tool {
        "bash" => {
            let first = input.split_whitespace().next().unwrap_or("*");
            format!("{} *", first)
        }
        "read" | "write" | "edit" | "list_dir" => {
            let path = std::path::Path::new(input);
            let parent = path
                .parent()
                .map(|p| p.to_string_lossy())
                .unwrap_or(std::borrow::Cow::Borrowed("*"));
            if parent.is_empty() {
                "**".to_string()
            } else {
                format!("{}/*", parent)
            }
        }
        "grep" | "find_files" => {
            let first = input.split_whitespace().next().unwrap_or("*");
            format!("{}*", first)
        }
        _ => "*".to_string(),
    }
}
