use futures::StreamExt;
use rig::agent::{Agent, MultiTurnStreamItem};
use rig::completion::{CompletionModel, Message};
use rig::message::ToolResultContent;
use rig::streaming::{StreamedAssistantContent, StreamedUserContent, StreamingChat};
use tokio::sync::mpsc;

use crate::event::AgentEvent;
use crate::session::{MessageRole, Session};

pub struct AgentRunner {
    pub event_rx: mpsc::Receiver<AgentEvent>,
}

pub fn convert_history(session: &Session) -> Vec<Message> {
    let mut messages = Vec::with_capacity(session.messages.len());
    for msg in &session.messages {
        match msg.role {
            MessageRole::User => messages.push(Message::user(msg.content.clone())),
            MessageRole::Assistant => messages.push(Message::assistant(msg.content.clone())),
            MessageRole::System => {
                messages.push(Message::user(format!("[system] {}", msg.content)))
            }
        }
    }
    messages
}

pub fn spawn_agent<M, P>(agent: Agent<M, P>, prompt: String, history: Vec<Message>) -> AgentRunner
where
    M: CompletionModel + 'static,
    M::StreamingResponse: Send + Sync + Unpin + Clone + 'static,
    P: rig::agent::PromptHook<M> + 'static,
{
    let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(256);

    tokio::spawn(async move {
        let mut stream = agent.stream_chat(prompt, history).await;

        while let Some(item) = stream.next().await {
            match item {
                Ok(MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::Text(
                    text,
                ))) => {
                    let _ = event_tx.send(AgentEvent::Token(text.text.into())).await;
                }
                Ok(MultiTurnStreamItem::StreamAssistantItem(
                    StreamedAssistantContent::Reasoning(r),
                )) => {
                    let _ = event_tx
                        .send(AgentEvent::Reasoning(r.display_text().to_string().into()))
                        .await;
                }
                Ok(MultiTurnStreamItem::StreamAssistantItem(
                    StreamedAssistantContent::ToolCall { tool_call, .. },
                )) => {
                    let args = serde_json::from_str(&tool_call.function.arguments.to_string())
                        .unwrap_or(serde_json::Value::Null);
                    let _ = event_tx
                        .send(AgentEvent::ToolCall {
                            name: tool_call.function.name.to_string().into(),
                            args,
                        })
                        .await;
                }
                Ok(MultiTurnStreamItem::StreamUserItem(StreamedUserContent::ToolResult {
                    tool_result,
                    ..
                })) => {
                    let mut output = String::new();
                    for c in tool_result.content.iter() {
                        if let ToolResultContent::Text(t) = c {
                            if !output.is_empty() {
                                output.push('\n');
                            }
                            output.push_str(&t.text);
                        }
                    }
                    let _ = event_tx
                        .send(AgentEvent::ToolResult {
                            output: output.into(),
                        })
                        .await;
                }
                Ok(MultiTurnStreamItem::FinalResponse(res)) => {
                    let response_text = res.response().to_string();
                    let tokens = Session::estimate_tokens(&response_text);
                    let _ = event_tx
                        .send(AgentEvent::Done {
                            response: response_text.into(),
                            tokens,
                            cost: 0.0,
                        })
                        .await;
                    break;
                }
                Err(e) => {
                    let _ = event_tx.send(AgentEvent::Error(e.to_string().into())).await;
                    break;
                }
                _ => {}
            }
        }
    });

    AgentRunner { event_rx }
}

pub async fn run_print<M, P>(
    agent: &Agent<M, P>,
    prompt: &str,
    max_turns: usize,
) -> anyhow::Result<String>
where
    M: CompletionModel + 'static,
    M::StreamingResponse: Send + Sync + Unpin + Clone + 'static,
    P: rig::agent::PromptHook<M> + 'static,
{
    run_stream(agent, prompt, max_turns, false).await
}

pub async fn run_quiet<M, P>(
    agent: &Agent<M, P>,
    prompt: &str,
    max_turns: usize,
) -> anyhow::Result<String>
where
    M: CompletionModel + 'static,
    M::StreamingResponse: Send + Sync + Unpin + Clone + 'static,
    P: rig::agent::PromptHook<M> + 'static,
{
    run_stream(agent, prompt, max_turns, true).await
}

async fn run_stream<M, P>(
    agent: &Agent<M, P>,
    prompt: &str,
    max_turns: usize,
    quiet: bool,
) -> anyhow::Result<String>
where
    M: CompletionModel + 'static,
    M::StreamingResponse: Send + Sync + Unpin + Clone + 'static,
    P: rig::agent::PromptHook<M> + 'static,
{
    let mut stream = agent
        .stream_chat(prompt.to_string(), Vec::<Message>::new())
        .multi_turn(max_turns)
        .await;

    let mut full_response = String::new();

    while let Some(item) = stream.next().await {
        match item {
            Ok(MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::Text(text))) => {
                full_response.push_str(&text.text);
                if !quiet {
                    print!("{}", text.text);
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
            Ok(MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::Reasoning(
                r,
            ))) => {
                if !quiet {
                    eprint!("{}", r.display_text());
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
            }
            Ok(MultiTurnStreamItem::FinalResponse(_)) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }

    if !quiet {
        println!();
    }
    Ok(full_response)
}

pub async fn run_print_any(
    agent: &AnyAgent,
    prompt: &str,
    max_turns: usize,
) -> anyhow::Result<String> {
    match agent {
        AnyAgent::OpenRouter(a) => run_print(a, prompt, max_turns).await,
        AnyAgent::OpenAI(a) => run_print(a, prompt, max_turns).await,
        AnyAgent::Anthropic(a) => run_print(a, prompt, max_turns).await,
        AnyAgent::Gemini(a) => run_print(a, prompt, max_turns).await,
        AnyAgent::Ollama(a) => run_print(a, prompt, max_turns).await,
        AnyAgent::Groq(a) => run_print(a, prompt, max_turns).await,
        AnyAgent::Custom(a) => run_print(a, prompt, max_turns).await,
    }
}

pub async fn run_quiet_any(
    agent: &AnyAgent,
    prompt: &str,
    max_turns: usize,
) -> anyhow::Result<String> {
    match agent {
        AnyAgent::OpenRouter(a) => run_quiet(a, prompt, max_turns).await,
        AnyAgent::OpenAI(a) => run_quiet(a, prompt, max_turns).await,
        AnyAgent::Anthropic(a) => run_quiet(a, prompt, max_turns).await,
        AnyAgent::Gemini(a) => run_quiet(a, prompt, max_turns).await,
        AnyAgent::Ollama(a) => run_quiet(a, prompt, max_turns).await,
        AnyAgent::Groq(a) => run_quiet(a, prompt, max_turns).await,
        AnyAgent::Custom(a) => run_quiet(a, prompt, max_turns).await,
    }
}

use rig::providers::{anthropic, gemini, ollama, openai, openrouter};

#[derive(Clone)]
pub enum AnyAgent {
    OpenRouter(Agent<openrouter::completion::CompletionModel>),
    OpenAI(Agent<openai::completion::CompletionModel>),
    Anthropic(Agent<anthropic::completion::CompletionModel>),
    Gemini(Agent<gemini::completion::CompletionModel>),
    Ollama(Agent<ollama::CompletionModel>),
    Groq(Agent<openai::completion::CompletionModel>),
    Custom(Agent<openai::completion::CompletionModel>),
}
