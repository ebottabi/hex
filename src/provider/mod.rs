use futures::StreamExt;
use rig::client::CompletionClient;
use rig::completion::{CompletionModel, Message};
use rig::providers::{anthropic, gemini, ollama, openai, openrouter};
use rig::streaming::StreamingChat;

pub use crate::agent::runner::AnyAgent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    OpenRouter,
    OpenAI,
    Anthropic,
    Gemini,
    Ollama,
    Groq,
    Custom,
}

impl ProviderKind {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "openrouter" => Some(Self::OpenRouter),
            "openai" => Some(Self::OpenAI),
            "anthropic" => Some(Self::Anthropic),
            "gemini" | "google" => Some(Self::Gemini),
            "ollama" => Some(Self::Ollama),
            "groq" => Some(Self::Groq),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ProviderKind::OpenRouter => "openrouter",
            ProviderKind::OpenAI => "openai",
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Gemini => "gemini",
            ProviderKind::Ollama => "ollama",
            ProviderKind::Groq => "groq",
            ProviderKind::Custom => "custom",
        }
    }

    /// A sensible default model for each provider, used when switching providers
    /// without specifying a model.
    pub fn default_model(self) -> &'static str {
        match self {
            ProviderKind::OpenRouter => "openai/gpt-4o-mini",
            ProviderKind::OpenAI => "gpt-4o-mini",
            ProviderKind::Anthropic => "claude-sonnet-4-5",
            ProviderKind::Gemini => "gemini-2.0-flash",
            ProviderKind::Ollama => "llama3.2",
            ProviderKind::Groq => "llama-3.3-70b-versatile",
            ProviderKind::Custom => "",
        }
    }
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

pub fn provider_env_var(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::OpenAI => "OPENAI_API_KEY",
        ProviderKind::Anthropic => "ANTHROPIC_API_KEY",
        ProviderKind::Gemini => "GEMINI_API_KEY",
        ProviderKind::Ollama => "OLLAMA_API_KEY",
        ProviderKind::OpenRouter => "OPENROUTER_API_KEY",
        ProviderKind::Groq => "GROQ_API_KEY",
        ProviderKind::Custom => "CUSTOM_API_KEY",
    }
}

pub fn resolve_api_key(kind: ProviderKind, cli_key: Option<&str>) -> anyhow::Result<String> {
    if let Some(key) = cli_key.filter(|k| !k.is_empty()) {
        tracing::warn!(
            "API key provided via --api-key is visible in process listings. Use the {} environment variable instead.",
            provider_env_var(kind)
        );
        return Ok(key.to_string());
    }

    let env_var = provider_env_var(kind);
    if let Ok(key) = std::env::var(env_var) {
        if !key.is_empty() {
            return Ok(key);
        }
    }

    if kind == ProviderKind::Ollama || kind == ProviderKind::Custom {
        return Ok(String::new());
    }

    anyhow::bail!(
        "No API key found for {kind:?}. Set the {env_var} environment variable or pass --api-key."
    )
}

pub enum AnyClient {
    OpenRouter(openrouter::Client),
    OpenAI(openai::CompletionsClient),
    Anthropic(anthropic::Client),
    Gemini(gemini::Client),
    Ollama(ollama::Client),
    Groq(openai::CompletionsClient),
    Custom(openai::CompletionsClient),
}

impl AnyClient {
    pub fn completion_model(&self, name: impl Into<String>) -> AnyModel {
        let name = name.into();
        match self {
            AnyClient::OpenRouter(c) => AnyModel::OpenRouter(c.completion_model(&name)),
            AnyClient::OpenAI(c) => AnyModel::OpenAI(c.completion_model(&name)),
            AnyClient::Anthropic(c) => AnyModel::Anthropic(c.completion_model(&name)),
            AnyClient::Gemini(c) => AnyModel::Gemini(c.completion_model(&name)),
            AnyClient::Ollama(c) => AnyModel::Ollama(c.completion_model(&name)),
            AnyClient::Groq(c) => AnyModel::Groq(c.completion_model(&name)),
            AnyClient::Custom(c) => AnyModel::Custom(c.completion_model(&name)),
        }
    }

    pub async fn compress_messages(
        &self,
        model_name: &str,
        messages: &[crate::session::SessionMessage],
        previous_summary: Option<&str>,
        instructions: Option<&str>,
    ) -> anyhow::Result<String> {
        let conversation = serialize_conversation(messages);
        let conversation = if conversation.len() > 6000 {
            let mut truncated = String::from(&conversation[..6000]);
            truncated.push_str("\n\n... [truncated]");
            truncated
        } else {
            conversation
        };

        let prompt = crate::agent::prompt::COMPACTION_PROMPT
            .replace("{conversation}", &conversation)
            .replace("{previous_summary}", previous_summary.unwrap_or("(none)"))
            .replace("{instructions}", instructions.unwrap_or("(none)"));

        summarize_with_model(self.completion_model(model_name.to_string()), prompt).await
    }
}

async fn summarize_with_model(model: AnyModel, prompt: String) -> anyhow::Result<String> {
    match model {
        AnyModel::OpenRouter(m) => run_summarizer(m, prompt).await,
        AnyModel::OpenAI(m) => run_summarizer(m, prompt).await,
        AnyModel::Anthropic(m) => run_summarizer(m, prompt).await,
        AnyModel::Gemini(m) => run_summarizer(m, prompt).await,
        AnyModel::Ollama(m) => run_summarizer(m, prompt).await,
        AnyModel::Groq(m) => run_summarizer(m, prompt).await,
        AnyModel::Custom(m) => run_summarizer(m, prompt).await,
    }
}

async fn run_summarizer<M>(model: M, prompt: String) -> anyhow::Result<String>
where
    M: CompletionModel + 'static,
    M::StreamingResponse: Send + Sync + Unpin + Clone + 'static,
{
    let agent = rig::agent::AgentBuilder::new(model)
        .preamble("You are a conversation summarizer.")
        .build();

    let mut stream = agent
        .stream_chat(prompt, Vec::<Message>::new())
        .multi_turn(1)
        .await;

    let mut response = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(rig::agent::MultiTurnStreamItem::StreamAssistantItem(
                rig::streaming::StreamedAssistantContent::Text(text),
            )) => response.push_str(&text.text),
            Ok(rig::agent::MultiTurnStreamItem::FinalResponse(res)) => {
                response = res.response().to_string();
                break;
            }
            Err(e) => return Err(anyhow::anyhow!("Compression failed: {}", e)),
            _ => {}
        }
    }

    if response.is_empty() {
        anyhow::bail!("Compression returned empty response");
    }

    Ok(response)
}

fn serialize_conversation(messages: &[crate::session::SessionMessage]) -> String {
    let mut result = String::new();
    for msg in messages {
        let role_tag = match msg.role {
            crate::session::MessageRole::User => "User",
            crate::session::MessageRole::Assistant => "Assistant",
            crate::session::MessageRole::System => "System",
        };
        result.push_str(&format!("[{}]: {}\n\n", role_tag, msg.content));
    }
    result
}

pub enum AnyModel {
    OpenRouter(openrouter::completion::CompletionModel),
    OpenAI(openai::completion::CompletionModel),
    Anthropic(anthropic::completion::CompletionModel),
    Gemini(gemini::completion::CompletionModel),
    Ollama(ollama::CompletionModel),
    Groq(openai::completion::CompletionModel),
    Custom(openai::completion::CompletionModel),
}

pub fn create_client(kind: ProviderKind, api_key: Option<&str>) -> anyhow::Result<AnyClient> {
    let key = resolve_api_key(kind, api_key)?;
    let base_url = if kind == ProviderKind::Custom {
        Some(std::env::var("CUSTOM_BASE_URL").map_err(|_| {
            anyhow::anyhow!("CUSTOM_BASE_URL environment variable must be set for custom provider")
        })?)
    } else {
        None
    };

    match kind {
        ProviderKind::OpenAI => {
            let b = openai::CompletionsClient::builder().api_key(&key);
            Ok(AnyClient::OpenAI(b.build()?))
        }
        ProviderKind::Anthropic => {
            let b = anthropic::Client::builder().api_key(&key);
            Ok(AnyClient::Anthropic(b.build()?))
        }
        ProviderKind::Gemini => {
            let b = gemini::Client::builder().api_key(&key);
            Ok(AnyClient::Gemini(b.build()?))
        }
        ProviderKind::Ollama => {
            let api_key: ollama::OllamaApiKey = key.as_str().into();
            let b = ollama::Client::builder().api_key(api_key);
            Ok(AnyClient::Ollama(b.build()?))
        }
        ProviderKind::OpenRouter => {
            let b = openrouter::Client::builder().api_key(&key);
            Ok(AnyClient::OpenRouter(b.build()?))
        }
        ProviderKind::Groq => {
            let b = openai::CompletionsClient::builder()
                .api_key(&key)
                .base_url("https://api.groq.com/openai/v1");
            Ok(AnyClient::Groq(b.build()?))
        }
        ProviderKind::Custom => {
            let base_url = base_url.expect("custom base url validated above");
            let b = openai::CompletionsClient::builder()
                .api_key(&key)
                .base_url(&base_url);
            Ok(AnyClient::Custom(b.build()?))
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderSettings {
    pub provider: ProviderKind,
    pub model: String,
}

pub trait ProviderClient {
    fn provider(&self) -> ProviderKind;
    fn model(&self) -> &str;
}

impl AnyAgent {
    pub async fn run_print(&self, prompt: &str, max_turns: usize) -> anyhow::Result<String> {
        match self {
            AnyAgent::OpenRouter(a) => crate::agent::runner::run_print(a, prompt, max_turns).await,
            AnyAgent::OpenAI(a) => crate::agent::runner::run_print(a, prompt, max_turns).await,
            AnyAgent::Anthropic(a) => crate::agent::runner::run_print(a, prompt, max_turns).await,
            AnyAgent::Gemini(a) => crate::agent::runner::run_print(a, prompt, max_turns).await,
            AnyAgent::Ollama(a) => crate::agent::runner::run_print(a, prompt, max_turns).await,
            AnyAgent::Groq(a) => crate::agent::runner::run_print(a, prompt, max_turns).await,
            AnyAgent::Custom(a) => crate::agent::runner::run_print(a, prompt, max_turns).await,
        }
    }

    pub fn spawn_runner(
        self,
        prompt: String,
        history: Vec<Message>,
    ) -> crate::agent::runner::AgentRunner {
        match self {
            AnyAgent::OpenRouter(a) => crate::agent::runner::spawn_agent(a, prompt, history),
            AnyAgent::OpenAI(a) => crate::agent::runner::spawn_agent(a, prompt, history),
            AnyAgent::Anthropic(a) => crate::agent::runner::spawn_agent(a, prompt, history),
            AnyAgent::Gemini(a) => crate::agent::runner::spawn_agent(a, prompt, history),
            AnyAgent::Ollama(a) => crate::agent::runner::spawn_agent(a, prompt, history),
            AnyAgent::Groq(a) => crate::agent::runner::spawn_agent(a, prompt, history),
            AnyAgent::Custom(a) => crate::agent::runner::spawn_agent(a, prompt, history),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn build_agent(
    model: AnyModel,
    cli: &crate::cli::Cli,
    cfg: &crate::config::Config,
    context: &crate::context::ContextFiles,
    permission: Option<crate::permission::checker::PermCheck>,
    ask_tx: Option<crate::permission::ask::AskSender>,
    sandbox: crate::sandbox::Sandbox,
    reasoning_enabled: bool,
) -> AnyAgent {
    crate::agent::builder::build_agent(
        model,
        cli,
        cfg,
        context,
        permission,
        ask_tx,
        sandbox,
        reasoning_enabled,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_groq_provider() {
        assert_eq!(ProviderKind::from_str("groq"), Some(ProviderKind::Groq));
        assert_eq!(ProviderKind::from_str("GROQ"), Some(ProviderKind::Groq));
        assert_eq!(ProviderKind::Groq.label(), "groq");
        assert_eq!(provider_env_var(ProviderKind::Groq), "GROQ_API_KEY");
        assert_eq!(
            ProviderKind::Groq.default_model(),
            "llama-3.3-70b-versatile"
        );
    }

    #[test]
    fn each_provider_has_distinct_label() {
        let kinds = [
            ProviderKind::OpenRouter,
            ProviderKind::OpenAI,
            ProviderKind::Anthropic,
            ProviderKind::Gemini,
            ProviderKind::Ollama,
            ProviderKind::Groq,
            ProviderKind::Custom,
        ];
        let labels: std::collections::HashSet<_> = kinds.iter().map(|k| k.label()).collect();
        assert_eq!(labels.len(), kinds.len());
    }
}
