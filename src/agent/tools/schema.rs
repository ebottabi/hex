//! Helper for sharing the *output* JSON Schema of a tool with the LLM.
//!
//! `rig` already forwards each tool's `name`, `description`, and the input
//! schema (`parameters`) to the provider. The output schema is not part of
//! that surface, so the model has no idea what shape the tool returns. This
//! helper derives the output schema from the typed `Output` struct via
//! `schemars` and appends it to the description string the LLM sees.

use schemars::{JsonSchema, schema_for};

/// Return `"{description}\n\nOutput schema (JSON): {schema}"` so the model
/// sees the exact shape of the tool result alongside the prose description.
///
/// Use at every tool's `definition()` site:
/// ```ignore
/// description: append_output_schema::<MyOutput>("Run my tool ..."),
/// ```
pub fn append_output_schema<O: JsonSchema>(description: &str) -> String {
    let schema = serde_json::to_value(schema_for!(O)).unwrap_or_else(|_| serde_json::json!({}));
    format!(
        "{desc}\n\nOutput schema (JSON): {schema}",
        desc = description.trim(),
        schema = schema
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::JsonSchema;
    use serde::Serialize;

    #[derive(Serialize, JsonSchema)]
    struct DemoOutput {
        ok: bool,
        items: Vec<String>,
    }

    #[test]
    fn appends_output_schema_with_keys() {
        let desc = append_output_schema::<DemoOutput>("Run the demo");
        assert!(desc.starts_with("Run the demo"));
        assert!(desc.contains("Output schema (JSON):"));
        assert!(desc.contains("\"ok\""));
        assert!(desc.contains("\"items\""));
    }

    #[test]
    fn trims_trailing_whitespace_in_description() {
        let desc = append_output_schema::<DemoOutput>("  Hello\n  ");
        assert!(desc.starts_with("Hello"));
    }
}

