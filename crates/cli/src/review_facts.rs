//! Source-bound reviewer notes. Facts are reusable evidence, never scanner proofs
//! or copied verdicts. The source and native input binding invalidate the store.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, path::Path};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Citation {
    path: String,
    start_line: usize,
    end_line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    excerpt: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Fact {
    contract: String,
    statement: String,
    citations: Vec<Citation>,
    remaining_checks: Vec<String>,
}

pub(super) fn run(
    root: &Path,
    inventory_dir: &Path,
    notes: Option<&Path>,
    saved: Option<&Path>,
    contract: Option<&str>,
    output: Option<&Path>,
) -> Result<Value, String> {
    let summary: Value = serde_json::from_slice(
        &fs::read(inventory_dir.join("inventory.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let cache: mehscan_engine::investigation::ReviewInventory = serde_json::from_slice(
        &fs::read(inventory_dir.join("scan-cache.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    mehscan_engine::investigation::validate_review_inventory(root, &cache)
        .map_err(|e| e.to_string())?;
    if summary["source_fingerprint"] != cache.source_fingerprint
        || summary["input_fingerprint"] != cache.input_fingerprint().map_err(|e| e.to_string())?
    {
        return Err("inventory summary and source cache disagree; regenerate inventory".into());
    }
    let mut data: Value = serde_json::from_slice(
        &fs::read(notes.or(saved).ok_or("supply --notes or --facts")?)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if saved.is_some()
        && (data["source_fingerprint"] != summary["source_fingerprint"]
            || data["input_fingerprint"] != summary["input_fingerprint"])
    {
        return Err("review facts have stale source or scanner inputs; inspect again".into());
    }
    let known: std::collections::BTreeSet<_> = summary["entries"]
        .as_array()
        .ok_or("missing inventory entries")?
        .iter()
        .flat_map(super::review_sweep::contract_keys)
        .map(|(key, _, _)| key)
        .collect();
    let mut facts: Vec<Fact> = serde_json::from_value(data["facts"].take())
        .map_err(|e| format!("invalid reviewer facts: {e}"))?;
    let canonical_root = root.canonicalize().map_err(|e| e.to_string())?;
    for fact in &mut facts {
        if !known.contains(&fact.contract)
            || fact.statement.trim().is_empty()
            || fact.citations.is_empty()
        {
            return Err(
                "review fact requires a known contract, statement and source citations".into(),
            );
        }
        for citation in &mut fact.citations {
            let file = root
                .join(&citation.path)
                .canonicalize()
                .map_err(|e| e.to_string())?;
            if !file.starts_with(&canonical_root)
                || citation.start_line == 0
                || citation.end_line < citation.start_line
                || citation.end_line - citation.start_line >= 400
            {
                return Err("invalid review fact source range".into());
            }
            let source = fs::read_to_string(file).map_err(|e| e.to_string())?;
            let lines: Vec<_> = source.lines().collect();
            let selected = lines
                .get(citation.start_line - 1..citation.end_line)
                .ok_or("review fact range exceeds file")?
                .join("\n");
            if saved.is_some() && citation.excerpt.as_deref() != Some(selected.as_str()) {
                return Err("review fact cited source changed; inspect again".into());
            }
            citation.excerpt = Some(selected);
        }
    }
    if let Some(contract) = contract {
        facts.retain(|f| f.contract == contract);
    }
    let result = json!({"source_fingerprint":summary["source_fingerprint"],
        "input_fingerprint":summary["input_fingerprint"], "origin":"reviewer_source_note",
        "notice":"Source binding validates reuse, not the reviewer's reasoning. Compare each caller and effect; no verdict transfers.",
        "facts":facts});
    if let Some(output) = output {
        if output.exists() {
            return Err("refusing to overwrite review facts; use a new file".into());
        }
        fs::write(
            output,
            serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(result)
}
