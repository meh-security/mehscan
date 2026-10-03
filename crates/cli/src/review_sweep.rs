//! Compact question queues and exact-anchor evidence sweeps. Groups are lookup
//! opportunities, never callable-identity proofs or propagated verdicts.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn contract_keys(entry: &Value) -> Vec<(String, String, String)> {
    entry["operand_facts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|fact| {
            let kind = fact["kind"].as_str()?;
            let value = fact["value"].as_str()?;
            let value = match kind {
                "configured_root_path" => value.split_once(" . ")?.0,
                "encoding_call" | "fixed_code_relative_path" | "repository_code_target" => value,
                _ => return None,
            };
            Some((format!("{kind}:{value}"), kind.into(), value.into()))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn checks(kind: &str) -> &'static [&'static str] {
    match kind {
        "encoding_call" => &[
            "callable_identity_and_contract",
            "options_and_hooks",
            "exact_output_context",
            "complete_operand",
        ],
        "configured_root_path" => &[
            "root_definition_and_overrides",
            "exact_suffix_and_target",
            "target_content_and_writers",
        ],
        _ => &["target_content_and_writers", "exact_target_identity"],
    }
}

pub(super) fn contract_queue(
    entries: &[&Value],
    fingerprint: &Value,
    offset: usize,
    limit: usize,
) -> Value {
    let mut groups = BTreeMap::<String, (String, String, usize, BTreeSet<String>)>::new();
    let mut ungrouped = 0;
    for entry in entries {
        let keys = contract_keys(entry);
        if keys.is_empty() {
            ungrouped += 1;
        }
        for (key, kind, value) in keys {
            let group = groups
                .entry(key)
                .or_insert((kind, value, 0, BTreeSet::new()));
            group.2 += 1;
            if let Some(path) = entry["path"].as_str() {
                group.3.insert(path.into());
            }
        }
    }
    let mut groups: Vec<_> = groups
        .into_iter()
        .map(|(key, (kind, value, count, paths))| {
            json!({
                "contract": key, "kind": kind, "value": value, "review_count": count,
                "file_count": paths.len(), "verified": false, "checks": checks(&kind),
            })
        })
        .collect();
    groups.sort_by(|a, b| {
        b["review_count"]
            .as_u64()
            .cmp(&a["review_count"].as_u64())
            .then_with(|| a["contract"].as_str().cmp(&b["contract"].as_str()))
    });
    json!({"source_fingerprint": fingerprint, "matching_review_count": entries.len(),
        "grouped_review_count": entries.len() - ungrouped, "ungrouped_review_count": ungrouped,
        "contract_count": groups.len(), "offset": offset,
        "groups": groups.into_iter().skip(offset).take(limit).collect::<Vec<_>>()})
}

pub(super) fn sweep(fingerprint: &str, mut cards: Vec<Value>) -> Result<Value, String> {
    let mut lines = BTreeMap::<String, BTreeMap<u64, String>>::new();
    let mut contexts = Vec::<Value>::new();
    for card in &cards {
        let context = &card["source_context"];
        if context.is_null() || context["truncated"] == true {
            continue;
        }
        let path = context["location"]["path"]
            .as_str()
            .ok_or("missing context path")?;
        let start = context["location"]["start_line"]
            .as_u64()
            .ok_or("missing context line")?;
        for (index, line) in context["excerpt"]
            .as_str()
            .unwrap_or_default()
            .lines()
            .enumerate()
        {
            let existing = lines
                .entry(path.into())
                .or_default()
                .insert(start + index as u64, line.into());
            if existing.is_some_and(|old| old != line) {
                return Err("conflicting source windows; inspect individual cards".into());
            }
        }
    }
    for (path, lines) in lines {
        let mut start = 0;
        let mut end = 0;
        let mut text = Vec::new();
        for (line, value) in lines {
            if !text.is_empty() && line != end + 1 {
                contexts.push(json!({"location":{"path":path,"start_line":start,"end_line":end},"excerpt":text.join("\n"),"truncated":false}));
                text.clear();
            }
            if text.is_empty() {
                start = line;
            }
            end = line;
            text.push(value);
        }
        if !text.is_empty() {
            contexts.push(json!({"location":{"path":path,"start_line":start,"end_line":end},"excerpt":text.join("\n"),"truncated":false}));
        }
    }
    let mut contracts = BTreeMap::new();
    let mut questions = Vec::<Value>::new();
    for card in &mut cards {
        let source = card["source_context"].take();
        let mut refs = Vec::new();
        if !source.is_null() {
            if source["truncated"] == true {
                let mut source = source;
                source.as_object_mut().unwrap().remove("evidence_id");
                let index = contexts
                    .iter()
                    .position(|item| item == &source)
                    .unwrap_or_else(|| {
                        contexts.push(source);
                        contexts.len() - 1
                    });
                refs.push(format!("source-{}", index + 1));
            } else {
                for (index, context) in contexts.iter().enumerate() {
                    if context["location"]["path"] == source["location"]["path"]
                        && context["location"]["start_line"].as_u64()
                            <= source["location"]["end_line"].as_u64()
                        && context["location"]["end_line"].as_u64()
                            >= source["location"]["start_line"].as_u64()
                    {
                        refs.push(format!("source-{}", index + 1));
                    }
                }
            }
        }
        let keys = contract_keys(card);
        card["contract_keys"] = json!(keys.iter().map(|item| &item.0).collect::<Vec<_>>());
        for (key, kind, value) in keys {
            contracts.entry(key.clone()).or_insert_with(|| json!({"contract":key,"kind":kind,"value":value,"verified":false,"checks":checks(&kind)}));
        }
        card["source_context_ids"] = json!(refs);
        let mut question = json!({});
        for field in ["category", "playbook", "security_question", "relationship"] {
            question[field] = card[field].take();
        }
        let question_index = questions
            .iter()
            .position(|item| item == &question)
            .unwrap_or_else(|| {
                questions.push(question);
                questions.len() - 1
            });
        card["question_id"] = json!(format!("question-{}", question_index + 1));
        let object = card.as_object_mut().ok_or("invalid review card")?;
        object.remove("source_context");
        object.remove("bundle_fingerprint");
        for field in ["category", "playbook", "security_question", "relationship"] {
            object.remove(field);
        }
    }
    for (index, context) in contexts.iter_mut().enumerate() {
        context["id"] = json!(format!("source-{}", index + 1));
    }
    for (index, question) in questions.iter_mut().enumerate() {
        question["id"] = json!(format!("question-{}", index + 1));
    }
    Ok(
        json!({"bundle_fingerprint":fingerprint,"review_count":cards.len(),
        "contracts":contracts.into_values().collect::<Vec<_>>(),"questions":questions,"source_contexts":contexts,"reviews":cards}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(text: &str, truncated: bool) -> Value {
        json!({"review_id":text,"source_context":{"location":{"path":"view.php","start_line":10,"end_line":10},"excerpt":text,"truncated":truncated}})
    }

    #[test]
    fn rejects_conflicting_exact_windows_and_keeps_clipped_windows_separate() {
        assert!(
            sweep(
                "bundle",
                vec![card("echo safe();", false), card("echo raw();", false)]
            )
            .is_err()
        );
        let result = sweep(
            "bundle",
            vec![card("echo safe", true), card("echo raw", true)],
        )
        .unwrap();
        assert_eq!(result["source_contexts"].as_array().unwrap().len(), 2);
        assert_ne!(
            result["reviews"][0]["source_context_ids"],
            result["reviews"][1]["source_context_ids"]
        );
        assert!(
            result["source_contexts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["truncated"] == true)
        );
    }
}
