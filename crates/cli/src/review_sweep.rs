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
            if kind == "semantic_definition" {
                let location = &fact["location"];
                let path = location["path"].as_str()?;
                let start = location["start"]["byte_offset"].as_u64()?;
                let end = location["end"]["byte_offset"].as_u64()?;
                let role = fact["role"].as_str()?;
                // Definition navigation is not security equivalence. Do not
                // group names alone or receiver declarations with producers.
                if role == "receiver" || end <= start {
                    return None;
                }
                let identity = format!("{path}:{start}:{end}:{role}:{value}");
                return Some((
                    format!("bound_producer:{identity}"),
                    "bound_producer".into(),
                    identity,
                ));
            }
            let value = match kind {
                "configured_root_path" => value.split_once(" . ")?.0,
                "encoding_call"
                | "fixed_code_relative_path"
                | "repository_code_target"
                | "shared_outbound_destination"
                | "immutable_filesystem_operand" => value,
                "shared_filesystem_producer" => value,
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
        "bound_producer" => &[
            "producer_return_and_stored_property_writers",
            "per_call_arguments_receiver_and_runtime_dispatch",
            "per_site_control_guards_and_effects",
        ],
        "shared_outbound_destination" => &[
            "destination_producer_and_same_owner_hooks",
            "caller_control_and_runtime_client_base",
            "per_operation_uri_authority_and_request_effects",
        ],
        "immutable_filesystem_operand" => &[
            "root_origin_and_authority",
            "per_operation_guards_and_effects",
        ],
        "shared_filesystem_producer" => &[
            "helper_return_and_containment_policy",
            "per_call_input_guards_and_resource_effects",
        ],
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
    let mut groups = BTreeMap::<String, (String, String, Vec<Value>, BTreeSet<String>)>::new();
    let mut ungrouped = 0;
    for entry in entries {
        let keys = contract_keys(entry);
        if keys.is_empty() {
            ungrouped += 1;
        }
        for (key, kind, value) in keys {
            let group = groups
                .entry(key)
                .or_insert((kind, value, Vec::new(), BTreeSet::new()));
            group
                .2
                .push(json!({"review_id":entry["review_id"], "path":entry["path"],
                "line":entry["line"], "symbol":entry["symbol"],
                "capability":entry["capability"], "evidence_strength":entry["evidence_strength"]}));
            if let Some(path) = entry["path"].as_str() {
                group.3.insert(path.into());
            }
        }
    }
    let mut groups: Vec<_> = groups
        .into_iter()
        .map(|(key, (kind, value, members, paths))| {
            json!({
                "contract": key, "kind": kind, "value": value, "review_count": members.len(),
                "review_ids": members.iter().map(|m| &m["review_id"]).collect::<Vec<_>>(),
                "members":members,
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
    let returned_count = groups.len().saturating_sub(offset).min(limit);
    let next_offset = (offset.saturating_add(returned_count) < groups.len())
        .then_some(offset.saturating_add(returned_count));
    json!({"source_fingerprint": fingerprint, "matching_review_count": entries.len(),
        "grouped_review_count": entries.len() - ungrouped, "ungrouped_review_count": ungrouped,
        "contract_count": groups.len(), "offset": offset, "returned_count": returned_count,
        "next_offset": next_offset,
        "groups": groups.into_iter().skip(offset).take(limit).collect::<Vec<_>>()})
}

/// Source neighborhoods for planning reads, not shared security contracts.
/// Partition by exact file, callable, capability and CWE set. Every ID remains
/// independent, including distinct guards/operands inside the same callable.
pub(super) fn implementation_queue(
    entries: &[&Value],
    fingerprint: &Value,
    offset: usize,
    limit: usize,
) -> Value {
    let mut grouped = BTreeMap::<String, Vec<&Value>>::new();
    for entry in entries {
        let key = json!([
            entry["path"],
            entry["symbol"],
            entry["capability"],
            entry["cwe_candidates"]
        ])
        .to_string();
        grouped.entry(key).or_default().push(entry);
    }
    let mut groups: Vec<Value> = grouped.into_values().map(|mut members| {
        members.sort_by(|a, b| a["line"].as_u64().cmp(&b["line"].as_u64())
            .then_with(|| a["review_id"].as_str().cmp(&b["review_id"].as_str())));
        let first = members[0];
        let contracts: BTreeSet<_> = members.iter().flat_map(|entry| contract_keys(entry))
            .map(|(key, _, _)| key).collect();
        json!({"path": first["path"], "symbol": first["symbol"],
            "capability": first["capability"], "cwe_candidates": first["cwe_candidates"],
            "review_count": members.len(), "verified": false,
            "representative_review_id": first["review_id"],
            "review_ids": members.iter().map(|entry| &entry["review_id"]).collect::<Vec<_>>(),
            "contracts": contracts,
            "checks": ["shared_implementation_and_producer", "per_site_operand_context_guards_and_effects"]})
    }).collect();
    groups.sort_by(|a, b| {
        b["review_count"]
            .as_u64()
            .cmp(&a["review_count"].as_u64())
            .then_with(|| a["path"].as_str().cmp(&b["path"].as_str()))
            .then_with(|| {
                a["representative_review_id"]
                    .as_str()
                    .cmp(&b["representative_review_id"].as_str())
            })
    });
    let mut by_capability = BTreeMap::<String, (u64, usize)>::new();
    for group in &groups {
        let counts = by_capability
            .entry(group["capability"].as_str().unwrap_or("unknown").into())
            .or_default();
        counts.0 += group["review_count"].as_u64().unwrap_or(0);
        counts.1 += 1;
    }
    let by_capability: BTreeMap<_, _> = by_capability
        .into_iter()
        .map(|(capability, (review_count, implementation_count))| {
            (
                capability,
                json!({"review_count": review_count, "implementation_count": implementation_count}),
            )
        })
        .collect();
    let returned_count = groups.len().saturating_sub(offset).min(limit);
    let next_offset = (offset.saturating_add(returned_count) < groups.len())
        .then_some(offset.saturating_add(returned_count));
    json!({"source_fingerprint": fingerprint, "matching_review_count": entries.len(),
        "implementation_count": groups.len(), "grouping": "source_neighborhood",
        "by_capability": by_capability, "offset": offset, "returned_count": returned_count,
        "next_offset": next_offset, "groups": groups.into_iter().skip(offset).take(limit).collect::<Vec<_>>()})
}

// Complete AST ranges can begin/end mid-line. Keep them atomic rather than
// weaving fragments from different same-line callbacks into one source view.
fn atomic_context(context: &Value) -> bool {
    context["truncated"] == true || context["location"]["start_byte_offset"].is_u64()
}

fn register_atomic_context(contexts: &mut Vec<Value>, mut source: Value) -> Result<String, String> {
    source
        .as_object_mut()
        .ok_or("invalid source context")?
        .remove("evidence_id");
    if source["location"]["start_byte_offset"].is_u64()
        && contexts.iter().any(|item| {
            item["location"] == source["location"] && item["excerpt"] != source["excerpt"]
        })
    {
        return Err("conflicting exact source ranges; inspect individual cards".into());
    }
    let index = contexts
        .iter()
        .position(|item| item == &source)
        .unwrap_or_else(|| {
            contexts.push(source);
            contexts.len() - 1
        });
    Ok(format!("source-{}", index + 1))
}

fn context_refs(contexts: &mut Vec<Value>, source: Value) -> Result<Vec<String>, String> {
    if source.is_null() {
        return Ok(Vec::new());
    }
    if atomic_context(&source) {
        return Ok(vec![register_atomic_context(contexts, source)?]);
    }
    Ok(contexts
        .iter()
        .enumerate()
        .filter(|(_, context)| {
            !atomic_context(context)
                && context["location"]["path"] == source["location"]["path"]
                && context["location"]["start_line"].as_u64()
                    <= source["location"]["end_line"].as_u64()
                && context["location"]["end_line"].as_u64()
                    >= source["location"]["start_line"].as_u64()
        })
        .map(|(index, _)| format!("source-{}", index + 1))
        .collect())
}

pub(super) fn sweep(fingerprint: &str, mut cards: Vec<Value>) -> Result<Value, String> {
    // Read adjacent operations in source order. Identity still comes from the
    // exact ID/anchor, never the position of a row in this list.
    cards.sort_by(|a, b| {
        a["anchor"]["location"]["path"]
            .as_str()
            .cmp(&b["anchor"]["location"]["path"].as_str())
            .then_with(|| {
                a["anchor"]["location"]["start_line"]
                    .as_u64()
                    .cmp(&b["anchor"]["location"]["start_line"].as_u64())
            })
            .then_with(|| a["review_id"].as_str().cmp(&b["review_id"].as_str()))
    });
    let mut lines = BTreeMap::<String, BTreeMap<u64, String>>::new();
    let mut contexts = Vec::<Value>::new();
    for context in cards.iter().flat_map(|card| {
        std::iter::once(&card["source_context"]).chain(
            card["path_steps"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|step| &step["context"]),
        )
    }) {
        if context.is_null() || atomic_context(context) {
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
        let refs = context_refs(&mut contexts, source)?;
        let keys = contract_keys(card);
        card["contract_keys"] = json!(keys.iter().map(|item| &item.0).collect::<Vec<_>>());
        for (key, kind, value) in keys {
            contracts.entry(key.clone()).or_insert_with(|| json!({"contract":key,"kind":kind,"value":value,"verified":false,"checks":checks(&kind)}));
        }
        card["source_context_ids"] = json!(refs);
        if let Some(steps) = card["path_steps"].as_array_mut() {
            for step in steps {
                let context = step["context"].take();
                step["context_ids"] = json!(context_refs(&mut contexts, context)?);
                step.as_object_mut()
                    .ok_or("invalid path step")?
                    .remove("context");
            }
        }
        let helpers = card["helper_context"].take();
        let mut helper_refs = Vec::new();
        for helper in helpers.as_array().into_iter().flatten() {
            helper_refs.push(register_atomic_context(&mut contexts, helper.clone())?);
        }
        if !helper_refs.is_empty() {
            card["helper_context_ids"] = json!(helper_refs);
        }
        card.as_object_mut()
            .ok_or("invalid review card")?
            .remove("helper_context");
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

    #[test]
    fn bound_producers_group_cross_file_members_without_transferring_safety() {
        let fact = json!({"kind":"semantic_definition", "role":"path", "value":"Store.Resolve(string)",
            "location":{"path":"Store.cs","start":{"byte_offset":10},"end":{"byte_offset":17}}});
        let a = json!({"review_id":"a","path":"Read.cs","capability":"filesystem_read","operand_facts":[fact.clone()]});
        let b = json!({"review_id":"b","path":"Write.cs","capability":"filesystem_write","operand_facts":[fact.clone()]});
        let mut unrelated = fact.clone();
        unrelated["location"]["path"] = json!("OtherStore.cs");
        let c = json!({"review_id":"c","path":"Other.cs","operand_facts":[unrelated]});
        let result = contract_queue(&[&a, &b, &c], &json!("revision"), 0, 20);
        assert_eq!(result["contract_count"], 2);
        assert_eq!(result["groups"][0]["review_ids"], json!(["a", "b"]));
        assert_eq!(result["groups"][0]["verified"], false);
        assert_eq!(result["groups"][0]["file_count"], 2);
        let receiver = json!({"operand_facts":[{"kind":"semantic_definition","value":"Store.Resolve(string)","role":"receiver","location":fact["location"]}]});
        assert!(contract_keys(&receiver).is_empty());
    }

    fn card(text: &str, truncated: bool) -> Value {
        json!({"review_id":text,"source_context":{"location":{"path":"view.php","start_line":10,"end_line":10},"excerpt":text,"truncated":truncated}})
    }

    #[test]
    fn exact_callables_reuse_source_without_merging_same_line_neighbors() {
        let make = |id: &str, start: u64, text: &str| {
            json!({"review_id":id,
            "anchor":{"location":{"path":"client.ts","start_line":1}},
            "source_context":{"location":{"path":"client.ts","start_line":1,"end_line":1,
                "start_column":start+1,"end_column":start+1+text.len() as u64,
                "start_byte_offset":start,"end_byte_offset":start+text.len() as u64},
                "excerpt":text,"truncated":false}})
        };
        let a = make("a", 0, "() => fetch(left)");
        let mut b = a.clone();
        b["review_id"] = json!("b");
        let c = make("c", 30, "() => fetch(right)");
        let plain = json!({"review_id":"plain", "anchor":{"location":{"path":"client.ts","start_line":1}},
            "source_context":{"location":{"path":"client.ts","start_line":1,"end_line":1},"excerpt":"whole line", "truncated":false}});
        let result = sweep("bundle", vec![a.clone(), b, c, plain]).unwrap();
        let rows = result["reviews"].as_array().unwrap();
        let row = |id| rows.iter().find(|r| r["review_id"] == id).unwrap();
        assert_eq!(
            row("a")["source_context_ids"],
            row("b")["source_context_ids"]
        );
        assert_ne!(
            row("a")["source_context_ids"],
            row("c")["source_context_ids"]
        );
        assert_eq!(
            row("plain")["source_context_ids"].as_array().unwrap().len(),
            1
        );
        assert_eq!(result["source_contexts"].as_array().unwrap().len(), 3);
        let mut conflict = a.clone();
        conflict["source_context"]["excerpt"] = json!("different source");
        assert!(sweep("bundle", vec![a, conflict]).is_err());
    }

    #[test]
    fn resolved_helper_source_is_shared_without_merging_call_decisions() {
        let helper = json!({"role":"captured_definition_context", "symbol":"run",
            "location":{"path":"helper.ts","start_line":1,"end_line":1,"start_byte_offset":0,"end_byte_offset":23},
            "excerpt":"function run(x){exec(x)}", "truncated":false});
        let cards = ["a", "b"].map(|id| {
            json!({"review_id":id,"selected_anchor_id":id,
            "anchor":{"location":{"path":format!("{id}.ts"),"start_line":1}},
            "helper_context":[helper.clone()]})
        });
        let result = sweep("bundle", cards.into()).unwrap();
        let rows = result["reviews"].as_array().unwrap();
        assert_eq!(result["source_contexts"].as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["helper_context_ids"], rows[1]["helper_context_ids"]);
        assert_ne!(rows[0]["selected_anchor_id"], rows[1]["selected_anchor_id"]);
        assert!(rows.iter().all(|row| row.get("helper_context").is_none()));
    }

    #[test]
    fn source_order_preserves_each_exact_identity_and_operand() {
        let cards = [("a", 17, "changed"), ("b", 21, "spread"), ("c", 12, "bound")].map(|(id, line, operand)| {
            json!({"review_id":id, "selected_anchor_id":operand, "anchor":{"location":{"path":"app.js", "start_line":line}, "captures":{"query":operand}}})
        });
        let result = sweep("bundle", cards.into()).unwrap();
        for (index, id, operand) in [(0, "c", "bound"), (1, "a", "changed"), (2, "b", "spread")] {
            assert_eq!(result["reviews"][index]["review_id"], id);
            assert_eq!(result["reviews"][index]["selected_anchor_id"], operand);
            assert_eq!(
                result["reviews"][index]["anchor"]["captures"]["query"],
                operand
            );
        }
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
