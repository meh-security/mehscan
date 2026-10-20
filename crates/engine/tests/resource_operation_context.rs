use mehscan_core::{Capability, EvidenceKind, PathReviewBundlePayload};
use mehscan_engine::investigation::{build_all_path_review_jobs, build_path_review_bundles};
use std::fs;

#[test]
fn compact_callable_context_preserves_credential_checks_and_separate_access_decisions() {
    let root =
        std::env::temp_dir().join(format!("mehscan-resource-operation-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let padding = "\n".repeat(18);
    for extension in ["js", "ts", "tsx"] {
        let source = format!(
            r#"
const credentials = async (email, password) => {{
  const user = await Accounts.findOne({{where:{{email}}}});
  if (!user) return false;
{padding}
  const valid = await verify(password, user.hash);
  if (!valid) return false;
  return user.id;
}};
const neighboring = async (id) => Records.destroy({{where:{{id}}}});
const two = async (left, right) => {{
  const first = await Records.findOne({{where:{{id:left}}}});
  const second = await Records.findOne({{where:{{id:right}}}});
  return [first, second];
}};
const operations = {{ read: async (id) => Records.findOne({{where:{{id}}}}) }};
class Service {{ readField = async (id) => Records.findOne({{where:{{id}}}}); }}
const named = async function explicitName(id) {{ return Records.findOne({{where:{{id}}}}); }};
const reload = (value) => {{
 const id=String(value);
 const selected=Rows.findOne({{where:{{id:id}}}});
 return Rows.findOne({{where:{{id:id}}}});
}};
const large = async (id) => {{
 const record = await Records.findOne({{where:{{id}}}});
 /* {} */
 return record;
}};
"#,
            "large-body ".repeat(200)
        );
        fs::write(root.join(format!("app.{extension}")), source).unwrap();
    }
    let job = build_all_path_review_jobs(&root, Some(1), false).unwrap();
    for extension in ["js", "ts", "tsx"] {
        let path = format!("app.{extension}");
        let reviews =
            job.observation_reviews
                .iter()
                .filter(|review| {
                    review.evidence.iter().any(|e| {
                        e.location.path == path && e.capability == Capability::ResourceAccess
                    })
                })
                .collect::<Vec<_>>();
        for name in [
            "credentials",
            "neighboring",
            "two",
            "read",
            "readField",
            "explicitName",
            "large",
        ] {
            assert!(
                reviews.iter().any(|review| review
                    .evidence
                    .iter()
                    .any(|e| { e.enclosing_symbol.as_deref() == Some(name) })),
                "missing {extension} callable {name}"
            );
        }
        let credential = reviews
            .iter()
            .find(|review| {
                review
                    .evidence
                    .iter()
                    .any(|e| e.enclosing_symbol.as_deref() == Some("credentials"))
            })
            .unwrap();
        let context = credential
            .facts
            .iter()
            .find(|f| f.role == "source_context")
            .unwrap();
        assert!(context.excerpt.contains("verify(password, user.hash)"));
        assert!(context.excerpt.contains("if (!valid) return false"));
        assert!(!context.excerpt.contains("neighboring"));
        assert!(context.excerpt.len() <= 1_536);
        let independent = reviews
            .iter()
            .filter(|review| {
                review
                    .evidence
                    .iter()
                    .any(|e| e.enclosing_symbol.as_deref() == Some("two"))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            independent.len(),
            2,
            "different selectors retain independent verdicts"
        );
        let first = independent[0]
            .facts
            .iter()
            .find(|f| f.role == "source_context")
            .unwrap();
        let second = independent[1]
            .facts
            .iter()
            .find(|f| f.role == "source_context")
            .unwrap();
        assert_eq!(first.location, second.location);
        assert!(first.evidence_id.is_some());
        assert_eq!(first.evidence_id, second.evidence_id);
        assert_eq!(
            first.excerpt, second.excerpt,
            "operation context is reusable, verdicts are not"
        );
        let reloads = reviews
            .iter()
            .filter(|review| {
                review.evidence.iter().any(|e| {
                    e.kind == EvidenceKind::Sink && e.enclosing_symbol.as_deref() == Some("reload")
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reloads.len(),
            1,
            "retain the original authority question once"
        );
        assert!(
            reloads[0].evidence.iter().any(|e| {
                e.kind == EvidenceKind::Resource && e.enclosing_symbol.as_deref() == Some("reload")
            }),
            "the original question must actually carry its related reload evidence"
        );
        let large = reviews
            .iter()
            .find(|review| {
                review
                    .evidence
                    .iter()
                    .any(|e| e.enclosing_symbol.as_deref() == Some("large"))
            })
            .unwrap();
        assert!(large.evidence.iter().any(|e| {
            e.context
                .operand_facts
                .iter()
                .any(|f| f.role == "resource_operation")
        }));
        assert!(
            !large
                .facts
                .iter()
                .find(|f| f.role == "source_context")
                .unwrap()
                .excerpt
                .contains("return record")
        );
    }
    // Native compact-card projection must preserve the complete small operation
    // too, rather than stripping the decisive check after source preparation.
    let bundles = build_path_review_bundles(&job, None).unwrap();
    for bundle in bundles.bundles {
        if let PathReviewBundlePayload::Observation { reviews } = bundle.payload {
            for review in reviews {
                if review
                    .evidence
                    .iter()
                    .any(|e| e.enclosing_symbol.as_deref() == Some("credentials"))
                {
                    assert!(review.facts.iter().any(|f| f.role == "source_context"
                        && f.excerpt.contains("if (!valid) return false")));
                }
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
