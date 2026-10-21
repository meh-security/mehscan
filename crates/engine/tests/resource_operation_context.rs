use mehscan_core::{Capability, EvidenceKind, PathReviewBundlePayload};
use mehscan_engine::investigation::{build_all_path_review_jobs, build_path_review_bundles};
use std::fs;

#[test]
fn resource_helpers_follow_direct_local_bindings_without_guessing_receiver_methods() {
    let root =
        std::env::temp_dir().join(format!("mehscan-resource-helpers-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for extension in ["js", "ts", "tsx"] {
        fs::write(
            root.join(format!("app.{extension}")),
            r#"
const verifyPassword = (password, hash) => crypt.compare(password, hash); const adjacentDefinition = () => unrelated();
function findOne() { return unrelated(); }
const mutableCheck = () => false;
mutableCheck = replacement;
const shadowedCheck = () => false;
const escapedCheck = () => false;
({escapedCheck} = replacements);
const unrelatedCheck = () => false;
function other(unrelatedCheck) { return unrelatedCheck(); }
function credentials(email, password, shadowedCheck) {
 const user = Accounts.findOne({where:{email}});
 if (!user) return false;
 return verifyPassword(password, user.hash) && shadowedCheck() && mutableCheck() && escapedCheck();
}
function lookup(id) {
 const row = Accounts.findOne({where:{id}});
 return client.findOne(row);
}
function separate() { function hiddenCheck() { return false; } }
function outside(id) {
 const row = Accounts.findOne({where:{id}});
 return hiddenCheck(row);
}
"#,
        )
        .unwrap();
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
        assert_eq!(
            reviews.len(),
            3,
            "helper filtering must not remove resource questions"
        );
        let credential = reviews
            .iter()
            .find(|r| {
                r.evidence
                    .iter()
                    .any(|e| e.enclosing_symbol.as_deref() == Some("credentials"))
            })
            .unwrap();
        let helpers = credential
            .facts
            .iter()
            .filter(|f| f.role == "helper_definition_context")
            .collect::<Vec<_>>();
        assert!(
            helpers
                .iter()
                .any(|f| f.symbol == "verifyPassword" && f.excerpt.contains("crypt.compare")),
            "actual verifier definition missing for {extension}"
        );
        assert!(
            helpers
                .iter()
                .all(|f| !f.excerpt.contains("adjacentDefinition")),
            "helper excerpt must respect exact byte boundaries"
        );
        for review in reviews {
            for fact in review
                .facts
                .iter()
                .filter(|f| f.role == "helper_definition_context")
            {
                assert!(
                    ![
                        "findOne",
                        "mutableCheck",
                        "shadowedCheck",
                        "escapedCheck",
                        "hiddenCheck",
                        "unrelatedCheck"
                    ]
                    .contains(&fact.symbol.as_str()),
                    "unresolved/irrelevant helper {} in {extension}",
                    fact.symbol
                );
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

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

#[test]
fn python_selector_and_execution_context_are_located_without_closing_authority() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-python-resource-context-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let source = r#"
from django.core.management.base import BaseCommand
class Command(BaseCommand):
    def handle(self, **options):
        page = Page.objects.get(pk=options["from_id"])
        return page

def reload(page):
    selected = Page.objects.get(pk=page.id)
    if not allowed(selected):
        raise PermissionError()
    return selected

def lookup(request):
    return Page.objects.get(pk=request.GET["id"])
"#;
    fs::write(root.join("app.py"), source).unwrap();
    let job = build_all_path_review_jobs(&root, Some(1), false).unwrap();
    let reviews = job
        .observation_reviews
        .iter()
        .filter(|r| {
            r.evidence
                .iter()
                .any(|e| e.capability == Capability::ResourceAccess && e.kind == EvidenceKind::Sink)
        })
        .collect::<Vec<_>>();
    for name in ["handle", "reload", "lookup"] {
        assert!(
            reviews.iter().any(|r| r
                .evidence
                .iter()
                .any(|e| e.capability == Capability::ResourceAccess
                    && e.enclosing_symbol.as_deref() == Some(name)))
                || job.reviews.iter().any(|r| r.candidate.sink.capability
                    == Capability::ResourceAccess
                    && r.candidate.sink.enclosing_symbol.as_deref() == Some(name)),
            "{name} must retain an authority question, as a path or observation"
        );
    }
    for review in &reviews {
        let e = review
            .evidence
            .iter()
            .find(|e| e.capability == Capability::ResourceAccess && e.kind == EvidenceKind::Sink)
            .unwrap();
        let owner = e
            .context
            .operand_facts
            .iter()
            .find(|f| f.role == "resource_operation")
            .unwrap();
        assert!(
            owner.location.start.byte_offset <= e.captures["filter"].location.start.byte_offset
        );
        assert!(owner.location.end.byte_offset >= e.captures["filter"].location.end.byte_offset);
        assert!(
            owner
                .remaining_checks
                .iter()
                .any(|c| c == "caller_authority")
        );
        if e.enclosing_symbol.as_deref() == Some("handle") {
            let bases = e
                .context
                .operand_facts
                .iter()
                .find(|f| f.role == "resource_execution_context")
                .unwrap();
            assert!(
                source[bases.location.start.byte_offset..bases.location.end.byte_offset]
                    .contains("BaseCommand")
            );
            assert!(bases.remaining_checks.iter().any(|c| c == "other_callers"));
        }
        if e.enclosing_symbol.as_deref() == Some("reload") {
            let context = review
                .facts
                .iter()
                .find(|f| f.role == "source_context")
                .unwrap();
            assert!(context.excerpt.contains("raise PermissionError()"));
            assert!(!context.excerpt.contains("def lookup"));
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn outbound_compact_callable_context_keeps_destination_and_late_controls() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-outbound-operation-context-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    for extension in ["js", "ts", "tsx"] {
        fs::write(
            root.join(format!("app.{extension}")),
            format!(
                r#"
async function request(url, options) {{
  const response = await fetch(url, options);
{}
  if (!permitted(response.url)) throw new Error('redirect rejected');
  return response;
}}
async function other(destination) {{ return fetch(destination); }}
"#,
                "\n".repeat(18)
            ),
        )
        .unwrap();
    }
    let job = build_all_path_review_jobs(&root, Some(1), false).unwrap();
    for extension in ["js", "ts", "tsx"] {
        let path = format!("app.{extension}");
        let review = job
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence.iter().any(|e| {
                    e.location.path == path
                        && e.capability == Capability::OutboundNetworkRequest
                        && e.enclosing_symbol.as_deref() == Some("request")
                })
            })
            .unwrap();
        let e = review
            .evidence
            .iter()
            .find(|e| e.capability == Capability::OutboundNetworkRequest)
            .unwrap();
        let owner = e
            .context
            .operand_facts
            .iter()
            .find(|f| f.role == "outbound_operation")
            .unwrap();
        assert!(
            owner.location.start.byte_offset <= e.captures["endpoint"].location.start.byte_offset
        );
        assert!(owner.location.end.byte_offset >= e.captures["endpoint"].location.end.byte_offset);
        let context = review
            .facts
            .iter()
            .find(|f| f.role == "source_context")
            .unwrap();
        assert!(context.excerpt.contains("redirect rejected"));
        assert!(!context.excerpt.contains("function other"));
        assert!(context.excerpt.len() <= 1_536);
    }
    fs::remove_dir_all(root).unwrap();
}
