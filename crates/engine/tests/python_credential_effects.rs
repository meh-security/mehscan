use mehscan_core::{Capability, EvidenceKind, Resolution};
use mehscan_engine::investigation::{build_all_path_review_jobs, build_review_inventory};
use std::fs;

#[test]
fn credential_service_effects_keep_source_bound_questions_and_controls() {
    let root =
        std::env::temp_dir().join(format!("mehscan-credential-effects-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let source = r#"
import sqlalchemy as sa
from django.contrib.auth import password_validation
from accounts import models
def apply(db, model, value):
    record = db.session.execute(sa.select(model)).scalar_one_or_none()
    record.password = value
def consume_once(id, token, value):
    record = models.Member.objects.get(id=id)
    if not nonce_store.consume(token, record.id):
        raise ValueError()
    record.set_password(value)
    record.save()
def password_bound(id, token, value):
    record = models.Member.objects.get(id=id)
    if not generator.check_token(record, token):
        raise ValueError()
    record.set_password(value)
    record.save()
def display_password_reset():
    return render_template("reset.html")
"#;
    fs::write(root.join("service.py"), source).unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    let entries = inventory
        .entries
        .iter()
        .filter(|entry| entry.rule_id == "framework-credential-lifecycle-review-marker")
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 3, "{:?}", inventory.entries);
    for entry in entries {
        assert_eq!(entry.capability, Capability::Authentication);
        assert!(matches!(
            entry.symbol.as_deref(),
            Some("apply" | "consume_once" | "password_bound")
        ));
    }
    let job = build_all_path_review_jobs(&root, None, false).unwrap();
    let reviews = job
        .observation_reviews
        .iter()
        .filter(|review| {
            review
                .evidence
                .iter()
                .any(|e| e.rule_id == "framework-credential-lifecycle-review-marker")
        })
        .collect::<Vec<_>>();
    assert_eq!(reviews.len(), 3);
    for review in reviews {
        let effect = review
            .evidence
            .iter()
            .find(|e| e.rule_id == "framework-credential-lifecycle-review-marker")
            .unwrap();
        assert_eq!(effect.kind, EvidenceKind::SensitiveOperation);
        assert_eq!(effect.provenance.resolution, Resolution::Ast);
        let capture = &effect.captures["effect"];
        assert_eq!(
            &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
            capture.text
        );
        assert!(capture.text.contains("password"));
        assert!(effect.captures.contains_key("effect_basis"));
        // A guarded control is admitted with the same bounded question. The
        // marker neither declares a flaw nor treats a setter as proof of commit.
        assert!(
            !effect
                .tags
                .iter()
                .any(|tag| tag == "missing-guard" || tag == "replayable-token")
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn decorated_credential_effect_is_one_question_and_source_excludes_tests() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-credential-decorator-{}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("spec")).unwrap();
    let source = r#"
from django.contrib.auth import password_validation
from accounts import models
@app.route('/reset', methods=['POST'])
def reset_password(id, value):
    record = models.Member.objects.get(id=id)
    record.set_password(value)
    record.save()
"#;
    fs::write(root.join("app.py"), source).unwrap();
    fs::write(root.join("spec/control.py"), source).unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    let entries = inventory
        .entries
        .iter()
        .filter(|entry| entry.rule_id == "framework-credential-lifecycle-review-marker")
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1, "{:?}", inventory.entries);
    assert_eq!(entries[0].path, "app.py");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn nested_credential_effect_does_not_remove_its_outer_route_question() {
    let root =
        std::env::temp_dir().join(format!("mehscan-credential-nested-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("app.py"),
        r#"
import sqlalchemy as sa
@app.post('/remove')
def remove_record():
    def apply(db, model, value):
        record = db.session.execute(sa.select(model)).scalar_one()
        record.password = value
    return repository.delete_record()
"#,
    )
    .unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "framework-authorization-review-marker"
                && e.symbol.as_deref() == Some("remove_record"))
    );
    assert!(inventory.entries.iter().any(|e| e.rule_id
        == "framework-credential-lifecycle-review-marker"
        && e.symbol.as_deref() == Some("apply")));
    fs::remove_dir_all(root).unwrap();
}
