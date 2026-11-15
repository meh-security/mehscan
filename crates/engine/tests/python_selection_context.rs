use mehscan_core::{ObservationReview, ReviewNeighborhoodFact};
use mehscan_engine::investigation::{build_all_path_review_jobs, build_review_inventory};

fn prepare(label: &str, body: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("mehscan-selection-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.py"), format!("from django.db import models\nclass Row(models.Model):\n    pass\nclass Other(models.Model):\n    pass\n{body}")).unwrap();
    root
}

fn review(root: &std::path::Path, needle: &str) -> ObservationReview {
    let inventory = build_review_inventory(root, false).unwrap();
    let entries: Vec<_> = inventory
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-django-orm-resource-access")
        .collect();
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .all(|e| e.value_hint.is_none() && e.comprehensive_exclusion.is_none())
    );
    let text = std::fs::read_to_string(root.join("app.py")).unwrap();
    let offset = text.find(needle).unwrap();
    let line = text[..offset].bytes().filter(|b| *b == b'\n').count() + 1;
    let jobs = build_all_path_review_jobs(root, Some(32), false).unwrap();
    let review = jobs
        .observation_reviews
        .into_iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                r.anchor_evidence_ids.contains(&e.id)
                    && e.rule_id == "python-django-orm-resource-access"
                    && e.location.start.line == line
            })
        })
        .unwrap();
    assert!(review.decision_facts.effective_controls.is_empty());
    for f in selection(&review) {
        let bytes = std::fs::read(root.join(&f.location.path)).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes[f.location.start.byte_offset..f.location.end.byte_offset])
                .unwrap(),
            f.excerpt
        );
        assert!(
            f.evidence_id
                .as_ref()
                .is_some_and(|id| review.anchor_evidence_ids.contains(id))
        );
        assert!(
            f.provenance
                .engine
                .contains("not reaching-definition, same-record")
        );
    }
    review
}

fn selection(review: &ObservationReview) -> Vec<&ReviewNeighborhoodFact> {
    review
        .facts
        .iter()
        .filter(|f| {
            f.role.starts_with("python_orm_selection_")
                || matches!(
                    f.role.as_str(),
                    "python_orm_alias_context" | "python_orm_binding_boundary_context"
                )
        })
        .collect()
}

fn has(review: &ObservationReview, role: &str, text: &str) -> bool {
    selection(review)
        .iter()
        .any(|f| f.role == role && f.excerpt.contains(text))
}

#[test]
fn delivers_selected_binding_direct_alias_writes_and_helper_uses() {
    let root = prepare(
        "aliases",
        "def work(key: int):\n    selected = Row.objects.get(pk=key)\n    alias = selected\n    alias.enabled = True\n    alias.save()\n    notify(alias)\n",
    );
    let r = review(&root, "selected = Row.objects");
    for (role, text) in [
        ("python_orm_selection_input_context", "pk=key"),
        ("python_orm_selection_origin_context", "key: int"),
        (
            "python_orm_selection_binding_context",
            "selected = Row.objects",
        ),
        ("python_orm_alias_context", "alias = selected"),
        (
            "python_orm_selection_consumer_context",
            "alias.enabled = True",
        ),
        ("python_orm_selection_consumer_context", "alias.save()"),
        ("python_orm_selection_consumer_context", "notify(alias)"),
    ] {
        assert!(
            has(&r, role, text),
            "missing {role} {text}: {:#?}",
            selection(&r)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rebinding_stops_the_replaced_name_but_retains_an_earlier_direct_alias() {
    let root = prepare(
        "rebind",
        "def work(key):\n    selected = Row.objects.get(pk=key)\n    alias = selected\n    if key:\n        selected = Other.objects.get(pk=key)\n    selected.delete()\n    alias.save()\n",
    );
    let r = review(&root, "selected = Row.objects");
    assert!(has(
        &r,
        "python_orm_binding_boundary_context",
        "selected = Other.objects"
    ));
    assert!(!has(
        &r,
        "python_orm_selection_consumer_context",
        "selected.delete()"
    ));
    assert!(has(
        &r,
        "python_orm_selection_consumer_context",
        "alias.save()"
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn reloads_show_alternative_key_origins_without_claiming_record_identity() {
    let root = prepare(
        "reload",
        "def work(key, flag):\n    if flag:\n        selected = load(key)\n    else:\n        selected = Row.objects.filter(pk=key).first()\n    reloaded = Other.objects.get(id=selected.id)\n    reloaded.delete()\n",
    );
    let r = review(&root, "reloaded = Other.objects");
    assert!(has(
        &r,
        "python_orm_selection_input_context",
        "id=selected.id"
    ));
    assert!(has(
        &r,
        "python_orm_selection_origin_context",
        "selected = load(key)"
    ));
    assert!(has(
        &r,
        "python_orm_selection_origin_context",
        "selected = Row.objects"
    ));
    assert!(has(
        &r,
        "python_orm_selection_consumer_context",
        "reloaded.delete()"
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inline_batch_deletes_and_named_expression_bulk_consumers_remain_source_context() {
    let root = prepare(
        "batch",
        "def work(keys):\n    ids = keys[:10]\n    Row.objects.filter(pk__in=ids).delete()\n    if row := Other.objects.filter(pk__in=ids).first():\n        row.enabled = True\n        Other.objects.bulk_update([row], ['enabled'])\n",
    );
    let r = review(&root, "Row.objects.filter(pk__in=ids).delete()");
    assert!(has(
        &r,
        "python_orm_selection_origin_context",
        "ids = keys[:10]"
    ));
    assert!(has(
        &r,
        "python_orm_selection_consumer_context",
        "Row.objects.filter(pk__in=ids).delete()"
    ));
    let r = review(&root, "if row := Other.objects");
    assert!(has(
        &r,
        "python_orm_selection_binding_context",
        "row := Other.objects"
    ));
    assert!(has(
        &r,
        "python_orm_selection_consumer_context",
        "bulk_update([row]"
    ));
    assert!(has(
        &r,
        "python_orm_selection_consumer_context",
        "row.enabled = True"
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nested_scope_parameters_keyword_labels_and_comprehension_locals_are_not_uses() {
    let root = prepare(
        "scopes",
        "def work(key, other):\n    selected = Row.objects.get(pk=key)\n    def nested(selected):\n        selected.delete()\n    notify(selected=other)\n    notify(other.selected)\n    notify([selected for selected in other])\n    (lambda selected: selected.delete())(other)\n",
    );
    let r = review(&root, "selected = Row.objects");
    assert!(
        !selection(&r)
            .iter()
            .any(|f| f.role == "python_orm_selection_consumer_context"),
        "{:#?}",
        selection(&r)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn tuple_loop_import_and_deletion_stores_stop_navigation() {
    for (label, store) in [
        ("tuple", "selected, unused = pair"),
        ("loop", "for selected in others:\n        pass"),
        ("import", "from elsewhere import selected"),
        ("delete", "del selected"),
    ] {
        let root = prepare(
            label,
            &format!(
                "def work(key, pair, others):\n    selected = Row.objects.get(pk=key)\n    {store}\n    selected.delete()\n"
            ),
        );
        let r = review(&root, "selected = Row.objects");
        assert!(
            has(&r, "python_orm_binding_boundary_context", store),
            "{label}: {:#?}",
            selection(&r)
        );
        assert!(!has(
            &r,
            "python_orm_selection_consumer_context",
            "selected.delete()"
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn bounded_consumers_keep_mutation_spelling_and_report_truncation() {
    let root = prepare(
        "bounded",
        "def work(key):\n    selected = Row.objects.get(pk=key)\n    inspect_a(selected)\n    inspect_b(selected)\n    inspect_c(selected)\n    inspect_d(selected)\n    inspect_e(selected)\n    selected.delete()\n",
    );
    let r = review(&root, "selected = Row.objects");
    assert!(r.context_truncated);
    assert_eq!(
        selection(&r)
            .iter()
            .filter(|f| f.role == "python_orm_selection_consumer_context")
            .count(),
        4
    );
    assert!(has(
        &r,
        "python_orm_selection_consumer_context",
        "selected.delete()"
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn global_bindings_do_not_get_local_consumer_navigation() {
    let root = prepare(
        "global",
        "selected = None\ndef work(key):\n    global selected\n    selected = Row.objects.get(pk=key)\n    selected.delete()\n",
    );
    let r = review(&root, "selected = Row.objects");
    assert!(has(
        &r,
        "python_orm_binding_boundary_context",
        "global selected"
    ));
    assert!(!has(
        &r,
        "python_orm_selection_consumer_context",
        "selected.delete()"
    ));
    std::fs::remove_dir_all(root).unwrap();
}
