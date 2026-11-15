use mehscan_core::{ObservationReview, ReviewNeighborhoodFact};
use mehscan_engine::investigation::{build_all_path_review_jobs, build_review_inventory};

fn prepare(label: &str, imports: &str, body: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "mehscan-query-context-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.py"), format!("from django.db import models\n{imports}\nclass Row(models.Model):\n    pass\nclass Related(models.Model):\n    pass\n{body}")).unwrap();
    root
}

fn query_facts(review: &ObservationReview) -> Vec<&ReviewNeighborhoodFact> {
    review
        .facts
        .iter()
        .filter(|f| {
            f.role.starts_with("python_orm_query_")
                || f.role == "python_orm_outer_reference_context"
        })
        .collect()
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
    let source = std::fs::read_to_string(root.join("app.py")).unwrap();
    let offset = source.find(needle).unwrap();
    let line = source[..offset].bytes().filter(|b| *b == b'\n').count() + 1;
    let jobs = build_all_path_review_jobs(root, Some(32), false).unwrap();
    let result = jobs
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
    assert!(result.decision_facts.effective_controls.is_empty());
    for f in query_facts(&result) {
        let bytes = std::fs::read(root.join(&f.location.path)).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes[f.location.start.byte_offset..f.location.end.byte_offset])
                .unwrap(),
            f.excerpt
        );
        assert!(
            f.evidence_id
                .as_ref()
                .is_some_and(|id| result.anchor_evidence_ids.contains(id))
        );
        assert!(f.provenance.engine.contains("not SQL scope"));
        assert!(f.provenance.engine.contains("shared-witness correlation"));
    }
    result
}

fn has(review: &ObservationReview, role: &str, text: &str) -> bool {
    query_facts(review)
        .iter()
        .any(|f| f.role == role && f.excerpt.contains(text))
}

const IMPORTS: &str = "from django.db.models import Exists, OuterRef, Subquery";

#[test]
fn separate_exists_inputs_keep_their_own_bindings_and_outer_references() {
    let root = prepare(
        "independent",
        IMPORTS,
        "def clean(keys):\n    related = Related.objects.filter(pk__in=keys)\n    enabled = Related.objects.filter(enabled=True)\n    Row.objects.filter(\n        Exists(related.filter(row_id=OuterRef('pk'))),\n        Exists(enabled.filter(email=OuterRef('email'))),\n    ).delete()\n",
    );
    let r = review(&root, "Exists(related.filter");
    assert!(has(&r, "python_orm_query_context", "Exists(enabled.filter"));
    assert!(has(&r, "python_orm_query_context", ").delete()"));
    assert_eq!(
        query_facts(&r)
            .iter()
            .filter(|f| f.role == "python_orm_query_predicate_context")
            .count(),
        2
    );
    for (role, text) in [
        (
            "python_orm_query_binding_context",
            "related = Related.objects.filter(pk__in=keys)",
        ),
        (
            "python_orm_query_binding_context",
            "enabled = Related.objects.filter(enabled=True)",
        ),
        ("python_orm_outer_reference_context", "OuterRef('pk')"),
        ("python_orm_outer_reference_context", "OuterRef('email')"),
    ] {
        assert!(
            has(&r, role, text),
            "missing {role}: {:#?}",
            query_facts(&r)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_exists_without_outerref_is_preserved_without_inventing_a_join() {
    let root = prepare(
        "uncorrelated",
        IMPORTS,
        "def clean(keys):\n    Row.objects.filter(Exists(Related.objects.filter(pk__in=keys))).delete()\n",
    );
    let r = review(&root, "Row.objects.filter(Exists");
    assert!(has(
        &r,
        "python_orm_query_predicate_context",
        "Exists(Related.objects.filter(pk__in=keys))"
    ));
    assert!(
        !query_facts(&r)
            .iter()
            .any(|f| f.role == "python_orm_outer_reference_context")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nested_outerrefs_and_negation_are_not_flattened() {
    let root = prepare(
        "nested",
        IMPORTS,
        "def clean():\n    related = Related.objects.filter(row_id=OuterRef(OuterRef('pk')))\n    Row.objects.filter(~Exists(related)).delete()\n",
    );
    let r = review(&root, "Row.objects.filter(~Exists");
    assert!(has(
        &r,
        "python_orm_query_predicate_context",
        "~Exists(related)"
    ));
    assert!(has(
        &r,
        "python_orm_outer_reference_context",
        "OuterRef(OuterRef('pk'))"
    ));
    assert_eq!(
        query_facts(&r)
            .iter()
            .filter(|f| f.role == "python_orm_outer_reference_context")
            .count(),
        2
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn batch_aliases_retain_subquery_inputs_and_projection_slices() {
    let root = prepare(
        "batch",
        IMPORTS,
        "def clean():\n    related = Related.objects.filter(row_id=OuterRef('pk'))\n    qs = Row.objects.annotate(limit=Subquery(related.values('limit')[:1])).filter(~Exists(related))\n    ids = qs.values_list('pk', flat=True)[:100]\n    ids = list(ids)\n    Row.objects.filter(pk__in=ids).delete()\n",
    );
    let r = review(&root, "Row.objects.filter(pk__in=ids).delete()");
    for (role, text) in [
        (
            "python_orm_query_predicate_context",
            "Subquery(related.values('limit')[:1])",
        ),
        ("python_orm_query_binding_context", "ids = list(ids)"),
        (
            "python_orm_query_binding_context",
            "ids = qs.values_list('pk', flat=True)[:100]",
        ),
        (
            "python_orm_query_binding_context",
            "related = Related.objects.filter",
        ),
    ] {
        assert!(
            has(&r, role, text),
            "missing {role} {text}: {:#?}",
            query_facts(&r)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn explicit_alias_and_namespace_imports_resolve_constructor_spelling() {
    for (label, imports, expression) in [
        (
            "alias",
            "from django.db.models import Exists as Present, OuterRef as Ref",
            "Present(Related.objects.filter(row_id=Ref('pk')))",
        ),
        (
            "namespace",
            "import django.db.models as orm",
            "orm.Exists(Related.objects.filter(row_id=orm.OuterRef('pk')))",
        ),
        (
            "expressions",
            "from django.db.models.expressions import Exists, OuterRef",
            "Exists(Related.objects.filter(row_id=OuterRef('pk')))",
        ),
    ] {
        let root = prepare(
            label,
            imports,
            &format!("def clean():\n    Row.objects.filter({expression}).delete()\n"),
        );
        let r = review(&root, "Row.objects.filter(");
        assert!(has(&r, "python_orm_query_predicate_context", expression));
        assert!(
            query_facts(&r)
                .iter()
                .any(|f| f.role == "python_orm_outer_reference_context")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn lookalikes_rebinding_wildcards_and_local_shadows_are_not_django_contracts() {
    for (label, imports, body) in [
        (
            "foreign",
            "from elsewhere import Exists, OuterRef",
            "def clean(keys):\n    Row.objects.filter(Exists(Related.objects.filter(pk__in=keys))).delete()\n",
        ),
        (
            "rebound",
            "from django.db.models import Exists\nExists = unrelated",
            "def clean(keys):\n    Row.objects.filter(Exists(Related.objects.filter(pk__in=keys))).delete()\n",
        ),
        (
            "parameter",
            "from django.db.models import Exists",
            "def clean(keys, Exists):\n    Row.objects.filter(Exists(Related.objects.filter(pk__in=keys))).delete()\n",
        ),
        (
            "closure",
            "from django.db.models import Exists",
            "def outer(Exists):\n    def clean(keys):\n        Row.objects.filter(Exists(Related.objects.filter(pk__in=keys))).delete()\n    return clean\n",
        ),
        (
            "wildcard",
            "from django.db.models import Exists\nfrom elsewhere import *",
            "def clean(keys):\n    Row.objects.filter(Exists(Related.objects.filter(pk__in=keys))).delete()\n",
        ),
        (
            "namespace-write",
            "import django.db.models as orm\norm.Exists = unrelated",
            "def clean(keys):\n    Row.objects.filter(orm.Exists(Related.objects.filter(pk__in=keys))).delete()\n",
        ),
        (
            "namespace-local",
            "import django.db.models as orm",
            "def clean(keys, orm):\n    Row.objects.filter(orm.Exists(Related.objects.filter(pk__in=keys))).delete()\n",
        ),
    ] {
        let root = prepare(label, imports, body);
        let r = review(&root, "Row.objects.filter(");
        assert!(
            query_facts(&r).is_empty(),
            "{label}: {:#?}",
            query_facts(&r)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn branch_origins_remain_alternatives_and_unrelated_expressions_stay_out() {
    let root = prepare(
        "alternatives",
        IMPORTS,
        "def clean(flag):\n    if flag:\n        related = Related.objects.filter(row_id=OuterRef('pk'))\n    else:\n        related = Related.objects.filter(enabled=True)\n    unused = Exists(Related.objects.filter(secret=OuterRef('secret')))\n    Row.objects.filter(Exists(related)).delete()\n",
    );
    let r = review(&root, "Row.objects.filter(Exists");
    assert!(has(
        &r,
        "python_orm_query_binding_context",
        "related = Related.objects.filter(row_id=OuterRef('pk'))"
    ));
    assert!(has(
        &r,
        "python_orm_query_binding_context",
        "related = Related.objects.filter(enabled=True)"
    ));
    assert!(!query_facts(&r).iter().any(|f| f.excerpt.contains("secret")));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn predicate_caps_report_partial_source_context() {
    let predicates = (0..6)
        .map(|i| format!("Exists(Related.objects.filter(key_{i}=OuterRef('pk')))"))
        .collect::<Vec<_>>()
        .join(", ");
    let root = prepare(
        "bounded",
        IMPORTS,
        &format!("def clean():\n    Row.objects.filter({predicates}).delete()\n"),
    );
    let r = review(&root, "Row.objects.filter(");
    assert!(r.context_truncated);
    assert_eq!(
        query_facts(&r)
            .iter()
            .filter(|f| f.role == "python_orm_query_predicate_context")
            .count(),
        4
    );
    assert!(query_facts(&r).len() <= 16);
    std::fs::remove_dir_all(root).unwrap();
}
