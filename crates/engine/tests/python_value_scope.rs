use mehscan_engine::investigation::{
    ReviewInventory, build_all_path_review_jobs, build_review_inventory,
};

fn scan(label: &str, source: &str) -> (std::path::PathBuf, ReviewInventory) {
    let root = std::env::temp_dir().join(format!(
        "mehscan-python-value-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.py"), source).unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    (root, inventory)
}

const MODELS: &str = "from django.db import models\nfrom django.db.models import Exists\nclass Row(models.Model):\n    pass\nclass Related(models.Model):\n    pass\n";

#[test]
fn one_query_chain_retains_one_complete_review_and_explicit_dependencies() {
    let chain = "Row.objects.filter(pk__in=keys).filter(kind=kind).delete()";
    let (root, inv) = scan("chain", &format!("{MODELS}def clean(keys):\n    {chain}\n"));
    let entries: Vec<_> = inv
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-django-orm-resource-access")
        .collect();
    assert_eq!(entries.len(), 2);
    let retained = entries.iter().find(|e| e.value_hint.is_none()).unwrap();
    let deferred = entries.iter().find_map(|e| e.value_hint.as_ref()).unwrap();
    assert_eq!(deferred.reason, "python_shared_orm_receiver_chain");
    assert_eq!(deferred.depends_on.as_ref(), Some(&retained.review_id));
    assert!(entries.iter().all(|e| e.comprehensive_exclusion.is_none()));
    assert_eq!(
        inv.scan
            .evidence
            .iter()
            .filter(|e| e.rule_id == "python-django-orm-resource-access")
            .count(),
        2
    );
    let jobs = build_all_path_review_jobs(&root, Some(32), false).unwrap();
    for entry in entries {
        let review = jobs
            .observation_reviews
            .iter()
            .find(|r| r.id == entry.review_id)
            .unwrap();
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "python_orm_shared_chain_context")
            .unwrap();
        assert_eq!(fact.excerpt, chain);
        assert!(
            fact.evidence_id
                .as_ref()
                .is_some_and(|id| review.anchor_evidence_ids.contains(id))
        );
        assert!(review.decision_facts.effective_controls.is_empty());
        let bytes = std::fs::read(root.join(&fact.location.path)).unwrap();
        assert_eq!(
            &bytes[fact.location.start.byte_offset..fact.location.end.byte_offset],
            chain.as_bytes()
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn uncorrelated_exists_keeps_the_first_question_and_whole_buggy_effect() {
    let chain = "Row.objects.filter(Exists(Related.objects.filter(pk__in=keys))).filter(kind=kind).delete()";
    let (root, inv) = scan(
        "exists-chain",
        &format!("{MODELS}def clean(keys):\n    {chain}\n"),
    );
    let entries: Vec<_> = inv
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-django-orm-resource-access")
        .collect();
    assert_eq!(entries.len(), 2, "{entries:#?}");
    let retained = entries.iter().find(|e| e.value_hint.is_none()).unwrap();
    let anchor = inv
        .scan
        .evidence
        .iter()
        .find(|e| e.id == retained.identity.as_ref().unwrap().anchor_id)
        .unwrap();
    assert_eq!(
        anchor.captures["filter"].text,
        "Exists(Related.objects.filter(pk__in=keys))"
    );
    let jobs = build_all_path_review_jobs(&root, Some(32), false).unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| r.id == retained.review_id)
        .unwrap();
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "python_orm_shared_chain_context" && f.excerpt == chain)
    );
    assert!(review.decision_facts.effective_controls.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nested_queries_and_separate_operations_keep_independent_reviews() {
    let (root, inv) = scan(
        "independent",
        &format!(
            "{MODELS}def clean(keys, other):\n    Row.objects.filter(pk=Related.objects.get(pk=other).id).filter(kind=kind).delete()\n    Row.objects.filter(pk__in=keys).delete()\n    Row.objects.filter(pk__in=keys).delete()\n"
        ),
    );
    let entries: Vec<_> = inv
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-django-orm-resource-access")
        .collect();
    assert_eq!(entries.len(), 5, "{entries:#?}");
    assert_eq!(entries.iter().filter(|e| e.value_hint.is_some()).count(), 1);
    let nested = inv
        .scan
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "python-django-orm-resource-access" && e.captures["filter"].text == "other"
        })
        .unwrap();
    assert!(
        entries
            .iter()
            .find(|e| e.identity.as_ref().unwrap().anchor_id == nested.id)
            .unwrap()
            .value_hint
            .is_none()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_transforms_earlier_terminals_and_oversized_chains_stay_in_value() {
    for (label, expression) in [
        (
            "transform",
            "Row.objects.filter(pk=key).custom().filter(kind=kind).delete()".to_string(),
        ),
        (
            "earlier-terminal",
            "Row.objects.get(pk=key).children.objects.filter(pk=key).filter(kind=kind).delete()"
                .to_string(),
        ),
        (
            "oversized",
            format!(
                "Row.objects.filter(pk=key).filter(kind='{}').delete()",
                "x".repeat(4096)
            ),
        ),
    ] {
        let (root, inv) = scan(
            label,
            &format!("{MODELS}def clean(key):\n    {expression}\n"),
        );
        let entries: Vec<_> = inv
            .entries
            .iter()
            .filter(|e| e.rule_id == "python-django-orm-resource-access")
            .collect();
        assert!(!entries.is_empty());
        assert!(
            entries.iter().all(|e| e.value_hint.is_none()),
            "{label}: {entries:#?}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn fixed_response_bodies_defer_but_keep_comprehensive_and_raw_evidence() {
    let (root, inv) = scan(
        "responses",
        "from django.http import HttpResponse\ndef view(request):\n    if request.method == 'POST':\n        response = HttpResponse(status=500)\n        response.content = 'Configuration missing'\n        return response\n    if request.method == 'PUT':\n        return HttpResponse(status=400)\n    return HttpResponse('Ready', status=200, content_type='text/html')\n",
    );
    let entries: Vec<_> = inv
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-html-output")
        .collect();
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().all(|e| e
            .value_hint
            .as_ref()
            .is_some_and(|h| h.reason == "python_fixed_http_response_body_research"
                && h.depends_on.is_none())
            && e.comprehensive_exclusion.is_none())
    );
    assert_eq!(
        inv.scan
            .evidence
            .iter()
            .filter(|e| e.rule_id == "python-html-output")
            .count(),
        2
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn dynamic_or_escaping_responses_and_unbound_constructors_stay_in_value() {
    for (label, setup, body) in [
        ("dynamic", "", "return HttpResponse(request.GET['body'])"),
        ("fstring", "", "return HttpResponse(f'{request.GET}')"),
        (
            "dynamic-keyword",
            "",
            "return HttpResponse(content=request.GET['body'])",
        ),
        (
            "dynamic-status",
            "",
            "return HttpResponse(status=request.GET['status'])",
        ),
        ("spread", "", "return HttpResponse(**request.GET)"),
        (
            "shadow",
            "HttpResponse = custom\n",
            "return HttpResponse(status=200)",
        ),
        (
            "other-import",
            "from custom import HttpResponse\n",
            "return HttpResponse(status=200)",
        ),
        (
            "wildcard",
            "from custom import *\n",
            "return HttpResponse(status=200)",
        ),
        (
            "dynamic-write",
            "",
            "response = HttpResponse(status=200)\n    response.content = request.GET['body']\n    return response",
        ),
        (
            "alias",
            "",
            "response = HttpResponse(status=200)\n    alias = response\n    alias.content = request.GET['body']\n    return response",
        ),
        (
            "helper",
            "",
            "response = HttpResponse(status=200)\n    decorate(response, request.GET)\n    return response",
        ),
        (
            "closure",
            "",
            "response = HttpResponse(status=200)\n    def later():\n        return response\n    return later",
        ),
        (
            "write-method",
            "",
            "response = HttpResponse(status=200)\n    response.write(request.GET['body'])\n    return response",
        ),
        (
            "rebind",
            "",
            "response = HttpResponse(status=200)\n    response = custom\n    return response",
        ),
        (
            "unbound",
            "def unrelated():\n    from django.http import HttpResponse\n",
            "return HttpResponse(status=200)",
        ),
    ] {
        let import = if label == "unbound" {
            ""
        } else {
            "from django.http import HttpResponse\n"
        };
        let (root, inv) = scan(
            label,
            &format!("{import}{setup}def view(request):\n    {body}\n"),
        );
        let entries: Vec<_> = inv
            .entries
            .iter()
            .filter(|e| e.rule_id == "python-html-output")
            .collect();
        assert!(!entries.is_empty(), "{label}");
        assert!(
            entries.iter().all(|e| e.value_hint.is_none()),
            "{label}: {entries:#?}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
