use mehscan_core::Capability;
use mehscan_engine::investigation::{build_review_inventory, validate_review_inventory};

fn root(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mehscan-python-signal-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(path.join("templates")).unwrap();
    path
}

#[test]
fn escaped_text_defers_value_but_retains_comprehensive_ids_and_evidence() {
    let path = root("escaped");
    std::fs::write(path.join("app.py"), "from flask import render_template, request\ndef view():\n    return render_template('page.html', name=request.args['name'])\n").unwrap();
    std::fs::write(path.join("templates/page.html"), "<p>{{ name }}</p>").unwrap();
    std::fs::write(path.join("django_settings.py"), "TEMPLATES = [{'OPTIONS': {'context_processors': ['django.template.context_processors.request']}}]\n").unwrap();
    let inventory = build_review_inventory(&path, false).unwrap();
    let html: Vec<_> = inventory
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-html-output")
        .collect();
    assert!(!html.is_empty());
    assert!(html.iter().all(|e| {
        e.value_hint
            .as_ref()
            .is_some_and(|h| h.reason == "python_autoescaped_text_template_research")
            && e.comprehensive_exclusion.is_none()
    }));
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.capability == Capability::HtmlOutput)
    );
    validate_review_inventory(&path, &inventory).unwrap();
    std::fs::write(
        path.join("templates/page.html"),
        "<script>{{ name }}</script>",
    )
    .unwrap();
    assert!(
        validate_review_inventory(&path, &inventory).is_err(),
        "template changes must expire admission facts"
    );
    let changed = build_review_inventory(&path, false).unwrap();
    assert!(
        changed
            .entries
            .iter()
            .filter(|e| e.rule_id == "python-html-output")
            .all(|e| e.value_hint.is_none())
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn active_ambiguous_or_custom_template_contexts_stay_in_value() {
    let cases = [
        ("script", "<script>{{ name }}</script>", ""),
        ("style", "<style>{{ name }}</style>", ""),
        ("attribute", "<a href=\"{{ name }}\">link</a>", ""),
        ("unquoted", "<a title={{ name }}>link</a>", ""),
        ("raw", "<p>{{ name | safe }}</p>", ""),
        ("filter", "<p>{{ name | custom }}</p>", ""),
        (
            "autoescape",
            "{% autoescape false %}{{ name }}{% endautoescape %}",
            "",
        ),
        (
            "dynamic_include",
            "{% include selected %}<p>{{ name }}</p>",
            "",
        ),
        (
            "environment",
            "<p>{{ name }}</p>",
            "app.jinja_env.autoescape = False\n",
        ),
        (
            "shadow",
            "<p>{{ name }}</p>",
            "render_template = custom_renderer\n",
        ),
        (
            "markup_alias",
            "<p>{{ name }}</p>",
            "from markupsafe import Markup as trusted\n",
        ),
    ];
    for (label, template, setup) in cases {
        let path = root(label);
        std::fs::write(path.join("app.py"), format!("from flask import render_template, request\n{setup}def view():\n    return render_template('page.html', name=request.args['name'])\n")).unwrap();
        std::fs::write(path.join("templates/page.html"), template).unwrap();
        let inventory = build_review_inventory(&path, false).unwrap();
        let html: Vec<_> = inventory
            .entries
            .iter()
            .filter(|e| e.rule_id == "python-html-output")
            .collect();
        assert!(!html.is_empty(), "{label}");
        assert!(
            html.iter().all(|e| e.value_hint.is_none()),
            "{label}: {html:#?}"
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn inherited_script_context_and_unrelated_import_cannot_defer() {
    for (label, app, template, parent) in [
        (
            "inherited",
            "from flask import render_template, request\ndef view():\n    return render_template('page.html', name=request.args['name'])\n",
            "{% extends 'base.html' %}{% block content %}{{ name }}{% endblock %}",
            "<script>{% block content %}{% endblock %}</script>",
        ),
        (
            "unrelated_import",
            "def setup():\n    from flask import render_template\ndef view():\n    return render_template('page.html', name='name')\n",
            "<p>{{ name }}</p>",
            "",
        ),
    ] {
        let path = root(label);
        std::fs::write(path.join("app.py"), app).unwrap();
        std::fs::write(path.join("templates/page.html"), template).unwrap();
        std::fs::write(path.join("templates/base.html"), parent).unwrap();
        let inventory = build_review_inventory(&path, false).unwrap();
        assert!(
            inventory
                .entries
                .iter()
                .filter(|e| e.rule_id == "python-html-output")
                .all(|e| e.value_hint.is_none()),
            "{label}"
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn fixed_sql_defers_only_the_selected_grammar_question() {
    let path = root("sql");
    std::fs::write(path.join("app.py"), "import sqlite3\nfrom flask import request\ndef view():\n    store = sqlite3.connect('app.db')\n    store.execute('CREATE TABLE IF NOT EXISTS users(name TEXT)')\n    store.execute('SELECT * FROM users WHERE name=?', (request.args['name'],))\n    store.execute('SELECT * FROM users WHERE name=' + request.args['name'])\n").unwrap();
    let inventory = build_review_inventory(&path, false).unwrap();
    let sql: Vec<_> = inventory
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-database-query")
        .collect();
    // The existing parameterized-query admission already closes its local
    // question. This change only defers the remaining constant DDL question.
    assert_eq!(sql.len(), 2, "{sql:#?}");
    assert_eq!(
        sql.iter()
            .filter(|e| e
                .value_hint
                .as_ref()
                .is_some_and(|h| h.reason == "python_fixed_sql_structure_research"))
            .count(),
        1
    );
    assert!(sql.iter().any(|e| e.value_hint.is_none()));
    assert!(sql.iter().all(|e| e.comprehensive_exclusion.is_none()));
    assert_eq!(
        inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.rule_id == "python-database-query")
            .count(),
        3
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn orm_review_delivers_import_bound_task_callers_and_later_effects() {
    let path = root("orm");
    std::fs::create_dir_all(path.join("pkg")).unwrap();
    std::fs::write(path.join("pkg/tasks.py"), "from django.db import models\nclass Row(models.Model):\n    pass\ndef process(job_id):\n    selected = Row.objects.get(pk=job_id)\n    selected.enabled = True\n    selected.save()\n").unwrap();
    std::fs::write(path.join("pkg/views.py"), "from .tasks import process as enqueue\ndef view(request):\n    if not request.user.is_staff:\n        raise PermissionError()\n    enqueue.delay(request.POST['job'])\ndef shadow(enqueue):\n    enqueue.delay('unrelated')\ndef doc():\n    text = \"enqueue.delay('quoted')\"\n").unwrap();
    std::fs::write(
        path.join("other.py"),
        "from unrelated import process\ndef other():\n    process.delay('wrong-module')\n",
    )
    .unwrap();
    let inventory = build_review_inventory(&path, false).unwrap();
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
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&path, Some(8), false).unwrap();
    let facts = jobs
        .observation_reviews
        .iter()
        .flat_map(|r| &r.facts)
        .collect::<Vec<_>>();
    assert!(facts.iter().any(|f| f.role == "python_orm_effect_context" && f.excerpt.contains("selected.save()")));
    let callers: Vec<_> = facts
        .iter()
        .filter(|f| f.role == "python_orm_caller_context")
        .collect();
    assert!(!callers.is_empty(), "{facts:#?}");
    assert!(
        callers
            .iter()
            .all(|f| f.location.path == "pkg/views.py" && f.symbol == "view")
    );
    assert!(
        callers
            .iter()
            .any(|f| f.excerpt.contains("request.user.is_staff")
                && f.excerpt.contains("enqueue.delay(request.POST['job'])"))
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn orm_shared_reads_group_by_exact_callable_not_repeated_method_names() {
    let path = root("orm-groups");
    std::fs::write(path.join("app.py"), "from django.db import models\nclass Row(models.Model):\n    pass\ndef shared(first, second):\n    one = Row.objects.get(pk=first)\n    two = Row.objects.get(pk=second)\n    return one, two\nclass First:\n    def get(self, key):\n        return Row.objects.get(pk=key)\nclass Second:\n    def get(self, key):\n        return Row.objects.get(pk=key)\n").unwrap();
    let inventory = build_review_inventory(&path, false).unwrap();
    let entries: Vec<_> = inventory
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-django-orm-resource-access")
        .collect();
    assert_eq!(entries.len(), 4);
    assert!(
        entries.iter().all(|e| e
            .operand_facts
            .iter()
            .filter(|f| f.role.as_deref() == Some("resource_operation"))
            .count()
            == 1),
        "callable grouping must not duplicate existing native facts"
    );
    let locations = entries
        .iter()
        .map(|e| {
            e.operand_facts
                .iter()
                .find(|f| f.role.as_deref() == Some("resource_operation"))
                .and_then(|f| f.location.as_ref())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let shared = entries
        .iter()
        .zip(&locations)
        .filter(|(e, _)| e.symbol.as_deref() == Some("shared"))
        .map(|(_, l)| *l)
        .collect::<Vec<_>>();
    let methods = entries
        .iter()
        .zip(&locations)
        .filter(|(e, _)| e.symbol.as_deref() == Some("get"))
        .map(|(_, l)| *l)
        .collect::<Vec<_>>();
    assert_eq!(shared.len(), 2);
    assert_eq!(shared[0], shared[1]);
    assert_eq!(methods.len(), 2);
    assert_ne!(methods[0], methods[1]);
    assert_eq!(
        locations
            .iter()
            .map(|l| (l.start.byte_offset, l.end.byte_offset))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert!(
        entries
            .iter()
            .all(|e| e.value_hint.is_none() && e.comprehensive_exclusion.is_none())
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn template_context_follows_supplied_bindings_and_collection_aliases() {
    for (label, data, template, deferred) in [
        (
            "unrelated_link",
            "name=request.args['name']",
            "<a href=\"{{ url_for('home') }}\">Home</a><p>{{ name }}</p>",
            true,
        ),
        (
            "loop_text",
            "names=request.args.getlist('name')",
            "{% for name in names %}<p>{{ name }}</p>{% endfor %}",
            true,
        ),
        (
            "loop_attribute",
            "names=request.args.getlist('name')",
            "{% for name in names %}<a href=\"{{ name }}\">link</a>{% endfor %}",
            false,
        ),
        (
            "loop_call",
            "names=request.args.getlist('name')",
            "{% for name in transform(names) %}{{ name }}{% endfor %}",
            false,
        ),
        ("unknown_kwargs", "**context", "<p>{{ name }}</p>", false),
    ] {
        let path = root(label);
        std::fs::write(path.join("app.py"), format!("from flask import render_template, request\ndef view():\n    return render_template('page.html', {data})\n")).unwrap();
        std::fs::write(path.join("templates/page.html"), template).unwrap();
        let inventory = build_review_inventory(&path, false).unwrap();
        let entries: Vec<_> = inventory
            .entries
            .iter()
            .filter(|e| e.rule_id == "python-html-output")
            .collect();
        assert!(!entries.is_empty(), "{label}");
        assert!(
            entries.iter().all(|e| e.value_hint.is_some() == deferred),
            "{label}: {entries:#?}"
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
