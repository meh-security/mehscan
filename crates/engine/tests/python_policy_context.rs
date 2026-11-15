use mehscan_core::ReviewNeighborhoodFact;
use mehscan_engine::investigation::{build_all_path_review_jobs, build_review_inventory};

fn root(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mehscan-python-policy-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(path.join("api")).unwrap();
    path
}

const BASE: &str = "from .permissions import allowed\nclass Gate:\n    @classmethod\n    def check_permissions(cls, context):\n        return allowed(context, cls._meta.permissions)\n    @classmethod\n    def mutate(cls, root, info, **data):\n        if not cls.check_permissions(info.context):\n            raise PermissionError()\n        return cls.perform_mutation(root, info, **data)\n";

fn prepare(path: &std::path::Path, extra: &str, metadata: &str) {
    std::fs::write(path.join("api/base.py"), BASE).unwrap();
    std::fs::write(
        path.join("api/permissions.py"),
        "def allowed(context, permissions):\n    return context.user.has_perms(permissions)\n",
    )
    .unwrap();
    std::fs::write(path.join("api/actions.py"), format!("from .base import Gate as Parent\nfrom django.db import models\nclass Row(models.Model):\n    pass\nclass Action(Parent):\n{metadata}{extra}    @classmethod\n    def perform_mutation(cls, root, info, key):\n        selected = Row.objects.get(pk=key)\n        selected.delete()\n")).unwrap();
    std::fs::write(
        path.join("api/__init__.py"),
        "from .actions import Action as Exported\n",
    )
    .unwrap();
    std::fs::write(
        path.join("schema.py"),
        "from api import Exported as Selected\nclass Mutation:\n    action = Selected.Field()\n",
    )
    .unwrap();
}

fn facts(path: &std::path::Path) -> Vec<ReviewNeighborhoodFact> {
    let inventory = build_review_inventory(path, false).unwrap();
    let entries: Vec<_> = inventory
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-django-orm-resource-access")
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(
        entries
            .iter()
            .all(|e| e.value_hint.is_none() && e.comprehensive_exclusion.is_none())
    );
    let jobs = build_all_path_review_jobs(path, Some(8), false).unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                r.anchor_evidence_ids.contains(&e.id)
                    && e.rule_id == "python-django-orm-resource-access"
            })
        })
        .unwrap();
    assert!(
        review.decision_facts.effective_controls.is_empty(),
        "source policy context must not assert a verified guard"
    );
    for f in review.facts.iter().filter(|f| {
        f.role.starts_with("python_mutation_") || f.role == "python_permission_helper_context"
    }) {
        let bytes = std::fs::read(path.join(&f.location.path)).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes[f.location.start.byte_offset..f.location.end.byte_offset])
                .unwrap(),
            f.excerpt
        );
    }
    review.facts.clone()
}

#[test]
fn resolves_relative_base_aliases_reexports_metadata_gate_and_helper() {
    let path = root("bound");
    prepare(
        &path,
        "",
        "    class Meta:\n        permissions = ('manage_records',)\n",
    );
    let fs = facts(&path);
    for (role, text) in [
        ("python_mutation_metadata_context", "manage_records"),
        (
            "python_mutation_entrypoint_context",
            "raise PermissionError",
        ),
        ("python_mutation_check_context", "cls._meta.permissions"),
        ("python_permission_helper_context", "context.user.has_perms"),
        ("python_mutation_field_context", "Selected.Field()"),
        ("python_mutation_import_context", "Gate as Parent"),
    ] {
        assert!(
            fs.iter()
                .any(|f| f.role == role && f.excerpt.contains(text)),
            "{role}: {fs:#?}"
        );
    }
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn overrides_empty_permissions_and_alternate_callers_remain_explicit() {
    let path = root("overridden");
    prepare(
        &path,
        "    @classmethod\n    def check_permissions(cls, context):\n        return True\n",
        "    class Meta:\n        permissions = ()\n",
    );
    std::fs::write(path.join("bypass.py"), "from api.actions import Action as Selected\ndef direct(info, key):\n    return Selected.perform_mutation(None, info, key)\ndef shadow(Selected):\n    return Selected.perform_mutation(None, None, 1)\n").unwrap();
    let fs = facts(&path);
    assert!(fs.iter().any(|f| f.role == "python_mutation_check_context"
        && f.location.path == "api/actions.py"
        && f.excerpt.contains("return True")));
    assert!(
        fs.iter()
            .any(|f| f.role == "python_mutation_metadata_context"
                && f.excerpt.contains("permissions = ()"))
    );
    let calls: Vec<_> = fs
        .iter()
        .filter(|f| f.role == "python_mutation_direct_call_context")
        .collect();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0]
            .excerpt
            .contains("Selected.perform_mutation(None, info, key)")
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn missing_policy_and_late_checks_do_not_imply_authorization() {
    let path = root("late");
    prepare(&path, "", "");
    std::fs::write(path.join("api/base.py"), "class Gate:\n    @classmethod\n    def check_permissions(cls, context):\n        return True\n    @classmethod\n    def mutate(cls, root, info, **data):\n        result = cls.perform_mutation(root, info, **data)\n        if not cls.check_permissions(info.context):\n            raise PermissionError()\n        return result\n").unwrap();
    let fs = facts(&path);
    assert!(
        !fs.iter()
            .any(|f| f.role == "python_mutation_metadata_context")
    );
    let entry = fs
        .iter()
        .find(|f| f.role == "python_mutation_entrypoint_context")
        .unwrap();
    assert!(
        entry.excerpt.find("cls.perform_mutation").unwrap()
            < entry.excerpt.find("cls.check_permissions").unwrap()
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn unrelated_or_reassigned_bases_are_not_guessed_by_name() {
    for (label, replacement) in [
        ("unresolved", "from missing import Gate as Parent"),
        (
            "reassigned",
            "from .base import Gate as Parent\nParent = other",
        ),
        (
            "collision",
            "from .base import Gate as Parent\nfrom unrelated import Other as Parent",
        ),
    ] {
        let path = root(label);
        prepare(&path, "", "");
        let source = std::fs::read_to_string(path.join("api/actions.py"))
            .unwrap()
            .replace("from .base import Gate as Parent", replacement);
        std::fs::write(path.join("api/actions.py"), source).unwrap();
        let fs = facts(&path);
        assert!(
            !fs.iter()
                .any(|f| f.role == "python_mutation_entrypoint_context"
                    || f.role == "python_mutation_check_context"),
            "{label}: {fs:#?}"
        );
        assert!(fs.iter().any(|f| f.role == "python_mutation_class_context"
            && f.provenance.engine.contains("unresolved")));
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn namespace_bases_and_inherited_permissions_keep_the_source_declarations() {
    let path = root("namespace");
    prepare(&path, "", "");
    let source = std::fs::read_to_string(path.join("api/actions.py"))
        .unwrap()
        .replace(
            "from .base import Gate as Parent",
            "from . import base as policy",
        )
        .replace("class Action(Parent):", "class Action(policy.Gate):");
    std::fs::write(path.join("api/actions.py"), source).unwrap();
    std::fs::write(
        path.join("api/base.py"),
        BASE.replace(
            "class Gate:\n",
            "class Gate:\n    class Meta:\n        permissions = ('base_permission',)\n",
        ),
    )
    .unwrap();
    let fs = facts(&path);
    assert!(
        fs.iter()
            .any(|f| f.role == "python_mutation_inherited_metadata_context"
                && f.excerpt.contains("base_permission"))
    );
    assert!(fs.iter().any(
        |f| f.role == "python_mutation_entrypoint_context" && f.location.path == "api/base.py"
    ));
    std::fs::remove_dir_all(path).unwrap();
}
