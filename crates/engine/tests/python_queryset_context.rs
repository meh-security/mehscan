use mehscan_core::ReviewNeighborhoodFact;
use mehscan_engine::investigation::{build_all_path_review_jobs, build_review_inventory};

const QUERYSETS: &str = "from django.db import models\nclass PublicBase(models.QuerySet[object]):\n    def published(self):\n        return self.filter(public=True)\nclass Scoped(PublicBase):\n    def for_actor(self, actor):\n        if actor.is_staff:\n            return self.all()\n        return self.published()\n    def reset(self):\n        return type(self)(model=self.model)\nFactory = models.Manager.from_queryset(Scoped)\n";

fn prepare(label: &str, manager: &str, queryset_extra: &str, view: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("mehscan-queryset-{label}-{}", std::process::id()));
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(
        root.join("pkg/querysets.py"),
        format!("{QUERYSETS}{queryset_extra}"),
    )
    .unwrap();
    std::fs::write(root.join("pkg/models.py"), format!("from django.db import models\nfrom .querysets import Factory, Scoped\nclass Entry(models.Model):\n{manager}\n")).unwrap();
    std::fs::write(
        root.join("helpers.py"),
        "def actor_for(request):\n    return request.user\n",
    )
    .unwrap();
    std::fs::write(
        root.join("view.py"),
        format!("from pkg import models\nfrom helpers import actor_for\n{view}"),
    )
    .unwrap();
    root
}

fn facts(root: &std::path::Path) -> Vec<ReviewNeighborhoodFact> {
    let inventory = build_review_inventory(root, false).unwrap();
    let entries: Vec<_> = inventory
        .entries
        .iter()
        .filter(|e| e.rule_id == "python-django-orm-resource-access" && e.path == "view.py")
        .collect();
    assert_eq!(entries.len(), 1, "{entries:#?}");
    assert!(
        entries
            .iter()
            .all(|e| e.value_hint.is_none() && e.comprehensive_exclusion.is_none())
    );
    let jobs = build_all_path_review_jobs(root, Some(32), false).unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                r.anchor_evidence_ids.contains(&e.id)
                    && e.location.path == "view.py"
                    && e.rule_id == "python-django-orm-resource-access"
            })
        })
        .unwrap();
    assert!(review.decision_facts.effective_controls.is_empty());
    let facts: Vec<_> = review
        .facts
        .iter()
        .filter(|f| f.role.starts_with("python_queryset_"))
        .cloned()
        .collect();
    for fact in &facts {
        let bytes = std::fs::read(root.join(&fact.location.path)).unwrap();
        assert_eq!(
            std::str::from_utf8(
                &bytes[fact.location.start.byte_offset..fact.location.end.byte_offset]
            )
            .unwrap(),
            fact.excerpt
        );
    }
    facts
}

const VIEW: &str = "def view(request, key):\n    actor = actor_for(request)\n    return models.Entry.objects.using('read').for_actor(actor).get(pk=key)\n";

#[test]
fn follows_imported_factory_queryset_argument_producer_and_inherited_delegate() {
    let root = prepare("factory", "    objects = Factory()", "", VIEW);
    let facts = facts(&root);
    for (role, text) in [
        ("python_queryset_manager_context", "objects = Factory()"),
        (
            "python_queryset_manager_context",
            "Manager.from_queryset(Scoped)",
        ),
        ("python_queryset_method_context", "if actor.is_staff"),
        (
            "python_queryset_argument_context",
            "actor = actor_for(request)",
        ),
        (
            "python_queryset_argument_helper_context",
            "return request.user",
        ),
        (
            "python_queryset_delegate_context",
            "self.filter(public=True)",
        ),
    ] {
        assert!(
            facts
                .iter()
                .any(|f| f.role == role && f.excerpt.contains(text)),
            "missing {role} {text}: {facts:#?}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn supports_as_manager_and_inline_factory_construction() {
    for (label, manager) in [
        ("as-manager", "    objects = Scoped.as_manager()"),
        (
            "inline",
            "    objects = models.Manager.from_queryset(Scoped)()",
        ),
    ] {
        let root = prepare(label, manager, "", VIEW);
        assert!(
            facts(&root)
                .iter()
                .any(|f| f.role == "python_queryset_method_context"
                    && f.excerpt.contains("def for_actor"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn unresolved_reassigned_shadowed_and_overridden_bindings_are_not_guessed() {
    for (label, manager, extra, view) in [
        ("unknown", "    objects = UnknownManager()", "", VIEW),
        (
            "factory-augmented",
            "    objects = Factory()",
            "Factory += other\n",
            VIEW,
        ),
        (
            "factory-reassigned",
            "    objects = Factory()",
            "Factory = other\n",
            VIEW,
        ),
        (
            "manager-reassigned",
            "    objects = Factory()\n    objects = other",
            "",
            VIEW,
        ),
        (
            "shadowed",
            "    objects = Factory()",
            "",
            "def view(request, key, models):\n    return models.Entry.objects.for_actor(request.user).get(pk=key)\n",
        ),
        (
            "closure-shadowed",
            "    objects = Factory()",
            "",
            "def outer(models):\n    def view(request, key):\n        return models.Entry.objects.for_actor(request.user).get(pk=key)\n    return view\n",
        ),
        (
            "loop-shadowed",
            "    objects = Factory()",
            "",
            "def view(request, key):\n    for models in request.providers:\n        return models.Entry.objects.for_actor(request.user).get(pk=key)\n",
        ),
        (
            "overridden-construction",
            "    objects = Scoped.as_manager()",
            "Scoped.as_manager = custom\n",
            VIEW,
        ),
        (
            "unrelated-factory",
            "    objects = Factory()",
            "models = unrelated\n",
            VIEW,
        ),
        (
            "overridden-method",
            "    objects = Factory()",
            "Scoped.for_actor = unrelated\n",
            VIEW,
        ),
    ] {
        let root = prepare(label, manager, extra, view);
        assert!(facts(&root).is_empty(), "{label}");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn reset_methods_and_rebound_argument_producers_never_receive_control_credit() {
    let root = prepare(
        "reset",
        "    objects = Factory()",
        "",
        "def view(request, key, actor_for):\n    actor = actor_for(request)\n    return models.Entry.objects.for_actor(actor).reset().get(pk=key)\n",
    );
    let facts = facts(&root);
    assert!(
        facts
            .iter()
            .any(|f| f.role == "python_queryset_method_context"
                && f.excerpt.contains("type(self)(model=self.model)")),
        "{facts:#?}"
    );
    assert!(
        !facts
            .iter()
            .any(|f| f.role == "python_queryset_argument_helper_context")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn queryset_name_without_declared_django_base_is_insufficient() {
    let root = prepare("unrelated-queryset", "    objects = Factory()", "", VIEW);
    std::fs::write(
        root.join("pkg/querysets.py"),
        QUERYSETS.replace("models.QuerySet[object]", "UnknownBase"),
    )
    .unwrap();
    assert!(facts(&root).is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn class_member_overrides_are_not_treated_as_django_construction() {
    let root = prepare(
        "class-override",
        "    objects = Scoped.as_manager()",
        "",
        VIEW,
    );
    std::fs::write(
        root.join("pkg/querysets.py"),
        QUERYSETS.replace(
            "class Scoped(PublicBase):",
            "class Scoped(PublicBase):\n    as_manager = replacement",
        ),
    )
    .unwrap();
    assert!(facts(&root).is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn mutation_and_queryset_policy_contexts_are_both_retained() {
    let root = prepare(
        "combined",
        "    objects = Factory()",
        "",
        "class Action:\n    class Meta:\n        permissions = ('manage_records',)\n    @classmethod\n    def check_permissions(cls, context):\n        return context.user.is_staff\n    @classmethod\n    def mutate(cls, info, key):\n        if not cls.check_permissions(info.context):\n            raise PermissionError()\n        return cls.perform_mutation(info, key)\n    @classmethod\n    def perform_mutation(cls, info, key):\n        return models.Entry.objects.for_actor(info.context.user).get(pk=key)\n",
    );
    let jobs = build_all_path_review_jobs(&root, Some(32), false).unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                r.anchor_evidence_ids.contains(&e.id)
                    && e.location.path == "view.py"
                    && e.rule_id == "python-django-orm-resource-access"
            })
        })
        .unwrap();
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "python_queryset_method_context")
    );
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "python_mutation_check_context")
    );
    assert!(review.decision_facts.effective_controls.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}
