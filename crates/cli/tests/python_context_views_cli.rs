use serde_json::Value;
use std::{fs, process::Command};

fn run(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_mehscan"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn python_role(value: &Value) -> bool {
    value["role"].as_str().is_some_and(|r| {
        r.starts_with("python_orm_")
            || r.starts_with("python_mutation_")
            || r.starts_with("python_queryset_")
            || r == "python_permission_helper_context"
    })
}

#[test]
fn python_policy_selection_and_query_sources_reach_cards_and_worker_sweeps() {
    let base = std::env::temp_dir().join(format!("mehscan-python-views-{}", std::process::id()));
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("models.py"), "from django.db import models\nclass Visible(models.QuerySet):\n    def for_actor(self, actor):\n        return self.filter(public=True)\nFactory = models.Manager.from_queryset(Visible)\nclass Row(models.Model):\n    public = models.BooleanField()\n    objects = Factory()\nclass Related(models.Model):\n    row = models.ForeignKey(Row, on_delete=models.CASCADE)\n").unwrap();
    fs::write(source.join("base.py"), "class Gate:\n    @classmethod\n    def check_permissions(cls, context):\n        return context.user.has_perms(cls.Meta.permissions)\n    @classmethod\n    def mutate(cls, info, key):\n        if not cls.check_permissions(info.context):\n            raise PermissionError()\n        return cls.perform_mutation(info, key)\n    @classmethod\n    def Field(cls):\n        return cls()\n").unwrap();
    fs::write(source.join("app.py"), "from django.db.models import Exists, OuterRef\nfrom models import Row, Related\nfrom base import Gate\nclass Action(Gate):\n    class Meta:\n        permissions = ('manage_rows',)\n    @classmethod\n    def perform_mutation(cls, info, key):\n        selected = Row.objects.for_actor(info.context.user).get(pk=key)\n        alias = selected\n        alias.delete()\nclass Mutation:\n    action = Action.Field()\ndef cleanup(keys):\n    Row.objects.filter(Exists(Related.objects.filter(row_id=OuterRef('pk'), pk__in=keys))).delete()\n").unwrap();
    let inventory = base.join("inventory");
    run(&[
        "investigate",
        "review-inventory",
        source.to_str().unwrap(),
        "--output",
        inventory.to_str().unwrap(),
    ]);
    let inv: Value =
        serde_json::from_slice(&fs::read(inventory.join("inventory.json")).unwrap()).unwrap();
    let ids: Vec<_> = inv["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["rule_id"] == "python-django-orm-resource-access")
        .map(|r| r["review_id"].as_str().unwrap())
        .collect();
    assert!(!ids.is_empty());
    let bundles = base.join("bundles");
    run(&[
        "investigate",
        "review-bundles",
        source.to_str().unwrap(),
        "--inventory",
        inventory.to_str().unwrap(),
        "--review-ids",
        &ids.join(","),
        "--output",
        bundles.to_str().unwrap(),
    ]);
    let manifest: Value =
        serde_json::from_slice(&fs::read(bundles.join("manifest.json")).unwrap()).unwrap();
    let mut roles = std::collections::BTreeSet::new();
    for entry in manifest["bundles"].as_array().unwrap() {
        let request = bundles
            .join("requests")
            .join(entry["filename"].as_str().unwrap());
        let raw: Value = serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        let sweep = run(&[
            "investigate",
            "review-sweep",
            "--bundle",
            request.to_str().unwrap(),
        ]);
        for review in raw["reviews"].as_array().unwrap() {
            let card = run(&[
                "investigate",
                "review-card",
                "--bundle",
                request.to_str().unwrap(),
                "--review-id",
                review["id"].as_str().unwrap(),
            ]);
            let contexts = card["helper_context"].as_array().unwrap();
            let expected = review["facts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| {
                    python_role(f)
                        && f["evidence_id"].as_str().is_none_or(|id| {
                            Some(id) == card["anchor"]["id"].as_str()
                                || id.starts_with("fact-artifact-")
                        })
                        && f["excerpt"].as_str().is_some_and(|s| !s.is_empty())
                })
                .count();
            assert!(expected > 0);
            assert_eq!(contexts.iter().filter(|f| python_role(f)).count(), expected);
            assert!(
                card["decision_facts"]["effective_controls"]
                    .as_array()
                    .is_none_or(|v| v.is_empty())
            );
            for context in contexts.iter().filter(|f| python_role(f)) {
                roles.insert(context["role"].as_str().unwrap().to_string());
                assert_eq!(context["verified"], false);
                assert!(
                    context["evidence_id"]
                        .as_str()
                        .is_none_or(|id| Some(id) == card["anchor"]["id"].as_str()
                            || id.starts_with("fact-artifact-"))
                );
                let loc = &context["location"];
                let bytes = fs::read(source.join(loc["path"].as_str().unwrap())).unwrap();
                let start = loc["start_byte_offset"].as_u64().unwrap() as usize;
                let end = loc["end_byte_offset"].as_u64().unwrap() as usize;
                assert_eq!(
                    std::str::from_utf8(&bytes[start..end]).unwrap(),
                    context["excerpt"].as_str().unwrap()
                );
                assert!(
                    sweep["source_contexts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|s| s["role"] == context["role"]
                            && s["excerpt"] == context["excerpt"]
                            && s["location"] == context["location"])
                );
            }
        }
    }
    for role in [
        "python_mutation_check_context",
        "python_queryset_method_context",
        "python_orm_alias_context",
        "python_orm_query_predicate_context",
        "python_orm_outer_reference_context",
    ] {
        assert!(roles.contains(role), "missing {role}: {roles:?}");
    }
    fs::remove_dir_all(base).unwrap();
}
