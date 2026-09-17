use super::identity::{self, Imports, KNode};
use crate::code::matcher::location;
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{QueryProvenance, Resolution, ReviewNeighborhoodFact};

fn package(root: &KNode<'_>) -> String {
    root.children()
        .find(|n| n.kind().as_ref() == "package_header")
        .map(|n| {
            n.text()
                .trim_start_matches("package")
                .trim()
                .trim_end_matches(';')
                .to_string()
        })
        .unwrap_or_default()
}

fn canonical(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.into()
    } else {
        format!("{package}.{name}")
    }
}

fn matches_type<'a>(
    root: &KNode<'a>,
    imports: &Imports,
    node: &KNode<'a>,
    observed: &str,
    target: &str,
) -> bool {
    imports.exact(root, node, observed, target)
        || (!observed.contains('.')
            && canonical(&package(root), observed) == target
            && !root.dfs().any(|n| {
                n.kind().as_ref() == "type_alias" && identity::name(&n).as_deref() == Some(observed)
            }))
}

/// Exact declared receiver and unique direct implementation context. These
/// facts are source excerpts for review, not a runtime-dispatch or flow proof.
pub(crate) fn caller_facts(
    files: &[(&str, &str)],
    target_path: &str,
    anchor: usize,
    limit: usize,
) -> Vec<ReviewNeighborhoodFact> {
    let Some((_, source)) = files.iter().find(|(path, _)| *path == target_path) else {
        return vec![];
    };
    let target_ast = SupportLang::Kotlin.ast_grep(source);
    let target_root = target_ast.root();
    if target_root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(method) = target_root
        .dfs()
        .find(|n| n.kind().as_ref() == "function_declaration" && n.range().contains(&anchor))
    else {
        return vec![];
    };
    let Some(owner) = identity::owner(&method) else {
        return vec![];
    };
    let Some(method_name) = identity::name(&method) else {
        return vec![];
    };
    let Some(owner_name) = identity::name(&owner) else {
        return vec![];
    };
    let method_arity = identity::named_child(&method, "function_value_parameters").map_or(0, |n| {
        n.children()
            .filter(|n| n.kind().as_ref() == "parameter")
            .count()
    });
    if owner
        .children()
        .filter(|n| n.kind().as_ref() == "class_body")
        .flat_map(|n| n.children().collect::<Vec<_>>())
        .filter(|n| {
            n.kind().as_ref() == "function_declaration"
                && identity::name(n).as_deref() == Some(&method_name)
        })
        .count()
        != 1
    {
        return vec![];
    }
    let owner_type = canonical(&package(&target_root), &owner_name);
    let parent_types = owner
        .children()
        .filter(|n| n.kind().as_ref() == "delegation_specifier")
        .flat_map(|n| {
            n.dfs()
                .filter(|n| n.kind().as_ref() == "user_type")
                .collect::<Vec<_>>()
        })
        .map(|n| canonical(&package(&target_root), &n.text()))
        .collect::<Vec<_>>();
    let mut permitted = vec![owner_type.clone()];
    for parent in parent_types {
        let declarations = files
            .iter()
            .map(|(_, source)| {
                let ast = SupportLang::Kotlin.ast_grep(source);
                let root = ast.root();
                root.dfs()
                    .filter(|n| n.kind().as_ref() == "class_declaration")
                    .filter(|n| {
                        identity::name(n)
                            .is_some_and(|name| canonical(&package(&root), &name) == parent)
                    })
                    .count()
            })
            .sum::<usize>();
        if declarations != 1 {
            continue;
        }
        let mut implementations = 0;
        for (_, source) in files {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let imports = Imports::build(&root);
            for ty in root.dfs().filter(|n| {
                n.kind().as_ref() == "class_declaration"
                    && !n.text().trim_start().starts_with("interface ")
            }) {
                if ty
                    .children()
                    .filter(|n| n.kind().as_ref() == "delegation_specifier")
                    .flat_map(|n| {
                        n.dfs()
                            .filter(|n| n.kind().as_ref() == "user_type")
                            .collect::<Vec<_>>()
                    })
                    .any(|n| matches_type(&root, &imports, &n, &n.text(), &parent))
                {
                    implementations += 1;
                }
            }
        }
        if implementations == 1 {
            permitted.push(parent);
        }
    }
    let mut result = vec![];
    let mut caller_count = 0;
    for (path, source) in files {
        let ast = SupportLang::Kotlin.ast_grep(source);
        let root = ast.root();
        if root.dfs().any(|n| n.is_error() || n.is_missing()) {
            continue;
        }
        let imports = Imports::build(&root);
        for node in root.dfs() {
            let Some(call) = identity::call(&node) else {
                continue;
            };
            let observed = call.callee.text();
            let Some((receiver, name)) = observed.rsplit_once('.') else {
                continue;
            };
            if name != method_name
                || call.arguments.len() != method_arity
                || call.arguments.iter().any(|a| a.name.is_some())
                || !identity::receiver_unchanged(&root, &node, receiver)
            {
                continue;
            }
            let Some(ty) = identity::binding_type(&root, &node, receiver) else {
                continue;
            };
            if !permitted
                .iter()
                .any(|p| matches_type(&root, &imports, &node, &ty, p))
            {
                continue;
            }
            let Some(function) =
                identity::callable(&node).filter(|n| n.kind().as_ref() == "function_declaration")
            else {
                continue;
            };
            if *path == target_path && function.range() == method.range() {
                continue;
            }
            if function.range().len() > 8192 {
                continue;
            }
            result.push(ReviewNeighborhoodFact {
                role: "exact_caller_context".into(), symbol: identity::name(&function).unwrap_or_default(),
                location: location(path, &function), excerpt: function.text().into_owned(), evidence_id: None,
                provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin exact typed call and unique direct implementation; non-flow context 1".into() },
            });
            if let Some(class) = identity::owner(&function) {
                for binder in class
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "function_declaration")
                    .filter(|n| {
                        identity::owner(n).is_some_and(|owner| owner.range() == class.range())
                    })
                    .filter(|n| {
                        identity::annotation(
                            &root,
                            &imports,
                            n,
                            "org.springframework.web.bind.annotation.InitBinder",
                        )
                    })
                {
                    if binder.range().len() <= 4096 {
                        result.push(ReviewNeighborhoodFact { role: "caller_binding_policy_context".into(), symbol: identity::name(&binder).unwrap_or_default(),
                            location: location(path, &binder), excerpt: binder.text().into_owned(), evidence_id: None,
                            provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin same-controller binding policy declaration; non-flow context 1".into() } });
                    }
                }
                if let Some(body) = identity::named_child(&class, "class_body") {
                    let start = class.range().start;
                    let end = body.range().start;
                    if end - start <= 4096 {
                        let mut loc = location(path, &class);
                        loc.end = location(path, &body).start;
                        result.push(ReviewNeighborhoodFact {
                            role: "caller_owner_context".into(),
                            symbol: ty.clone(),
                            location: loc,
                            excerpt: source[start..end].to_string(),
                            evidence_id: None,
                            provenance: QueryProvenance {
                                resolution: Resolution::Ast,
                                engine:
                                    "Kotlin caller owner declaration and constructor receiver 1"
                                        .into(),
                            },
                        });
                    }
                }
            }
            for argument in &call.arguments {
                let text = argument.value.text();
                let Some((producer, _)) = text.split_once('.') else {
                    continue;
                };
                let Some(binding) = identity::binding(&root, &node, producer) else {
                    continue;
                };
                if binding.kind().as_ref() != "parameter" {
                    continue;
                }
                let Some(model_type) = identity::binding_type(&root, &node, producer) else {
                    continue;
                };
                for (model_path, model_source) in files {
                    let model_ast = SupportLang::Kotlin.ast_grep(model_source);
                    let model_root = model_ast.root();
                    for model in model_root
                        .dfs()
                        .filter(|n| n.kind().as_ref() == "class_declaration")
                    {
                        let Some(model_name) = identity::name(&model) else {
                            continue;
                        };
                        if !matches_type(
                            &root,
                            &imports,
                            &node,
                            &model_type,
                            &canonical(&package(&model_root), &model_name),
                        ) {
                            continue;
                        }
                        let mapped = [
                            "RequestMapping",
                            "GetMapping",
                            "PostMapping",
                            "PutMapping",
                            "PatchMapping",
                            "DeleteMapping",
                        ]
                        .iter()
                        .any(|name| {
                            identity::annotation(
                                &root,
                                &imports,
                                &function,
                                &format!("org.springframework.web.bind.annotation.{name}"),
                            )
                        });
                        let controller = identity::owner(&function).is_some_and(|owner| {
                            [
                                "org.springframework.stereotype.Controller",
                                "org.springframework.web.bind.annotation.RestController",
                            ]
                            .iter()
                            .any(|name| identity::annotation(&root, &imports, &owner, name))
                        });
                        let annotated_parameter = binding
                            .prev()
                            .is_some_and(|n| n.kind().as_ref() == "parameter_modifiers");
                        if mapped && controller && !annotated_parameter {
                            result.push(ReviewNeighborhoodFact {
                                role: "spring_model_argument_binding_context".into(), symbol: producer.into(),
                                location: location(path, &binding),
                                excerpt: format!("The canonical Spring MVC mapped controller method {} declares the unannotated complex argument {producer}: {model_type}, whose exact model declaration is supplied. Spring MVC normally treats this argument as an implicit @ModelAttribute and binds request parameters to its writable properties. The exact caller passes {text} to the reviewed repository method. Apply the supplied controller binder policy and model/base property declarations to that property; this is framework source semantics, not runtime dispatch verification or a native cross-file taint path.", identity::name(&function).unwrap_or_default()),
                                evidence_id: None,
                                provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin canonical Spring MVC complex argument and exact property call context 1".into() },
                            });
                        }
                        if model.range().len() <= 8192 {
                            result.push(ReviewNeighborhoodFact { role: "request_model_type_context".into(), symbol: model_name.clone(), location: location(model_path, &model), excerpt: model.text().into_owned(), evidence_id: None,
                                provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin exact controller argument model declaration; non-flow context 1".into() } });
                        }
                        let model_imports = Imports::build(&model_root);
                        for parent in model
                            .children()
                            .filter(|n| n.kind().as_ref() == "delegation_specifier")
                            .flat_map(|n| {
                                n.dfs()
                                    .filter(|n| n.kind().as_ref() == "user_type")
                                    .collect::<Vec<_>>()
                            })
                        {
                            for (base_path, base_source) in files {
                                let base_ast = SupportLang::Kotlin.ast_grep(base_source);
                                let base_root = base_ast.root();
                                for base in base_root
                                    .dfs()
                                    .filter(|n| n.kind().as_ref() == "class_declaration")
                                {
                                    let Some(base_name) = identity::name(&base) else {
                                        continue;
                                    };
                                    if matches_type(
                                        &model_root,
                                        &model_imports,
                                        &parent,
                                        &parent.text(),
                                        &canonical(&package(&base_root), &base_name),
                                    ) && base.range().len() <= 4096
                                    {
                                        result.push(ReviewNeighborhoodFact { role: "request_model_base_context".into(), symbol: base_name, location: location(base_path, &base), excerpt: base.text().into_owned(), evidence_id: None,
                                            provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin exact model direct superclass declaration; non-flow context 1".into() } });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            caller_count += 1;
            if caller_count >= limit {
                return result;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_model_binding_context_requires_canonical_mapping_and_owned_model() {
        let target = "package app\nclass Storage { fun lookup(name: String) { consume(name) } }";
        let model = "package app\nclass Owner { var lastName: String = \"\" }";
        for (annotation, expected) in [
            ("@org.springframework.stereotype.Controller", true),
            ("@Controller", false),
        ] {
            let controller = format!(
                "package app\n{annotation}\nclass Routes(val repo: Storage) {{ @org.springframework.web.bind.annotation.GetMapping fun search(owner: Owner) {{ repo.lookup(owner.lastName) }} }}"
            );
            let facts = caller_facts(
                &[
                    ("storage.kt", target),
                    ("routes.kt", &controller),
                    ("model.kt", model),
                ],
                "storage.kt",
                target.find("consume").unwrap(),
                4,
            );
            assert_eq!(
                facts
                    .iter()
                    .any(|f| f.role == "spring_model_argument_binding_context"),
                expected
            );
        }
    }

    #[test]
    fn callers_require_owned_types_and_unique_direct_implementation() {
        let target = "package app\ninterface Repository { fun lookup(name: String) }\nclass Storage: Repository { override fun lookup(name: String) { consume(name) } }";
        let controller = "package app\nclass Routes(val repo: Repository) { fun search(name: String) { repo.lookup(name) } }";
        let unrelated = "package other\nclass Routes(val repo: Repository) { fun search(name: String) { repo.lookup(name) } }";
        let anchor = target.find("consume").unwrap();
        let files = [
            ("storage.kt", target),
            ("routes.kt", controller),
            ("unrelated.kt", unrelated),
        ];
        let facts = caller_facts(&files, "storage.kt", anchor, 4);
        assert_eq!(
            facts
                .iter()
                .filter(|f| f.role == "exact_caller_context")
                .count(),
            1
        );
        assert_eq!(facts[0].location.path, "routes.kt");
        let extra = "package app\nclass Other: Repository { fun lookup(name: String) {} }";
        let files = [
            ("storage.kt", target),
            ("routes.kt", controller),
            ("extra.kt", extra),
        ];
        assert!(caller_facts(&files, "storage.kt", anchor, 4).is_empty());
    }
}
