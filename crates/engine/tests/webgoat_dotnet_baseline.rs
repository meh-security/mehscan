use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

#[test]
#[ignore = "requires the optional local WebGoat.NET corpus"]
fn optional_webgoat_dotnet_baseline_matches_when_requested() {
    let root = std::env::var_os("MEHSCAN_WEBGOAT_DOTNET_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("apps/WebGoat.NET")
        });
    assert!(root.join("WebGoat.NET/WebGoat.NET.csproj").is_file());

    let result = mehscan_engine::scan_path(&root).expect("WebGoat.NET should scan");
    assert_eq!(result.coverage.totals.scanned, 90);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence.len(), 64);
    assert_eq!(result.security_paths.len(), 4);

    let privilege_sink = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "csharp-request-controlled-role-assignment")
        .expect("request-controlled administrative role assignment should be observed");
    assert_eq!(
        privilege_sink.location.path,
        "WebGoat.NET/Controllers/AccountController.cs"
    );
    assert_eq!(privilege_sink.location.start.line, 229);
    assert_eq!(
        privilege_sink.captures["assigned_fields"].text,
        "model.MakeNewUserAdmin"
    );
    assert_eq!(
        privilege_sink.captures["client_authorization_guard"].text,
        "!model.IsIssuerAdmin"
    );
    let privilege_path = result
        .security_paths
        .iter()
        .find(|path| path.sink_evidence_id == privilege_sink.id)
        .expect("request-controlled role assignment should form one bounded path");
    assert_eq!(privilege_path.state, SecurityPathState::Unknown);
    assert!(privilege_path.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::IneffectiveProtection
            && step.symbol.as_deref()
                == Some("request-bound model property cannot establish caller privilege")
    }));

    let path = result
        .security_paths
        .iter()
        .find(|path| {
            path.steps.last().is_some_and(|sink| {
                sink.location.path == "WebGoat.NET/Controllers/AccountController.cs"
                    && sink.location.start.line == 50
            })
        })
        .expect("login return URL path should remain present");
    assert_eq!(path.capability, Capability::Redirect);
    assert_eq!(path.state, SecurityPathState::Unknown);
    assert!(path.protection_evidence_ids.is_empty());
    assert!(path.steps.last().is_some_and(|sink| {
        sink.location.path == "WebGoat.NET/Controllers/AccountController.cs"
            && sink.location.start.line == 50
    }));
    assert!(path.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::IneffectiveProtection
            && step
                .symbol
                .as_deref()
                .is_some_and(|symbol| symbol.contains("does not constrain redirect destination"))
    }));
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.steps.last().is_some_and(|sink| {
                sink.location.path == "WebGoat.NET/Controllers/CheckoutController.cs"
                    && sink.location.start.line == 219
            }))
            .count(),
        2
    );

    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), false)
        .expect("WebGoat.NET review jobs should build");
    assert_eq!(reviews.reviews.len(), 3);
    assert_eq!(reviews.observation_reviews.len(), 9);
    assert_eq!(
        reviews
            .observation_reviews
            .iter()
            .filter(|review| review
                .evidence
                .iter()
                .any(|item| item.rule_id == "csharp-sql-command-text"))
            .count(),
        2
    );
    assert_eq!(
        reviews
            .observation_reviews
            .iter()
            .filter(|review| review
                .evidence
                .iter()
                .any(|item| item.rule_id == "csharp-razor-html-raw-output"))
            .count(),
        2
    );
    let privilege_review = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.sink.rule_id == "csharp-request-controlled-role-assignment")
        .expect("role assignment path should receive a self-contained review");
    for role in [
        "privilege_assignment_operation_context",
        "caller_authorization_context",
        "privilege_assignment_ui_context",
    ] {
        assert!(
            privilege_review.facts.iter().any(|fact| fact.role == role),
            "{role}: {:#?}",
            privilege_review.facts
        );
    }
    assert!(privilege_review.facts.iter().any(|fact| {
        fact.role == "privilege_assignment_ui_context"
            && fact.excerpt.contains("HiddenFor(m => m.IsIssuerAdmin)")
            && fact
                .excerpt
                .contains("CheckBoxFor(m => m.MakeNewUserAdmin)")
    }));
    assert_eq!(privilege_review.open_questions.len(), 1);
    assert!(privilege_review.open_questions[0].contains("hidden form field"));
    assert!(
        !privilege_review
            .facts
            .iter()
            .any(|fact| { fact.role == "reference_use_context" && fact.symbol == "model" })
    );
    let anonymous_reviews = reviews
        .observation_reviews
        .iter()
        .filter(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "csharp-anonymous-state-change-review")
        })
        .collect::<Vec<_>>();
    assert_eq!(anonymous_reviews.len(), 2);
    for review in anonymous_reviews {
        assert!(
            review
                .evidence
                .iter()
                .all(|item| item.kind != EvidenceKind::Sink)
        );
        for role in [
            "anonymous_endpoint_operation_context",
            "controller_authorization_context",
            "public_entrypoint_ui_context",
        ] {
            assert!(
                review.facts.iter().any(|fact| fact.role == role),
                "{role}: {review:#?}"
            );
        }
        assert!(review.facts.iter().any(|fact| {
            fact.role == "anonymous_endpoint_operation_context"
                && (fact.excerpt.contains("PasswordSignInAsync")
                    || (fact.excerpt.contains("CreateAsync")
                        && fact.excerpt.contains("SignInAsync")))
        }));
        assert!(review.open_questions.iter().any(|question| {
            question.contains("intended anonymous authentication or self-registration boundary")
        }));
        assert!(
            !review
                .open_questions
                .iter()
                .any(|question| question.contains("effective runtime or deployed control"))
        );
        assert!(review.decision_facts.unresolved.is_empty());
        assert_eq!(review.decision_facts.effective_controls.len(), 1);
    }
    let identity_review = reviews
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "csharp-identity-weak-password-policy")
        })
        .expect("explicit weak Identity settings should remain reviewable");
    assert!(identity_review.facts.iter().all(|fact| {
        fact.role != "helper_definition_context"
            || !["model", "options", "order"].contains(&fact.symbol.as_str())
    }));
    assert!(identity_review.open_questions.iter().any(|question| {
        question.contains("exact later application-owned validation")
            && question.contains("Do not count a commented stronger regular expression")
    }));
    assert!(identity_review.decision_facts.unresolved.is_empty());
    assert!(
        identity_review
            .decision_facts
            .established
            .iter()
            .any(|fact| fact.contains("two-character minimum password"))
    );
    assert!(
        !identity_review
            .open_questions
            .iter()
            .any(|question| question.contains("effective runtime or deployed control"))
    );
    let sql_review = reviews
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "csharp-sql-command-text")
        })
        .expect("factory command text should retain a review job");
    assert!(sql_review.facts.iter().any(|fact| {
        fact.role == "exact_caller_context"
            && fact.symbol == "CreateOrder"
            && fact.excerpt.contains("Checkout(CheckoutViewModel model)")
            && fact.excerpt.contains("ShipAddress = model.Address")
            && fact.excerpt.contains("_orderRepository.CreateOrder(order)")
    }));
    assert!(sql_review.open_questions.iter().any(|question| {
        question.contains("request-bound model data") && question.contains("parameterization")
    }));
    assert!(sql_review.decision_facts.unresolved.is_empty());
    assert!(
        sql_review
            .decision_facts
            .established
            .iter()
            .any(|fact| fact.contains("request-model fields")
                && fact.contains("interpolated into executed SQL"))
    );
    let raw_reviews = reviews
        .observation_reviews
        .iter()
        .filter(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "csharp-razor-html-raw-output")
        })
        .collect::<Vec<_>>();
    assert_eq!(raw_reviews.len(), 2);
    for review in raw_reviews {
        for role in [
            "bound_remote_input",
            "persistence_call_observed",
            "raw_output_sink",
            "view_action_context",
            "retrieval_helper_context",
        ] {
            assert!(review.facts.iter().any(|fact| fact.role == role), "{role}");
        }
        assert!(review.facts.iter().any(|fact| {
            fact.role == "retrieval_helper_context"
                && fact.symbol == "GetTopBlogEntries"
                && fact.excerpt.contains("_context.BlogEntries")
        }));
        assert!(
            review.facts.iter().any(|fact| {
                fact.role == "retrieval_model_context"
                    && fact.symbol == "BlogEntry"
                    && fact
                        .excerpt
                        .contains("virtual IList<BlogResponse> Responses")
            }),
            "{:#?}",
            review.facts
        );
        assert!(review.facts.iter().any(|fact| {
            fact.role == "retrieval_configuration_context"
                && fact.excerpt.contains("UseLazyLoadingProxies")
        }));
        assert!(review.open_questions.iter().any(|question| {
            question.contains("write, persistence, retrieval/view, and raw-output")
        }));
        assert!(
            !review
                .open_questions
                .iter()
                .any(|question| question.contains("exact origin"))
        );
        assert!(review.decision_facts.unresolved.is_empty());
        assert!(
            review
                .decision_facts
                .established
                .iter()
                .any(|fact| fact.contains("emitted through Html.Raw"))
        );
    }
    let tracker = reviews
        .reviews
        .iter()
        .find(|review| {
            review.candidate.sink.location.path == "WebGoat.NET/Controllers/CheckoutController.cs"
                && review.candidate.sink.location.start.line == 219
        })
        .expect("external tracker path should remain reviewable");
    assert_eq!(
        tracker
            .review_basis
            .as_ref()
            .and_then(|basis| basis.source.captures.get("parameter"))
            .map(String::as_str),
        Some("carrier")
    );
    assert!(!reviews.reviews.iter().any(|review| {
        review.candidate.sink.location.path == "WebGoat.NET/Controllers/CheckoutController.cs"
            && review.candidate.sink.location.start.line == 219
            && review
                .review_basis
                .as_ref()
                .and_then(|basis| basis.source.captures.get("parameter"))
                .is_some_and(|parameter| parameter == "trackingNumber")
    }));
    assert!(
        tracker.facts.iter().any(|fact| {
            fact.role == "helper_definition_context"
                && fact.symbol == "GetPackageTrackingUrl"
                && fact.excerpt.contains("default:")
                && fact.excerpt.contains("http://{0}?TrackingNumber={1}")
        }),
        "{:#?}",
        tracker.facts
    );
    assert!(tracker.decision_facts.established.iter().any(|fact| {
        fact.contains("authority of an absolute redirect URL")
            && fact.contains("fixed-host sibling branches")
    }));

    assert!(!reviews.observation_reviews.iter().any(|review| {
        review
            .evidence
            .iter()
            .any(|item| item.rule_id == "csharp-cookie-httponly-flag")
    }));

    let sql_sinks = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-sql-command-text")
        .collect::<Vec<_>>();
    assert_eq!(sql_sinks.len(), 2);
    assert!(sql_sinks.iter().all(|item| {
        item.location.path == "WebGoat.NET/Data/OrderRepository.cs"
            && item
                .tags
                .iter()
                .any(|tag| tag == "factory-created-receiver")
    }));
    for rule in [
        "csharp-identity-weak-password-policy",
        "csharp-identity-weak-lockout-policy",
    ] {
        assert!(result.evidence.iter().any(|item| {
            item.rule_id == rule
                && item.location.path == "WebGoat.NET/Startup.cs"
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "recommendation:fix-application")
        }));
    }

    let razor_files = result
        .coverage
        .files
        .iter()
        .filter(|file| file.path.ends_with(".cshtml"))
        .collect::<Vec<_>>();
    assert_eq!(razor_files.len(), 34);
    assert!(
        razor_files
            .iter()
            .all(|file| file.status == mehscan_core::FileStatus::Scanned)
    );
    let raw_outputs = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-razor-html-raw-output")
        .collect::<Vec<_>>();
    assert_eq!(raw_outputs.len(), 2);
    assert!(raw_outputs.iter().all(|item| {
        item.location.path.starts_with("WebGoat.NET/Views/Blog/")
            && item
                .tags
                .iter()
                .any(|tag| tag == "recommendation:review-data-provenance")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "csharp-session-cookie-policy-risk"
            && item.location.path == "WebGoat.NET/Startup.cs"
            && item.tags.iter().any(|tag| tag == "http-only:false")
            && item.tags.iter().any(|tag| tag == "secure-policy:unknown")
            && item.tags.iter().any(|tag| tag == "same-site:unknown")
    }));
}
