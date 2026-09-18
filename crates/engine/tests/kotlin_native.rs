use mehscan_core::{Capability, Language};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-native")
}

#[test]
fn ktor_client_factories_keep_builder_leads_without_claiming_initial_url_survives() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-ktor-builders");
    let scan = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-ktor-client-request")
            .count(),
        4
    );
    let source_owners = scan
        .security_paths
        .iter()
        .map(|p| {
            scan.evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(source_owners, ["rawFactory"]);
}

#[test]
fn jvm_client_factories_and_process_mutator_chains_keep_owned_boundaries() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-client-factories");
    let scan = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-http-client-request")
            .count(),
        3
    );
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-okhttp-request")
            .count(),
        3
    );
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-process-builder")
            .count(),
        3
    );
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    let chained = scan
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "kotlin-process-builder"
                && e.enclosing_symbol.as_deref() == Some("chainedCommand")
        })
        .unwrap();
    assert_eq!(chained.captures["command"].text, "executable");
    let fixed = scan
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "kotlin-process-builder"
                && e.enclosing_symbol.as_deref() == Some("fixedCommand")
        })
        .unwrap();
    assert_eq!(fixed.captures["command"].text, "\"whoami\"");
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    for owner in ["rawOkhttp", "rawOkhttpBuilder", "lazyOkhttp"] {
        let review = jobs
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence.iter().any(|e| {
                    e.rule_id == "kotlin-okhttp-request"
                        && e.enclosing_symbol.as_deref() == Some(owner)
                        && r.anchor_evidence_ids.contains(&e.id)
                })
            })
            .unwrap();
        let consumers = review
            .facts
            .iter()
            .filter(|f| f.role == "okhttp_call_execution_context")
            .collect::<Vec<_>>();
        assert_eq!(consumers.len(), usize::from(owner != "lazyOkhttp"));
        assert!(consumers.iter().all(|f| f.excerpt.ends_with(".execute()")));
    }
}

#[test]
fn hostname_verifier_trailing_lambdas_remain_owned_configuration_anchors() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-tls-policies");
    let scan = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let setters = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-tls-hostname-verifier")
        .collect::<Vec<_>>();
    assert_eq!(setters.len(), 4);
    assert_eq!(
        setters
            .iter()
            .filter(|e| e.captures.get("callback").is_some_and(|c| c.text == "true"))
            .count(),
        2
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    for review in jobs.observation_reviews.iter().filter(|r| {
        r.evidence.iter().any(|e| {
            e.rule_id == "kotlin-tls-hostname-verifier" && r.anchor_evidence_ids.contains(&e.id)
        })
    }) {
        let exact = review
            .facts
            .iter()
            .filter(|f| f.role == "matched_tls_operation")
            .collect::<Vec<_>>();
        assert_eq!(exact.len(), 1);
        assert!(
            exact[0]
                .evidence_id
                .as_ref()
                .is_some_and(|id| review.anchor_evidence_ids.contains(id))
        );
    }
    for review in jobs.observation_reviews.iter().filter(|r| {
        r.evidence.iter().any(|e| {
            e.rule_id == "kotlin-url-connection-consumer" && r.anchor_evidence_ids.contains(&e.id)
        })
    }) {
        assert!(
            review
                .review_basis
                .as_ref()
                .unwrap()
                .observations
                .iter()
                .all(|b| b.rule_id == "kotlin-url-connection-consumer")
        );
        assert!(review.decision_facts.established.iter().any(|f| f.contains(
            "hostname-verification failure does not establish caller-controlled URL selection"
        )));
    }
}

#[test]
fn object_filter_review_context_does_not_replace_the_read_stream_anchor() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-object-policies");
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    assert_eq!(jobs.observation_reviews.len(), 3);
    let wrong = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.enclosing_symbol.as_deref() == Some("wrongStream")
                    && r.anchor_evidence_ids.contains(&e.id)
            })
        })
        .unwrap();
    let exact = wrong
        .facts
        .iter()
        .filter(|f| f.role == "matched_object_operation")
        .collect::<Vec<_>>();
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].excerpt, "exposed.readObject()");
    assert!(
        wrong
            .facts
            .iter()
            .any(|f| f.excerpt.contains("guarded.setObjectInputFilter")
                && f.excerpt.contains("exposed.readObject()"))
    );
}

#[test]
fn xml_policy_reviews_keep_distinct_factory_settings_in_source_context() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-xml-policies");
    let scan = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-xml-parse")
            .count(),
        3
    );
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-xml-configuration")
            .count(),
        4
    );
    // Policy association is source review context, not native XML propagation.
    assert!(scan.security_paths.is_empty());
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    let wrong = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.rule_id == "kotlin-xml-parse"
                    && e.enclosing_symbol.as_deref() == Some("wrongFactory")
                    && r.anchor_evidence_ids.contains(&e.id)
            })
        })
        .unwrap();
    assert!(
        wrong
            .facts
            .iter()
            .any(|f| f.excerpt.contains("guarded.setFeature")
                && f.excerpt.contains("exposed.setFeature")
                && f.excerpt.contains("exposed.newDocumentBuilder().parse"))
    );
    let guarded = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.rule_id == "kotlin-xml-configuration"
                    && e.location.start.line == 29
                    && r.anchor_evidence_ids.contains(&e.id)
            })
        })
        .unwrap();
    assert!(
        guarded
            .facts
            .iter()
            .any(|f| f.role == "matched_xml_operation"
                && f.excerpt.starts_with("guarded.setFeature(")
                && f.excerpt.ends_with("true)"))
    );
    assert!(
        guarded
            .decision_facts
            .established
            .iter()
            .any(|f| f.contains("captured value true")
                && f.contains("Judge this setter and its receiver"))
    );
    let parse_anchors = wrong
        .facts
        .iter()
        .filter(|f| f.role == "matched_xml_operation")
        .collect::<Vec<_>>();
    assert_eq!(parse_anchors.len(), 1);
    assert!(
        parse_anchors[0]
            .excerpt
            .starts_with("exposed.newDocumentBuilder().parse(")
    );
    assert!(
        !wrong
            .decision_facts
            .established
            .iter()
            .any(|f| f.contains("Judge this setter and its receiver"))
    );
}

#[test]
fn jvm_breadth_keeps_paths_separate_from_content_and_lookalikes() {
    let scan = mehscan_engine::scan_path(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-jvm-breadth"),
    )
    .unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let boundaries = scan
        .evidence
        .iter()
        .filter(|e| {
            e.kind == mehscan_core::EvidenceKind::Sink
                || e.kind == mehscan_core::EvidenceKind::SecurityConfiguration
        })
        .collect::<Vec<_>>();
    assert_eq!(boundaries.len(), 14);
    assert!(
        !boundaries
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalikes"))
    );
    let owners = scan
        .security_paths
        .iter()
        .map(|p| {
            scan.evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        std::collections::BTreeSet::from(["rawProcess", "rawRead"])
    );
}

#[test]
fn typed_ktor_inputs_track_effective_sinks_and_exclude_plain_text() {
    let scan = mehscan_engine::scan_path(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-ktor"),
    )
    .unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sources = scan
        .evidence
        .iter()
        .filter(|e| {
            e.rule_id.starts_with("kotlin-ktor-") && e.kind == mehscan_core::EvidenceKind::Source
        })
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 9);
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "kotlin-ktor-html-output"
                && e.enclosing_symbol.as_deref() == Some("plainText"))
    );
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.rule_id.starts_with("kotlin-ktor-")
                && e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    let owners = scan
        .security_paths
        .iter()
        .map(|p| {
            scan.evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        std::collections::BTreeSet::from([
            "dslCommands",
            "queryCommand",
            "pathCommand",
            "bodyCommand",
            "rawRedirect",
            "rawHtml",
            "rawClient"
        ])
    );
}

#[test]
fn ktor_html_decisions_keep_success_and_fixed_error_responses_separate() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-ktor");
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    let responses = jobs
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|e| {
                e.enclosing_symbol.as_deref() == Some("rawBytes")
                    && e.rule_id == "kotlin-ktor-html-output"
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2);
    for review in responses {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let content = &anchor.captures["content"].text;
        assert!(
            review
                .decision_facts
                .established
                .iter()
                .any(|fact| fact.contains("matched HTML response") && fact.contains(content))
        );
        assert_eq!(
            review
                .decision_facts
                .established
                .iter()
                .any(|fact| fact.contains("known fixed string")),
            content == "\"Invalid Base64\""
        );
    }
}

#[test]
fn kotlin_jvm_boundaries_and_scripts_preserve_captures() {
    let result = mehscan_engine::scan_path(root()).unwrap();
    assert_eq!(result.coverage.languages[&Language::Kotlin].scanned, 5);
    let native = result
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("kotlin-"))
        .collect::<Vec<_>>();
    assert_eq!(native.len(), 9);
    let rules = mehscan_engine::rules::load_builtin_rules().unwrap();
    let declared = rules
        .iter()
        .filter(|r| r.language == Language::Kotlin)
        .map(|r| r.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut exercised = native
        .iter()
        .map(|e| e.rule_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for fixture in [
        "kotlin-quality",
        "kotlin-jdbc",
        "kotlin-network",
        "kotlin-jvm-breadth",
        "kotlin-ktor",
        "kotlin-exposed",
        "kotlin-webflux",
        "kotlin-webclient",
        "kotlin-tls-trust",
        "kotlin-tls-defaults",
        "kotlin-tls-factory-defaults",
        "kotlin-jwt",
        "kotlin-jwt-lifetime",
        "kotlin-cookies",
        "kotlin-authorization",
        "kotlin-uploads",
        "kotlin-html-encoding",
        "kotlin-extended-database",
    ] {
        let scan = mehscan_engine::scan_path(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures")
                .join(fixture),
        )
        .unwrap();
        exercised.extend(
            scan.evidence
                .into_iter()
                .map(|e| e.rule_id)
                .filter(|id| declared.contains(id)),
        );
    }
    assert_eq!(
        declared, exercised,
        "Every Kotlin rule needs an executable fixture"
    );
    for cwe in ["CWE-78", "CWE-22", "CWE-327", "CWE-918", "CWE-89"] {
        assert!(
            result
                .coverage
                .cwe
                .iter()
                .find(|item| item.cwe == cwe)
                .unwrap()
                .supported_languages
                .contains(&Language::Kotlin)
        );
    }
    let command = native
        .iter()
        .find(|e| e.rule_id == "kotlin-runtime-exec")
        .unwrap();
    assert_eq!(command.captures["command"].text, "command");
    assert_eq!(command.enclosing_symbol.as_deref(), Some("boundaries"));
    assert!(
        native
            .iter()
            .any(|e| e.capability == Capability::CryptographicHash
                && e.location.path.ends_with("script.kts"))
    );
    assert!(
        native
            .iter()
            .all(|e| !e.location.path.ends_with("inert.kt")
                && !e.location.path.ends_with("shadow.kt"))
    );
    assert!(result.security_paths.is_empty());
}

#[test]
fn url_boundaries_preserve_endpoint_flow_and_lazy_construction() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-network");
    let result = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let sinks = result
        .evidence
        .iter()
        .filter(|e| {
            matches!(
                e.rule_id.as_str(),
                "kotlin-url-read" | "kotlin-url-connection"
            )
        })
        .map(|e| e.enclosing_symbol.as_deref().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        sinks,
        [
            "rawStream",
            "constructorStream",
            "rawConnection",
            "fixedStream",
            "allowlistedStream",
            "connectionOnly",
            "fetch"
        ]
        .into_iter()
        .collect()
    );
    let path_owners = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        path_owners,
        [
            "rawStream",
            "constructorStream",
            "rawConnection",
            "connectionOnly"
        ]
        .into_iter()
        .collect()
    );
    // Construction-only remains a review lead, never a native finding or proof
    // of a request. Coroutine handoff is observation context, not a native path.
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    assert_eq!(jobs.total_reviews, 7);
    let fetch = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some("fetch"))
        })
        .unwrap();
    assert!(
        fetch
            .facts
            .iter()
            .any(|f| f.role == "exact_caller_context" && f.symbol == "coroutineRaw")
    );
}

#[test]
fn kotlin_outline_and_test_policy_are_available() {
    let outline = mehscan_engine::investigation::get_file_outline(&root(), "app.kt").unwrap();
    assert_eq!(outline.results.language, Language::Kotlin);
    assert!(
        outline
            .results
            .symbols
            .iter()
            .any(|s| s.name == "boundaries")
    );
    let result = mehscan_engine::scan_path_with_options(
        root(),
        mehscan_engine::ScanOptions {
            include_tests: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.coverage.languages[&Language::Kotlin].scanned, 7);
}

#[test]
fn kotlin_quality_app_admits_unsafe_and_safe_operations_without_verdicts() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-quality");
    let result = mehscan_engine::scan_path(fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let observations = result
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("kotlin-") && e.kind == mehscan_core::EvidenceKind::Sink)
        .collect::<Vec<_>>();
    let owners = observations
        .iter()
        .filter_map(|e| e.enclosing_symbol.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        [
            "rawQuery",
            "boundQuery",
            "boundJdbcQuery",
            "numericQuery",
            "rawJdbcQuery",
            "rawCommand",
            "fixedCommand",
            "rawFileRead",
            "rawFileWrite",
            "safeFileRead"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(observations.len(), 10);
    assert_eq!(result.security_paths.len(), 5);
    let linked = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        linked,
        [
            "rawCommand",
            "rawQuery",
            "rawJdbcQuery",
            "rawFileRead",
            "rawFileWrite"
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn kotlin_review_constraints_and_sources_stay_with_their_owner() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-quality");
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    let encoded = serde_json::to_value(job).unwrap();
    let reviews = encoded["observation_reviews"].as_array().unwrap();
    let numeric = reviews
        .iter()
        .find(|review| review.to_string().contains("numeric_query_operand_context"))
        .unwrap();
    let text = numeric.to_string();
    assert!(text.contains("numericQuery"));
    assert!(!text.contains("fun rawCommand"));
    assert!(!text.contains("fun rawQuery"));
    assert!(!text.contains("kotlin-spring-mvc-parameter-source"));
    assert!(
        reviews
            .iter()
            .filter(|review| review.to_string().contains("numeric_query_operand_context"))
            .count()
            == 1
    );
}

#[test]
fn jdbc_paths_track_sql_text_and_leave_separately_bound_values_as_data() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-jdbc");
    let result = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let sinks = result
        .evidence
        .iter()
        .filter(|e| e.kind == mehscan_core::EvidenceKind::Sink)
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 4);
    assert_eq!(result.security_paths.len(), 2);
    let owners = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        ["rawStatement", "rawPrepared"].into_iter().collect()
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    assert_eq!(jobs.total_reviews, 4);
    assert!(
        serde_json::to_string(&jobs)
            .unwrap()
            .contains("constant_query_operand_context")
    );
}

#[test]
fn filesystem_paths_follow_owned_path_values_and_distinguish_content() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-files");
    let result = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let sinks = result
        .evidence
        .iter()
        .filter(|e| {
            matches!(
                e.capability,
                Capability::FilesystemRead | Capability::FilesystemWrite
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 6);
    let owners = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        ["rawRead", "rawWrite", "normalizedRead"]
            .into_iter()
            .collect()
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    assert_eq!(jobs.total_reviews, 6);
}

#[test]
fn runtime_import_controls_preserve_real_calls_and_exclude_custom_wildcard_calls() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-imports");
    let result = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let sinks = result
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-runtime-exec")
        .map(|e| e.enclosing_symbol.as_deref().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        sinks,
        ["qualifiedCall", "aliasedCall", "explicitCall"]
            .into_iter()
            .collect()
    );
    assert_eq!(result.security_paths.len(), 3);
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    let qualified = jobs
        .reviews
        .iter()
        .find(|r| r.candidate.sink.enclosing_symbol.as_deref() == Some("qualifiedCall"))
        .unwrap();
    for fact in qualified
        .facts
        .iter()
        .filter(|f| matches!(f.role.as_str(), "source_context" | "sink_context"))
    {
        assert!(fact.excerpt.contains("qualifiedCall"));
        assert!(!fact.excerpt.contains("customCall"));
    }
}

#[test]
fn jdbc_factory_receivers_admit_sql_and_exclude_lookalikes() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-jdbc-factories");
    let result = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let owners = result
        .evidence
        .iter()
        .filter(|e| {
            matches!(
                e.rule_id.as_str(),
                "kotlin-jdbc-statement-query" | "kotlin-jdbc-prepare-query"
            )
        })
        .map(|e| e.enclosing_symbol.as_deref().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        owners,
        [
            "factoryRaw",
            "factoryFixed",
            "factoryPreparedRaw",
            "factoryPreparedBound"
        ]
        .into_iter()
        .collect()
    );
    let path_owners = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        path_owners,
        ["factoryRaw", "factoryPreparedRaw"].into_iter().collect()
    );
}

#[test]
fn prepared_use_facts_keep_binding_and_execution_with_their_origin() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-jdbc-factories");
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    let raw = jobs
        .reviews
        .iter()
        .find(|r| r.candidate.sink.enclosing_symbol.as_deref() == Some("factoryPreparedRaw"))
        .unwrap();
    assert_eq!(
        raw.facts
            .iter()
            .filter(|f| f.role == "prepared_statement_execution_context")
            .count(),
        1
    );
    assert!(
        !raw.facts
            .iter()
            .any(|f| f.role == "prepared_statement_binding_context")
    );
    let bound = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some("factoryPreparedBound"))
        })
        .unwrap();
    assert_eq!(
        bound
            .facts
            .iter()
            .filter(|f| f.role == "prepared_statement_execution_context")
            .count(),
        1
    );
    assert_eq!(
        bound
            .facts
            .iter()
            .filter(|f| f.role == "prepared_statement_binding_context")
            .count(),
        1
    );
}

#[test]
fn prepared_ownership_excludes_unrelated_bindings_and_preserves_resets() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-prepared-ownership");
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    assert_eq!(jobs.total_reviews, 4);
    let raw = jobs
        .reviews
        .iter()
        .find(|r| r.candidate.sink.enclosing_symbol.as_deref() == Some("ownedRaw"))
        .unwrap();
    assert!(
        !raw.facts
            .iter()
            .any(|f| f.role == "prepared_statement_binding_context")
    );
    assert!(
        raw.facts
            .iter()
            .any(|f| f.role == "prepared_statement_execution_context" && f.symbol == "alias")
    );
    let bound = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some("ownedBound"))
        })
        .unwrap();
    assert_eq!(
        bound
            .facts
            .iter()
            .filter(|f| f.role == "prepared_statement_binding_context")
            .count(),
        2
    );
    assert!(
        bound
            .facts
            .iter()
            .any(|f| f.role == "prepared_statement_lifecycle_context"
                && f.excerpt.contains("clearParameters"))
    );
    let only = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some("preparationOnly"))
        })
        .unwrap();
    assert!(
        !only
            .facts
            .iter()
            .any(|f| f.role == "prepared_statement_execution_context")
    );
    let conditional = jobs
        .reviews
        .iter()
        .find(|r| r.candidate.sink.enclosing_symbol.as_deref() == Some("conditionalRaw"))
        .unwrap();
    assert!(
        conditional
            .facts
            .iter()
            .any(|f| f.role == "prepared_statement_execution_context"
                && f.excerpt.contains("enclosing conditions"))
    );
}

#[test]
fn explicit_member_receivers_preserve_boundary_and_path_ownership() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-receivers");
    let result = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let query_owners = result
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-persistence-query")
        .map(|e| e.enclosing_symbol.as_deref().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(query_owners, ["memberQuery"]);
    let path_owners = result
        .security_paths
        .iter()
        .map(|p| {
            result
                .evidence
                .iter()
                .find(|e| e.id == p.sink_evidence_id)
                .unwrap()
                .enclosing_symbol
                .as_deref()
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        path_owners,
        ["memberQuery", "memberRead"].into_iter().collect()
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    assert_eq!(jobs.observation_reviews.len(), 1);
    let facts = &jobs.observation_reviews[0].facts;
    let member = facts
        .iter()
        .find(|f| f.role == "member_receiver_binding_context")
        .unwrap();
    assert_eq!(member.symbol, "FixedMembers.root");
    assert!(
        member
            .excerpt
            .contains("private val root: OtherPath = OtherPath()")
    );
    let ty = facts
        .iter()
        .find(|f| f.role == "member_receiver_type_context")
        .unwrap();
    assert_eq!(ty.symbol, "OtherPath");
    assert!(
        ty.excerpt
            .contains("Path.of(\"/fixture/public/readme.txt\")")
    );
}

#[test]
fn incompatible_path_and_text_arguments_do_not_become_deterministic_paths() {
    // Deliberately incompatible Java argument types: syntax alone is not a
    // proved invocation. In particular, a Path object is not command/SQL text.
    let root = std::env::temp_dir().join(format!(
        "mehscan-kotlin-types-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("app.kt");
    std::fs::write(
        &source,
        r#"
import java.nio.file.Files
import java.nio.file.Path
import java.net.URI
import java.net.URL
import java.sql.Statement
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
@RestController
class C(private val statement: Statement) {
    @GetMapping("/bad/read")
    fun badRead(@RequestParam name: String) { Files.readString(name) }
    @GetMapping("/bad/query")
    fun badQuery(@RequestParam name: String) { statement.executeQuery(Path.of(name)) }
    @GetMapping("/bad/command")
    fun badCommand(@RequestParam name: String) { Runtime.getRuntime().exec(Path.of(name)) }
    @GetMapping("/bad/url-query")
    fun badUrlQuery(@RequestParam name: String) { statement.executeQuery(URI.create(name).toURL()) }
    @GetMapping("/bad/url-command")
    fun badUrlCommand(@RequestParam name: String) { Runtime.getRuntime().exec(URI.create(name).toURL()) }
    @GetMapping("/bad/url-path")
    fun badUrlPath(@RequestParam name: String) { URL(Path.of(name)).openStream() }
}

"#,
    )
    .unwrap();
    let result = mehscan_engine::scan_path(&root);
    std::fs::remove_file(&source).unwrap();
    std::fs::remove_dir(&root).unwrap();
    let result = result.unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert!(result.security_paths.is_empty());
}

#[test]
fn scope_lambda_context_keeps_member_shadowing_and_flow_limits_explicit() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kotlin-scopes");
    let scan = mehscan_engine::scan_path(&fixture).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert!(scan.security_paths.is_empty());
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture, None, true).unwrap();
    let mut owners = std::collections::BTreeSet::new();
    for review in &jobs.observation_reviews {
        let anchor = scan
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let owner = anchor.enclosing_symbol.as_deref().unwrap();
        let scopes = review
            .facts
            .iter()
            .filter(|f| f.role == "stdlib_scope_call_context")
            .collect::<Vec<_>>();
        if owner == "lookalike" {
            assert!(
                scopes.is_empty(),
                "application member must not become kotlin.let"
            );
        } else {
            assert!(
                !scopes.is_empty(),
                "missing scope source context for {owner}"
            );
            for fact in scopes {
                assert!(fact.excerpt.contains("not compiler-resolved identity"));
                assert!(
                    fact.evidence_id
                        .as_ref()
                        .is_some_and(|id| review.anchor_evidence_ids.contains(id))
                );
            }
            owners.insert(owner.to_owned());
        }
    }
    assert_eq!(
        owners,
        ["rawLet", "rawImplicit", "rawAlias", "fixedLet"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
}
