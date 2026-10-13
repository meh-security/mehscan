use mehscan_core::{
    IdentityContinuity, PathReviewBundle, PathReviewBundlePayload, PathReviewBundleResponseSet,
    PathReviewTriageResult, ReviewArtifactCitation, ReviewConfidence, ReviewDecision,
    ReviewInvestigationTrace,
};
use mehscan_engine::investigation::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mehscan-native-identity-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}
fn inventory(path: &Path, source: &str, key: Option<&str>) -> ReviewInventory {
    fs::write(path.join("app.js"), source).unwrap();
    let mut inventory = build_review_inventory(path, false).unwrap();
    bind_inventory_repository(&mut inventory, key.map(str::to_owned), None).unwrap();
    assert!(!inventory.entries.is_empty());
    inventory
}
const SOURCE: &str = "function handle(request) {\n  eval(request.query.code);\n}\n";

fn answers(
    bundle: &PathReviewBundle,
    choose: impl Fn(&str) -> ReviewDecision,
) -> PathReviewBundleResponseSet {
    PathReviewBundleResponseSet {
        schema_version: "1.3".into(),
        bundle_fingerprint: bundle.bundle_fingerprint.clone(),
        results: bundle
            .review_ids
            .iter()
            .map(|id| {
                let anchor = bundle_selected_anchor_id(bundle, id).unwrap().to_string();
                let decision = choose(id);
                PathReviewTriageResult {
                    review_id: id.clone(),
                    selected_anchor_id: Some(anchor.clone()),
                    decision,
                    confidence: ReviewConfidence::Medium,
                    summary: "Synthetic decision for reporting transport verification.".into(),
                    checks: if decision == ReviewDecision::NeedsReview {
                        vec!["Confirm input authority.".into()]
                    } else {
                        Vec::new()
                    },
                    investigation: Some(ReviewInvestigationTrace {
                        decisive_artifacts: Vec::new(),
                        journal_summary: None,
                        citations: vec![ReviewArtifactCitation {
                            artifact_id: anchor,
                            claim: "Selected operation.".into(),
                        }],
                        reviewer_inferences: Vec::new(),
                        reviewer_origin_leads: Vec::new(),
                        blockers: Vec::new(),
                    }),
                }
            })
            .collect(),
    }
}

fn bundles_for(path: &Path, inventory: &ReviewInventory) -> Vec<PathReviewBundle> {
    let ids = inventory
        .entries
        .iter()
        .map(|entry| entry.review_id.clone())
        .collect();
    let job = build_selected_review_jobs(path, inventory, &ids, None).unwrap();
    build_path_review_bundles(&job, None).unwrap().bundles
}

#[test]
fn sarif_preserves_each_native_path_without_promoting_pending_proof() {
    let path = root("multiple-paths");
    fs::write(
        path.join("handler.ts"),
        include_str!("../../../tests/fixtures/review-issue-grouping/handler.ts"),
    )
    .unwrap();
    let mut inventory = build_review_inventory(&path, false).unwrap();
    bind_inventory_repository(&mut inventory, Some("repo:123".into()), None).unwrap();
    let bundles = bundles_for(&path, &inventory);
    let mut paths =
        BTreeMap::<String, BTreeMap<String, Vec<mehscan_core::SecurityPathStep>>>::new();
    for bundle in &bundles {
        if let PathReviewBundlePayload::SecurityPath { reviews } = &bundle.payload {
            for review in reviews {
                let identity = &bundle.identity_catalog.as_ref().unwrap().subjects[&review.id];
                paths
                    .entry(identity.occurrence_key.clone())
                    .or_default()
                    .insert(review.id.clone(), review.candidate.steps.clone());
            }
        }
    }
    let (occurrence, expected) = paths
        .iter()
        .find(|(_, paths)| paths.len() >= 2)
        .expect("two native sources reach the same operation");
    let pairs = bundles
        .iter()
        .map(|bundle| (bundle.clone(), answers(bundle, |_| ReviewDecision::Issue)))
        .collect::<Vec<_>>();
    let report = build_finding_report(".", "test", None, &pairs, false).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|finding| &finding.id == occurrence)
        .unwrap();
    let actual = finding
        .flow
        .iter()
        .chain(&finding.additional_flows)
        .map(|flow| serde_json::to_string(&flow.steps).unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        expected
            .values()
            .map(|steps| serde_json::to_string(steps).unwrap())
            .collect()
    );
    let sarif = mehscan_core::FindingSarifLog::from_finding_report(&report);
    let result = sarif.runs[0]
        .results
        .iter()
        .find(|result| result.partial_fingerprints.get("mehscanFinding/v2") == Some(occurrence))
        .unwrap();
    assert_eq!(result.code_flows.len(), actual.len());
    assert!(report.to_markdown().matches("Flow: ").count() >= actual.len());
    let mut reversed = pairs.clone();
    reversed.reverse();
    for (_, answers) in &mut reversed {
        answers.results.reverse();
    }
    let reversed_report = build_finding_report(".", "test", None, &reversed, false).unwrap();
    let reversed_sarif = mehscan_core::FindingSarifLog::from_finding_report(&reversed_report);
    let reversed_result = reversed_sarif.runs[0]
        .results
        .iter()
        .find(|result| result.partial_fingerprints.get("mehscanFinding/v2") == Some(occurrence))
        .unwrap();
    assert_eq!(result.code_flows, reversed_result.code_flows);
    for flow in &result.code_flows {
        assert_eq!(flow.thread_flows.len(), 1);
        let steps = &flow.thread_flows[0].locations;
        let native = expected
            .values()
            .find(|native| {
                native.first().unwrap().evidence_id == steps.first().unwrap().properties.evidence_id
            })
            .unwrap();
        assert_eq!(steps.len(), native.len());
        for (index, (rendered, native)) in steps.iter().zip(native).enumerate() {
            assert_eq!(rendered.execution_order, index);
            assert_eq!(rendered.properties.step_kind, native.kind);
            assert_eq!(rendered.properties.evidence_id, native.evidence_id);
            assert_eq!(rendered.properties.symbol, native.symbol);
            assert_eq!(
                rendered.location.physical_location.artifact_location.uri,
                native.location.path
            );
            assert_eq!(
                rendered.location.physical_location.region.start_line,
                native.location.start.line
            );
        }
        assert_eq!(
            steps.first().unwrap().properties.step_kind,
            mehscan_core::SecurityPathStepKind::Source
        );
        assert_eq!(
            steps.last().unwrap().properties.step_kind,
            mehscan_core::SecurityPathStepKind::Sink
        );
    }
    let (pending_id, pending_steps) = expected.iter().next().unwrap();
    let pairs = bundles
        .iter()
        .map(|bundle| {
            (
                bundle.clone(),
                answers(bundle, |id| {
                    if id == pending_id {
                        ReviewDecision::NeedsReview
                    } else {
                        ReviewDecision::Issue
                    }
                }),
            )
        })
        .collect::<Vec<_>>();
    let report = build_finding_report(".", "test", None, &pairs, false).unwrap();
    let issue = report
        .findings
        .iter()
        .find(|finding| &finding.id == occurrence)
        .unwrap();
    assert!(
        issue
            .flow
            .iter()
            .chain(&issue.additional_flows)
            .all(|flow| &flow.steps != pending_steps)
    );
    let pending = report
        .review_required
        .iter()
        .find(|finding| &finding.id == occurrence)
        .unwrap();
    assert_eq!(&pending.flow.as_ref().unwrap().steps, pending_steps);
    assert!(
        report
            .decision_records
            .iter()
            .any(|record| &record.response.review_id == pending_id
                && record.response.decision == ReviewDecision::NeedsReview)
    );
    // Legacy positional grouping must not import pending proof into an issue.
    let mut legacy = pairs;
    for (bundle, _) in &mut legacy {
        bundle.identity_catalog = None;
    }
    for _ in 0..2 {
        let legacy_report = build_finding_report(".", "test", None, &legacy, false).unwrap();
        assert!(legacy_report.findings.iter().all(|finding| {
            finding
                .flow
                .iter()
                .chain(&finding.additional_flows)
                .all(|flow| &flow.steps != pending_steps)
        }));
        legacy.reverse();
        for (_, answers) in &mut legacy {
            answers.results.reverse();
        }
    }
}

#[test]
fn same_line_operations_share_github_hint_and_keep_distinct_native_keys() {
    let path = root("same-line-hints");
    let inventory = inventory(
        &path,
        "function handle(request) { eval(request.query.first); eval(request.query.second); }",
        Some("repo:123"),
    );
    let catalog = inventory.identity_catalog.as_ref().unwrap();
    let hashes = catalog
        .subjects
        .values()
        .map(|identity| {
            let hint = identity.primary_location_fingerprint.as_ref().unwrap();
            assert_eq!(hint.location.start.line, 1);
            hint.primary_location_line_hash.clone()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        catalog
            .subjects
            .values()
            .map(|identity| &identity.occurrence_key)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    let bundles = bundles_for(&path, &inventory);
    let pairs = bundles
        .iter()
        .map(|bundle| (bundle.clone(), answers(bundle, |_| ReviewDecision::Issue)))
        .collect::<Vec<_>>();
    let report = build_finding_report(".", "test", None, &pairs, false).unwrap();
    let sarif = mehscan_core::FindingSarifLog::from_finding_report(&report);
    assert_eq!(sarif.runs[0].results.len(), 2);
    for result in &sarif.runs[0].results {
        assert_eq!(
            result.partial_fingerprints.get("primaryLocationLineHash"),
            hashes.first()
        );
    }
    let mut changed_report = report.clone();
    for finding in &mut changed_report.findings {
        finding.primary_location.start.line += 1;
    }
    assert!(
        mehscan_core::FindingSarifLog::from_finding_report(&changed_report).runs[0]
            .results
            .iter()
            .all(|result| !result
                .partial_fingerprints
                .contains_key("primaryLocationLineHash"))
    );
    let mut tampered = bundles[0].clone();
    tampered
        .identity_catalog
        .as_mut()
        .unwrap()
        .subjects
        .values_mut()
        .next()
        .unwrap()
        .primary_location_fingerprint
        .as_mut()
        .unwrap()
        .location
        .start
        .line += 1;
    assert!(
        validate_path_review_bundle_response(
            &tampered,
            &answers(&tampered, |_| ReviewDecision::Issue)
        )
        .unwrap_err()
        .to_string()
        .contains("line fingerprint")
    );
    let mut missing_hint = bundles[0].clone();
    for identity in missing_hint
        .identity_catalog
        .as_mut()
        .unwrap()
        .subjects
        .values_mut()
    {
        identity.primary_location_fingerprint = None;
    }
    let pairs = [(
        missing_hint.clone(),
        answers(&missing_hint, |_| ReviewDecision::Issue),
    )];
    let report = build_finding_report(".", "test", None, &pairs, false).unwrap();
    assert!(
        mehscan_core::FindingSarifLog::from_finding_report(&report).runs[0]
            .results
            .iter()
            .all(|result| !result
                .partial_fingerprints
                .contains_key("primaryLocationLineHash"))
    );
}

#[test]
fn git_subdirectory_sarif_uses_repository_paths_for_all_evidence() {
    let repo = root("sarif-prefix");
    let output = std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = repo.join("app space");
    fs::create_dir_all(&path).unwrap();
    let inventory = inventory(&path, SOURCE, Some("repo:123"));
    let bundles = bundles_for(&path, &inventory);
    let pairs = bundles
        .iter()
        .map(|bundle| (bundle.clone(), answers(bundle, |_| ReviewDecision::Issue)))
        .collect::<Vec<_>>();
    let report = build_finding_report(".", "test", None, &pairs, false).unwrap();
    let sarif = mehscan_core::FindingSarifLog::from_finding_report(&report);
    assert!(!sarif.runs[0].results.is_empty());
    for result in &sarif.runs[0].results {
        for location in result
            .locations
            .iter()
            .chain(&result.related_locations)
            .chain(
                result
                    .code_flows
                    .iter()
                    .flat_map(|flow| &flow.thread_flows)
                    .flat_map(|flow| &flow.locations)
                    .map(|step| &step.location),
            )
        {
            assert_eq!(
                location.physical_location.artifact_location.uri,
                "app%20space/app.js"
            );
        }
        assert!(
            result
                .partial_fingerprints
                .contains_key("primaryLocationLineHash")
        );
    }
}

#[test]
fn sarif_configuration_changes_neither_native_identity_nor_decision_evidence() {
    let path = root("publication-identity");
    let inventory = inventory(&path, SOURCE, Some("repo:123"));
    let bundles = bundles_for(&path, &inventory);
    let pairs = bundles
        .iter()
        .map(|bundle| (bundle.clone(), answers(bundle, |_| ReviewDecision::Issue)))
        .collect::<Vec<_>>();
    let original = build_finding_report(".", "test", None, &pairs, false).unwrap();
    let original_sarif = mehscan_core::FindingSarifLog::from_finding_report(&original);
    assert_eq!(
        original_sarif.runs[0].automation_details.id,
        "mehscan/triaged/"
    );
    let mut configured = original.clone();
    configured.triage.reviewer = Some("different/model".into());
    assert_eq!(
        mehscan_core::FindingSarifLog::from_finding_report(&configured).runs[0]
            .automation_details
            .id,
        "mehscan/triaged/"
    );
    configured.scan.sarif_automation = Some(
        mehscan_core::SarifAutomationConfiguration::new(
            "mehscan/triaged/branch",
            Some("attempt-2"),
        )
        .unwrap(),
    );
    let configured_sarif = mehscan_core::FindingSarifLog::from_finding_report(&configured);
    assert_eq!(
        configured_sarif.runs[0].automation_details.id,
        "mehscan/triaged/branch/attempt-2"
    );
    assert_eq!(
        original_sarif.runs[0].results,
        configured_sarif.runs[0].results
    );
    assert_eq!(original.decision_records, configured.decision_records);
    let publication = configured.sarif_publication();
    assert!(publication.review_work_complete);
    assert_eq!(
        publication.alert_disposition,
        mehscan_core::FindingAlertDisposition::NotEstablished
    );
    let pending_pairs = bundles
        .iter()
        .map(|bundle| {
            (
                bundle.clone(),
                answers(bundle, |_| ReviewDecision::NeedsReview),
            )
        })
        .collect::<Vec<_>>();
    let pending = build_finding_report(".", "test", None, &pending_pairs, false).unwrap();
    assert!(pending.sarif_publication().review_work_complete);
    assert_eq!(
        pending.sarif_publication().alert_disposition,
        mehscan_core::FindingAlertDisposition::NotEstablished
    );
    assert!(!pending.review_required.is_empty());
}

#[test]
fn direct_reports_preserve_change_scope_and_reject_mixed_comparisons() {
    let path = root("publication-scope");
    fs::write(
        path.join("app.js"),
        "function handle(request) { eval(request.query.first); eval(request.query.second); }",
    )
    .unwrap();
    let mut request =
        mehscan_engine::impact::changed_files_from_list(&path, vec!["app.js".into()]).unwrap();
    request.diff_mode = mehscan_engine::ImpactDiffMode::Files;
    let options = mehscan_engine::ScanOptions {
        impact_scope: Some(request),
        ..Default::default()
    };
    let mut inventory = build_review_inventory_scoped_with_native_backends(
        &path, false, None, None, None, options, None,
    )
    .unwrap();
    bind_inventory_repository(&mut inventory, Some("repo:123".into()), None).unwrap();
    let ids = inventory
        .entries
        .iter()
        .map(|entry| entry.review_id.clone())
        .collect();
    let job = build_selected_review_jobs(&path, &inventory, &ids, None).unwrap();
    let set = build_path_review_bundles_with_limits(&job, None, Some(1)).unwrap();
    assert!(set.bundles.len() >= 2);
    let mut pairs = set
        .bundles
        .iter()
        .map(|bundle| (bundle.clone(), answers(bundle, |_| ReviewDecision::Issue)))
        .collect::<Vec<_>>();
    let report = build_finding_report(".", "test", None, &pairs, false).unwrap();
    assert_eq!(report.scan.impact_scope, inventory.scan.impact_scope);
    let publication = report.sarif_publication();
    assert_eq!(
        publication.analysis_scope,
        mehscan_core::FindingAnalysisScope::ChangeComparison
    );
    assert_eq!(
        publication.automation.automation_id(),
        "mehscan/triaged/changed/"
    );
    assert_eq!(
        publication.alert_disposition,
        mehscan_core::FindingAlertDisposition::NotEstablished
    );
    pairs[1].0.impact_scope = None;
    assert!(
        build_finding_report(".", "test", None, &pairs, false)
            .unwrap_err()
            .to_string()
            .contains("cannot mix different change comparisons")
    );
}

#[test]
fn structural_identity_survives_formatting_lines_and_checkout_roots() {
    let a = inventory(&root("a"), SOURCE, Some("github.com/repositories/123"));
    let b = inventory(
        &root("b"),
        "// header\r\n\r\nfunction handle(request) {\r\n  eval ( /* trivia */ request.query.code );\r\n}\r\n",
        Some("github.com/repositories/123"),
    );
    let keys = |i: &ReviewInventory| {
        i.entries
            .iter()
            .map(|e| {
                let identity = e.identity.as_ref().unwrap();
                assert_eq!(
                    identity.continuity,
                    IdentityContinuity::Structural,
                    "{identity:?}"
                );
                (
                    identity.occurrence_key.clone(),
                    identity.subject_key.clone(),
                )
            })
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(keys(&a), keys(&b));
    let a = a.identity_catalog.unwrap();
    let b = b.identity_catalog.unwrap();
    assert_ne!(a.source_fingerprint, b.source_fingerprint);
    // Comment edits change the GitHub transport hint but not native syntax keys.
    let hints = |catalog: &mehscan_core::ReviewIdentityCatalog| {
        catalog
            .subjects
            .values()
            .filter_map(|identity| identity.primary_location_fingerprint.as_ref())
            .map(|hint| hint.primary_location_line_hash.clone())
            .collect::<BTreeSet<_>>()
    };
    assert_ne!(hints(&a), hints(&b));
}

#[test]
fn repository_namespace_is_independent_of_source_fork_provenance() {
    let path = root("namespace");
    let mut a = inventory(&path, SOURCE, Some("github.com/repositories/123"));
    let before = a.entries[0].identity.clone().unwrap();
    bind_inventory_repository(
        &mut a,
        Some("github.com/repositories/123".into()),
        Some("github.com/repositories/999".into()),
    )
    .unwrap();
    assert_eq!(a.entries[0].identity.as_ref().unwrap(), &before);
    bind_inventory_repository(&mut a, Some("github.com/repositories/999".into()), None).unwrap();
    assert_ne!(
        a.entries[0].identity.as_ref().unwrap().occurrence_key,
        before.occurrence_key
    );
    let unscoped = inventory(&path, SOURCE, None);
    assert!(
        unscoped
            .entries
            .iter()
            .all(|e| e.identity.as_ref().unwrap().continuity == IdentityContinuity::Unscoped)
    );
    assert!(
        bind_inventory_repository(
            &mut a,
            Some("https://user:secret@example.com/repo".into()),
            None
        )
        .is_err()
    );
}

#[test]
fn identical_duplicate_sites_are_snapshot_bound_and_never_renumbered_as_stable() {
    let path = root("duplicates");
    let a = inventory(
        &path,
        "function handle(request) { eval(request.query.code); eval(request.query.code); }",
        Some("repo:123"),
    );
    assert!(
        a.entries
            .iter()
            .all(|e| e.identity.as_ref().unwrap().continuity == IdentityContinuity::Ambiguous)
    );
    let b = inventory(
        &path,
        "function handle(request) { eval(request.query.code); eval(request.query.code); eval(request.query.code); }",
        Some("repo:123"),
    );
    assert!(
        b.entries
            .iter()
            .all(|e| e.identity.as_ref().unwrap().continuity == IdentityContinuity::Ambiguous)
    );
    let keys = |i: &ReviewInventory| {
        i.entries
            .iter()
            .map(|e| e.identity.as_ref().unwrap().occurrence_key.clone())
            .collect::<BTreeSet<_>>()
    };
    assert!(keys(&a).is_disjoint(&keys(&b)));
}

#[test]
fn operation_and_operand_changes_do_not_inherit_identity() {
    let path = root("operand");
    let a = inventory(&path, SOURCE, Some("repo:123"));
    let b = inventory(
        &path,
        "function handle(request) { eval(request.query.other); }",
        Some("repo:123"),
    );
    let keys = |i: &ReviewInventory| {
        i.entries
            .iter()
            .map(|e| e.identity.as_ref().unwrap().occurrence_key.clone())
            .collect::<BTreeSet<_>>()
    };
    assert!(keys(&a).is_disjoint(&keys(&b)));
}

#[test]
fn same_line_sites_and_similarly_named_owners_do_not_collapse() {
    let path = root("owners");
    let inventory = inventory(
        &path,
        "class A { handle(request) { eval(request.query.a); } }\nclass B { handle(request) { eval(request.query.a); eval(request.query.b); } }",
        Some("repo:123"),
    );
    let catalog = inventory.identity_catalog.unwrap();
    let mut sites = std::collections::BTreeMap::<String, BTreeSet<String>>::new();
    for identity in catalog.subjects.values() {
        sites
            .entry(identity.occurrence_key.clone())
            .or_default()
            .insert(identity.anchor_id.clone());
    }
    assert!(sites.len() >= 3);
    assert!(sites.values().all(|anchors| anchors.len() == 1));
}

#[test]
fn all_verdicts_keep_native_identity_evidence_and_distinct_decision_records() {
    let path = root("verdicts");
    let inventory = inventory(&path, SOURCE, Some("repo:123"));
    let ids = inventory
        .entries
        .iter()
        .map(|e| e.review_id.clone())
        .collect();
    let job = build_selected_review_jobs(&path, &inventory, &ids, None).unwrap();
    let set = build_path_review_bundles(&job, None).unwrap();
    let bundle = set.bundles.first().unwrap();
    let expected = bundle.identity_catalog.as_ref().unwrap().subjects.clone();
    let mut decisions = BTreeSet::new();
    for decision in [
        ReviewDecision::NotIssue,
        ReviewDecision::NeedsReview,
        ReviewDecision::Issue,
    ] {
        let responses = PathReviewBundleResponseSet {
            schema_version: "1.3".into(),
            bundle_fingerprint: bundle.bundle_fingerprint.clone(),
            results: bundle
                .review_ids
                .iter()
                .map(|id| {
                    let anchor = bundle_selected_anchor_id(bundle, id).unwrap().to_string();
                    PathReviewTriageResult {
                        review_id: id.clone(),
                        selected_anchor_id: Some(anchor.clone()),
                        decision,
                        confidence: ReviewConfidence::Medium,
                        summary: "Synthetic transport decision for the exact selected operation."
                            .into(),
                        checks: if decision == ReviewDecision::NeedsReview {
                            vec!["Confirm the exact input authority.".into()]
                        } else {
                            Vec::new()
                        },
                        investigation: Some(ReviewInvestigationTrace {
                            decisive_artifacts: Vec::new(),
                            journal_summary: None,
                            citations: vec![ReviewArtifactCitation {
                                artifact_id: anchor,
                                claim: "This is the selected operation.".into(),
                            }],
                            reviewer_inferences: Vec::new(),
                            reviewer_origin_leads: Vec::new(),
                            blockers: Vec::new(),
                        }),
                    }
                })
                .collect(),
        };
        let pairs = vec![(bundle.clone(), responses)];
        let report = build_finding_report(".", "test", None, &pairs, false).unwrap();
        assert!(report.dismissed.is_empty());
        assert_eq!(report.decision_records.len(), bundle.review_ids.len());
        for record in &report.decision_records {
            assert_eq!(
                &record.identity,
                expected.get(&record.response.review_id).unwrap()
            );
            assert!(!record.native_evidence.is_empty());
            assert_eq!(record.response.decision, decision);
            decisions.insert(record.decision_id.clone());
        }
        if decision == ReviewDecision::Issue {
            let sarif =
                serde_json::to_value(mehscan_core::FindingSarifLog::from_finding_report(&report))
                    .unwrap();
            assert!(
                sarif["runs"][0]["results"][0]["partialFingerprints"]["mehscanFinding/v2"]
                    .is_string()
            );
        }
    }
    assert_eq!(decisions.len(), 3 * bundle.review_ids.len());
    let mut tampered = bundle.clone();
    tampered
        .identity_catalog
        .as_mut()
        .unwrap()
        .subjects
        .values_mut()
        .next()
        .unwrap()
        .subject_key = "forged".into();
    // A matching bundle fingerprint cannot make model-supplied identity valid.
    let empty = PathReviewBundleResponseSet {
        schema_version: "1.3".into(),
        bundle_fingerprint: tampered.bundle_fingerprint.clone(),
        results: Vec::new(),
    };
    assert!(
        validate_path_review_bundle_response(&tampered, &empty)
            .unwrap_err()
            .to_string()
            .contains("native identity")
    );
}
