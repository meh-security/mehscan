//! Operation/question identity is intentionally independent of review validity.
use super::*;
use mehscan_core::{
    IdentityContinuity, IdentityToken, OccurrenceIdentityTuple, OperationIdentity,
    ReviewDecisionRecord, ReviewIdentityCatalog, ReviewRelationshipScope, ReviewRepositoryIdentity,
    ReviewSubjectIdentity,
};
use sha2::{Digest, Sha256};

pub(super) fn build_catalog(
    root: &Path,
    sources: &RepositorySources,
    candidates: &[mehscan_core::Candidate],
    groups: &[ObservationGroup],
) -> Result<ReviewIdentityCatalog, EngineError> {
    let mut context = ReviewRepositoryIdentity::default();
    let git_directory = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    // Only infer a path prefix. A remote name/URL is not a stable platform ID.
    if let Ok(output) = std::process::Command::new("git")
        .arg("-C")
        .arg(git_directory)
        .args(["rev-parse", "--show-prefix"])
        .output()
    {
        if output.status.success() {
            context.path_prefix = String::from_utf8(output.stdout)
                .map_err(|_| EngineError("repository prefix must be UTF-8".into()))?
                .trim_end_matches(['\r', '\n'])
                .trim_end_matches('/')
                .to_string();
        }
    }
    let mut hash = Sha256::new();
    hash.update(b"mehscan-review-sources/v1\0");
    for (path, file) in &sources.files {
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path.as_bytes());
        hash.update((file.source.len() as u64).to_le_bytes());
        hash.update(file.source.as_bytes());
    }
    let source_fingerprint = format!("review-sources-v1-{:x}", hash.finalize());
    let assessment_context = mehscan_core::ReviewAssessmentContext {
        kind: "source_only".into(),
        source_boundary: context.path_prefix.clone(),
    };
    let mut catalog = ReviewIdentityCatalog {
        schema_version: "1".into(),
        repository: context,
        assessment_context,
        source_fingerprint,
        inventory_input_fingerprint: None,
        subjects: BTreeMap::new(),
    };
    let mut parsed = BTreeMap::<String, Option<AstGrep<StrDoc<SupportLang>>>>::new();
    let mut primary_locations = BTreeMap::new();
    for candidate in candidates {
        let (operation, stable, duplicate) = operation_identity(
            sources,
            &mut parsed,
            &candidate.sink.location,
            candidate.sink.enclosing_symbol.as_deref(),
            &catalog.repository.path_prefix,
        )?;
        let (source, source_stable, source_duplicate) = operation_identity(
            sources,
            &mut parsed,
            &candidate.source.location,
            candidate.source.enclosing_symbol.as_deref(),
            &catalog.repository.path_prefix,
        )?;
        let relationship_scope = ReviewRelationshipScope::SourceToOperation {
            source,
            source_rule: candidate.source.rule_id.clone(),
            source_role: format!("{:?}", candidate.source.capability),
            source_snapshot: (!source_stable || source_duplicate)
                .then(|| candidate.source.id.clone()),
        };
        let mut identity = subject(
            &catalog,
            &candidate.sink.id,
            &candidate.sink.rule_id,
            format!("{:?}", candidate.sink.kind),
            operation,
            relationship_scope,
            stable,
            duplicate,
        )?;
        if !duplicate && (!source_stable || source_duplicate) {
            identity.continuity = IdentityContinuity::SnapshotBound;
        }
        identity.source_anchor_id = Some(candidate.source.id.clone());
        let review_id = candidate.id.replacen("path-", "review-", 1);
        primary_locations.insert(review_id.clone(), candidate.primary_location.clone());
        catalog.subjects.insert(review_id, identity);
    }
    for group in groups {
        let Some(anchor) = group
            .evidence
            .iter()
            .filter(|e| group.anchor_evidence_ids.contains(&e.id))
            .find(|e| e.kind == EvidenceKind::Sink)
            .or_else(|| {
                group.evidence.iter().find(|e| {
                    group.anchor_evidence_ids.contains(&e.id)
                        && matches!(
                            e.kind,
                            EvidenceKind::SensitiveOperation | EvidenceKind::SecurityConfiguration
                        )
                })
            })
        else {
            continue;
        };
        let (operation, stable, duplicate) = operation_identity(
            sources,
            &mut parsed,
            &anchor.location,
            anchor.enclosing_symbol.as_deref(),
            &catalog.repository.path_prefix,
        )?;
        let identity = subject(
            &catalog,
            &anchor.id,
            &anchor.rule_id,
            format!("{:?}", anchor.kind),
            operation,
            ReviewRelationshipScope::OperationQuestion,
            stable,
            duplicate,
        )?;
        let review_id =
            observation_review_id(&group.path, &group.symbol, &group.anchor_evidence_ids);
        primary_locations.insert(review_id.clone(), anchor.location.clone());
        catalog.subjects.insert(review_id, identity);
    }
    disambiguate_catalog(&mut catalog)?;
    // Hash each represented file once, including unselected lines so duplicate
    // suffixes are independent of pagination and selected review IDs.
    let mut locations_by_file = BTreeMap::<&str, Vec<(&String, &Location)>>::new();
    for (id, location) in &primary_locations {
        locations_by_file
            .entry(&location.path)
            .or_default()
            .push((id, location));
    }
    for (path, locations) in locations_by_file {
        let Some(file) = sources.files.get(path) else {
            continue;
        };
        // Native positions count LF. Standalone CR line endings cannot reliably
        // bind that position to the GitHub algorithm's normalized line number.
        if file
            .source
            .as_bytes()
            .iter()
            .enumerate()
            .any(|(i, byte)| *byte == b'\r' && file.source.as_bytes().get(i + 1) != Some(&b'\n'))
        {
            continue;
        }
        let lines = locations
            .iter()
            .map(|(_, location)| location.start.line)
            .collect();
        let hashes = mehscan_core::sarif_fingerprint::github_line_hashes(&file.source, &lines);
        for (id, location) in locations {
            if let Some(hash) = hashes.get(&location.start.line) {
                catalog
                    .subjects
                    .get_mut(id)
                    .expect("catalog primary location")
                    .primary_location_fingerprint = Some(mehscan_core::ReviewLocationFingerprint {
                    location: location.clone(),
                    primary_location_line_hash: hash.clone(),
                });
            }
        }
    }
    Ok(catalog)
}

fn disambiguate_catalog(catalog: &mut ReviewIdentityCatalog) -> Result<(), EngineError> {
    let mut sites = BTreeMap::<String, BTreeSet<String>>::new();
    let mut producers = BTreeMap::<String, BTreeSet<String>>::new();
    for identity in catalog.subjects.values() {
        sites
            .entry(identity.occurrence_key.clone())
            .or_default()
            .insert(identity.anchor_id.clone());
        if let ReviewRelationshipScope::SourceToOperation {
            source,
            source_rule,
            source_role,
            ..
        } = &identity.relationship_scope
        {
            let key = digest("producer-site/v1", &(source, source_rule, source_role))?;
            if let Some(anchor) = &identity.source_anchor_id {
                producers.entry(key).or_default().insert(anchor.clone());
            }
        }
    }
    for identity in catalog.subjects.values_mut() {
        if sites
            .get(&identity.occurrence_key)
            .is_some_and(|ids| ids.len() > 1)
        {
            identity.continuity = IdentityContinuity::Ambiguous;
            identity.occurrence.snapshot_discriminator = Some(format!(
                "{}:{}",
                catalog.source_fingerprint, identity.anchor_id
            ));
        }
        if let ReviewRelationshipScope::SourceToOperation {
            source,
            source_rule,
            source_role,
            source_snapshot,
        } = &mut identity.relationship_scope
        {
            let key = digest(
                "producer-site/v1",
                &(&*source, &*source_rule, &*source_role),
            )?;
            if producers.get(&key).is_some_and(|ids| ids.len() > 1) {
                *source_snapshot = identity
                    .source_anchor_id
                    .as_ref()
                    .map(|anchor| format!("{}:{anchor}", catalog.source_fingerprint));
                if identity.continuity != IdentityContinuity::Ambiguous {
                    identity.continuity = IdentityContinuity::SnapshotBound;
                }
            }
        }
        rehash(identity)?;
    }
    Ok(())
}

fn subject(
    catalog: &ReviewIdentityCatalog,
    anchor: &str,
    rule: &str,
    role: String,
    operation: OperationIdentity,
    relationship_scope: ReviewRelationshipScope,
    stable: bool,
    duplicate: bool,
) -> Result<ReviewSubjectIdentity, EngineError> {
    let continuity = if duplicate {
        IdentityContinuity::Ambiguous
    } else if !stable {
        IdentityContinuity::SnapshotBound
    } else {
        IdentityContinuity::Unscoped
    };
    let occurrence = OccurrenceIdentityTuple {
        version: "mehscanFinding/v2".into(),
        repository_key: catalog.repository.repository_key.clone(),
        weakness_identity: rule.into(),
        operation,
        operation_role: role,
        snapshot_discriminator: (duplicate || !stable)
            .then(|| format!("{}:{anchor}", catalog.source_fingerprint)),
    };
    let mut identity = ReviewSubjectIdentity {
        primary_location_fingerprint: None,
        anchor_id: anchor.into(),
        source_anchor_id: None,
        occurrence_key: String::new(),
        subject_key: String::new(),
        continuity,
        occurrence,
        relationship_scope,
    };
    rehash(&mut identity)?;
    Ok(identity)
}

fn rehash(identity: &mut ReviewSubjectIdentity) -> Result<(), EngineError> {
    identity.occurrence_key = digest("mehscanFinding/v2", &identity.occurrence)?;
    identity.subject_key = digest(
        "mehscanSubject/v1",
        &(&identity.occurrence_key, &identity.relationship_scope),
    )?;
    Ok(())
}

pub(super) fn digest<T: Serialize>(version: &str, input: &T) -> Result<String, EngineError> {
    let bytes = serde_json::to_vec(&(version, input)).map_err(|e| EngineError(e.to_string()))?;
    Ok(format!(
        "{version}:{}",
        crate::csharp_semantic::digest(&bytes)
    ))
}

pub(super) fn bind_repository(
    catalog: &mut ReviewIdentityCatalog,
    key: Option<String>,
    source_key: Option<String>,
) -> Result<(), EngineError> {
    for value in key.iter().chain(source_key.iter()) {
        if value.trim() != value
            || value.is_empty()
            || value.len() > 512
            || value.chars().any(char::is_control)
            || value.contains("://")
            || value.contains('@')
            || Path::new(value).is_absolute()
        {
            return Err(EngineError("repository keys must be stable opaque IDs, without credentials, URLs, absolute paths or control characters".into()));
        }
    }
    catalog.repository.repository_key = key.clone();
    catalog.repository.source_repository_key = source_key;
    for identity in catalog.subjects.values_mut() {
        identity.occurrence.repository_key = key.clone();
        if matches!(
            identity.continuity,
            IdentityContinuity::Unscoped | IdentityContinuity::Structural
        ) {
            identity.continuity = if key.is_some() {
                IdentityContinuity::Structural
            } else {
                IdentityContinuity::Unscoped
            };
        }
        rehash(identity)?;
    }
    Ok(())
}

fn operation_identity(
    sources: &RepositorySources,
    cache: &mut BTreeMap<String, Option<AstGrep<StrDoc<SupportLang>>>>,
    location: &Location,
    symbol: Option<&str>,
    prefix: &str,
) -> Result<(OperationIdentity, bool, bool), EngineError> {
    let file = sources.file(&location.path)?;
    let start = location.start.byte_offset;
    let end = location.end.byte_offset;
    let exact = file
        .source
        .get(start..end)
        .ok_or_else(|| EngineError("identity anchor is outside source bytes".into()))?;
    let path = if prefix.is_empty() {
        location.path.clone()
    } else {
        format!("{prefix}/{}", location.path)
    };
    let ast = cache.entry(file.path.clone()).or_insert_with(|| {
        let language = file.language?;
        if file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
            return None;
        }
        let doc = StrDoc::try_new(&file.source, parser_language(language)).ok()?;
        let ast = AstGrep::doc(doc);
        let valid = !ast.root().dfs().any(|n| n.is_error() || n.is_missing());
        valid.then_some(ast)
    });
    let mut op = OperationIdentity {
        path,
        language: file.language,
        enclosing_symbol: symbol.map(str::to_owned),
        tokens: vec![IdentityToken {
            kind: "exact_source_sha256".into(),
            text: crate::csharp_semantic::digest(exact.as_bytes()),
        }],
        structural_context: Vec::new(),
        normalization: "exact_source_snapshot/v1".into(),
    };
    let Some(ast) = ast else {
        return Ok((op, false, false));
    };
    let root = ast.root();
    let Some(node) = root.dfs().find(|n| n.range() == (start..end)) else {
        return Ok((op, false, false));
    };
    let normalized = tokens(&node);
    if normalized.len() > 128 || normalized.iter().map(|t| t.text.len()).sum::<usize>() > 4096 {
        return Ok((op, false, false));
    }
    op.tokens = normalized;
    op.structural_context = structural_context(&node);
    op.normalization = "typed_ast_tokens/v1".into();
    let owner = owner_range(&node);
    let mut matches = 0;
    for other in root
        .dfs()
        .filter(|n| n.kind() == node.kind() && owner_range(n) == owner)
    {
        if structural_context(&other) == op.structural_context && tokens(&other) == op.tokens {
            matches += 1;
            if matches > 1 {
                break;
            }
        }
    }
    Ok((op, true, matches > 1))
}

fn owner_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|n| {
            let kind = n.kind();
            kind.contains("function") || kind.contains("method") || kind.contains("lambda")
        })
        .map(|n| n.range())
}

fn structural_context(node: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    let mut result = Vec::new();
    for parent in node.ancestors() {
        let kind = parent.kind();
        if kind.contains("function") || kind.contains("method") || kind.contains("lambda") {
            break;
        }
        if kind.contains("if")
            || kind.contains("case")
            || kind.contains("loop")
            || kind.contains("for")
            || kind.contains("while")
            || kind.contains("catch")
            || kind.contains("conditional")
        {
            let branch = ["consequence", "alternative", "body", "condition"]
                .into_iter()
                .find(|field| {
                    parent.field(field).is_some_and(|child| {
                        child.range().start <= node.range().start
                            && child.range().end >= node.range().end
                    })
                })
                .unwrap_or("scope");
            result.push(format!("{kind}:{branch}"));
        }
    }
    result
}

fn tokens(node: &Node<'_, StrDoc<SupportLang>>) -> Vec<IdentityToken> {
    let mut result = Vec::new();
    collect_tokens(node, &mut result);
    result
}
fn collect_tokens(node: &Node<'_, StrDoc<SupportLang>>, result: &mut Vec<IdentityToken>) {
    let kind = node.kind();
    if kind.contains("comment") {
        return;
    }
    if node.is_leaf()
        || kind.contains("string")
        || kind.contains("char_literal")
        || kind.contains("regex")
        || kind.starts_with("preproc")
    {
        let literal = kind.contains("string")
            || kind.contains("char_literal")
            || kind.contains("regex")
            || kind.starts_with("preproc");
        let text = if literal {
            format!(
                "sha256:{}",
                crate::csharp_semantic::digest(node.text().as_bytes())
            )
        } else {
            node.text().into_owned()
        };
        result.push(IdentityToken {
            kind: kind.into_owned(),
            text,
        });
    } else {
        for child in node.children() {
            collect_tokens(&child, result);
        }
    }
}

pub(super) fn validate_bundle(
    catalog: &ReviewIdentityCatalog,
    bundle: &PathReviewBundle,
) -> Result<(), EngineError> {
    let mut checked = catalog.clone();
    bind_repository(
        &mut checked,
        catalog.repository.repository_key.clone(),
        catalog.repository.source_repository_key.clone(),
    )?;
    if checked.subjects != catalog.subjects {
        return Err(EngineError(
            "native identity continuity does not match its namespace".into(),
        ));
    }
    if catalog.schema_version != "1"
        || catalog.assessment_context.kind != "source_only"
        || catalog.assessment_context.source_boundary != catalog.repository.path_prefix
        || catalog.subjects.len() != bundle.review_ids.len()
    {
        return Err(EngineError(
            "invalid native identity catalog contract".into(),
        ));
    }
    for id in &bundle.review_ids {
        let identity = catalog
            .subjects
            .get(id)
            .ok_or_else(|| EngineError("missing native review subject".into()))?;
        let mut computed = identity.clone();
        rehash(&mut computed)?;
        let (_, _, location, rule, _) = bundle_issue_context(bundle, id)?;
        let expected_path = if catalog.repository.path_prefix.is_empty() {
            location.path
        } else {
            format!("{}/{}", catalog.repository.path_prefix, location.path)
        };
        let source_structural = match &identity.relationship_scope {
            ReviewRelationshipScope::SourceToOperation {
                source,
                source_snapshot,
                ..
            } => source.normalization == "typed_ast_tokens/v1" && source_snapshot.is_none(),
            ReviewRelationshipScope::OperationQuestion => true,
        };
        if let Some(fingerprint) = &identity.primary_location_fingerprint {
            let primary = match &bundle.payload {
                PathReviewBundlePayload::SecurityPath { reviews } => reviews
                    .iter()
                    .find(|review| &review.id == id)
                    .map(|review| &review.candidate.primary_location),
                PathReviewBundlePayload::Observation { reviews } => reviews
                    .iter()
                    .find(|review| &review.id == id)
                    .and_then(observation_actionable_anchor)
                    .map(|anchor| &anchor.location),
            };
            let valid_hash = fingerprint
                .primary_location_line_hash
                .split_once(':')
                .is_some_and(|(hash, count)| {
                    !hash.is_empty()
                        && hash.len() <= 16
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        && count.parse::<usize>().is_ok_and(|count| count > 0)
                });
            if primary != Some(&fingerprint.location) || !valid_hash {
                return Err(EngineError(
                    "native line fingerprint does not match its primary location or hash format"
                        .into(),
                ));
            }
        }
        if &computed != identity
            || identity.occurrence.version != "mehscanFinding/v2"
            || identity.occurrence.weakness_identity != rule
            || identity.occurrence.operation.path != expected_path
            || identity.anchor_id != bundle_selected_anchor_id(bundle, id)?
            || identity.occurrence.repository_key != catalog.repository.repository_key
            || (identity.continuity == IdentityContinuity::Structural
                && (catalog.repository.repository_key.is_none()
                    || identity.occurrence.snapshot_discriminator.is_some()
                    || identity.occurrence.operation.normalization != "typed_ast_tokens/v1"
                    || !source_structural))
        {
            return Err(EngineError(
                "native identity does not match its tuple, repository or selected anchor".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(name: &str, code: &str, expression: &str) -> OperationIdentity {
        let root = std::env::temp_dir().join(format!(
            "mehscan-identity-tokens-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(name), code).unwrap();
        let start = code.find(expression).unwrap();
        let location = Location {
            path: name.into(),
            start: Position {
                line: 1,
                column: 1,
                byte_offset: start,
            },
            end: Position {
                line: 1,
                column: 1,
                byte_offset: start + expression.len(),
            },
        };
        let sources = RepositorySources::load(&root).unwrap();
        let (operation, stable, _) =
            operation_identity(&sources, &mut BTreeMap::new(), &location, Some("run"), "").unwrap();
        assert!(stable);
        operation
    }

    #[test]
    fn literal_values_and_string_whitespace_remain_distinct_without_copying_literals() {
        let spaced = normalized("app.js", "eval('a b');", "eval('a b')");
        let compact = normalized("app.js", "eval('ab');", "eval('ab')");
        assert_ne!(spaced.tokens, compact.tokens);
        assert!(!serde_json::to_string(&spaced).unwrap().contains("a b"));
        let formatted = normalized(
            "app.js",
            "eval ( /* comment */ 'a b' );",
            "eval ( /* comment */ 'a b' )",
        );
        assert_eq!(spaced.tokens, formatted.tokens);
    }

    #[test]
    fn python_indentation_that_changes_control_scope_changes_the_site() {
        let guarded = normalized(
            "app.py",
            "def run(request):\n    if allowed(request):\n        eval(request.args['code'])\n",
            "eval(request.args['code'])",
        );
        let exposed = normalized(
            "app.py",
            "def run(request):\n    if allowed(request):\n        pass\n    eval(request.args['code'])\n",
            "eval(request.args['code'])",
        );
        assert_eq!(guarded.tokens, exposed.tokens);
        assert_ne!(guarded.structural_context, exposed.structural_context);
    }
}

pub(super) fn decision_record(
    bundle: &PathReviewBundle,
    response: &PathReviewTriageResult,
) -> Result<Option<ReviewDecisionRecord>, EngineError> {
    let Some(catalog) = &bundle.identity_catalog else {
        return Ok(None);
    };
    let identity = catalog
        .subjects
        .get(&response.review_id)
        .ok_or_else(|| EngineError("missing decision subject identity".into()))?
        .clone();
    let (native_evidence, native_flows) = match &bundle.payload {
        PathReviewBundlePayload::SecurityPath { reviews } => {
            let candidate = &reviews
                .iter()
                .find(|r| r.id == response.review_id)
                .ok_or_else(|| EngineError("missing path review".into()))?
                .candidate;
            let mut evidence = vec![candidate.source.clone(), candidate.sink.clone()];
            evidence.extend(candidate.protections.clone());
            (evidence, vec![candidate.steps.clone()])
        }
        PathReviewBundlePayload::Observation { reviews } => {
            let review = reviews
                .iter()
                .find(|r| r.id == response.review_id)
                .ok_or_else(|| EngineError("missing observation review".into()))?;
            (
                review
                    .evidence
                    .iter()
                    .map(|e| mehscan_core::CandidateEvidence {
                        id: e.id.clone(),
                        rule_id: e.rule_id.clone(),
                        kind: e.kind,
                        capability: e.capability,
                        location: e.location.clone(),
                        enclosing_symbol: e.enclosing_symbol.clone(),
                        confidence: e.confidence,
                        provenance: e.provenance.clone(),
                        context: e.context.clone(),
                        symbol_resolution: e.symbol_resolution.clone(),
                    })
                    .collect(),
                Vec::new(),
            )
        }
    };
    let basis_fingerprint = digest(
        "mehscanReviewBasis/v1",
        &(
            &catalog.source_fingerprint,
            &catalog.inventory_input_fingerprint,
            &bundle.job_fingerprint,
            &bundle.bundle_fingerprint,
            &bundle.impact_scope,
            &bundle.triage_contract,
            &response.investigation,
        ),
    )?;
    let response_fingerprint = digest("mehscanDecisionResponse/v1", response)?;
    let decision_id = digest(
        "mehscanDecision/v1",
        &(
            &identity.subject_key,
            &catalog.repository,
            &catalog.assessment_context,
            &basis_fingerprint,
            &response_fingerprint,
        ),
    )?;
    Ok(Some(ReviewDecisionRecord {
        decision_id,
        identity,
        repository: catalog.repository.clone(),
        assessment_context: catalog.assessment_context.clone(),
        basis_fingerprint,
        source_fingerprint: catalog.source_fingerprint.clone(),
        inventory_input_fingerprint: catalog.inventory_input_fingerprint.clone(),
        job_fingerprint: bundle.job_fingerprint.clone(),
        bundle_fingerprint: bundle.bundle_fingerprint.clone(),
        response_fingerprint,
        native_evidence,
        native_flows,
        response: response.clone(),
    }))
}
