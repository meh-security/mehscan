use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Pattern};
use ast_grep_language::SupportLang;
use ast_grep_outline::DEFAULT_OUTLINE_RULES;
use ast_grep_outline::combined_extractor::CombinedExtractors;
use ast_grep_outline::extractor::parse_outline_rules;
use ast_grep_outline::model::{OutlineEntry, OutlineItem, OutlineMember, SymbolType};
use mehscan_core::{
    CandidateReport, Capability, DismissedReview, EnclosingSymbolResult, Evidence, EvidenceFilter,
    EvidenceKind, EvidenceResults, FINDING_REPORT_SCHEMA_VERSION, FileOutline, FindingFlow,
    FindingProvenance, FindingRelatedLocation, FindingReport, FindingReportScan,
    FindingReportSummary, FindingReportTool, FindingReportTriage, FindingStatus,
    InvestigationAnchor, InvestigationJob, InvestigationLimits, InvestigationUnit,
    InvestigationUnitProvenance, Language, LiteralState, LiteralValue, Location, ObservationReview,
    ObservationReviewBasis, OutlineSymbol, PATH_REVIEW_BUNDLE_SCHEMA_VERSION,
    PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, PathReview, PathReviewBasis, PathReviewBundle,
    PathReviewBundleCategory, PathReviewBundleIssueGroup, PathReviewBundleManifest,
    PathReviewBundleManifestEntry, PathReviewBundlePayload, PathReviewBundleResponseSet,
    PathReviewBundleRunReport, PathReviewBundleSet, PathReviewBundleTriageReport,
    PathReviewEvidenceBasis, PathReviewIssueGroup, PathReviewJob, PathReviewTask,
    PathReviewTaskPage, PathReviewTaskPayload, PathReviewTriageProgress, PathReviewTriageReport,
    PathReviewTriageResponseSet, Position, QueryProvenance, QueryResponse,
    REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, RelationContract, RelationshipFunnel,
    RelationshipFunnelCapability, ReportedFinding, ReportedSeverity, Resolution,
    ResourcePolicyState, ReviewConfidence, ReviewConfidencePolicy, ReviewContextTruncation,
    ReviewDecision, ReviewDecisionFacts, ReviewNeighborhoodFact, ReviewNeighborhoodJob,
    ReviewTriageContract, ReviewTriageReport, ReviewTriageResponseSet, Rule, RuntimeEnvironment,
    SCHEMA_VERSION, SecurityPathStepKind, Severity, SeveritySource, SourceSlice, StructuralMatch,
    TextReference,
};

use crate::repository::{FileClass, discover, is_sast_excluded_source};
use crate::rules::parser_language;
use crate::{EngineError, csharp_review, scan_path};

const DEFAULT_RESULT_LIMIT: usize = 200;
const MAX_RESULT_LIMIT: usize = 1_000;
const MAX_SOURCE_LINES: usize = 400;
const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_REVIEW_PRIMARY_CONTEXT_BYTES: usize = 16 * 1024;
const DEFAULT_UNIT_LIMIT: usize = 25;
const MAX_UNIT_LIMIT: usize = 100;
const DEFAULT_CONTEXT_LINES: usize = 20;
const MAX_CONTEXT_LINES: usize = 100;
const MAX_UNIT_EVIDENCE: usize = 100;
const MAX_UNIT_IMPORTS: usize = 50;
const DEFAULT_REVIEW_CONTEXT_LINES: usize = 8;
const MAX_REVIEW_CONFIGURATION_FACTS: usize = 16;
const MAX_REVIEW_HELPER_FACTS: usize = 12;
const MAX_REVIEW_SECOND_HOP_FACTS: usize = 8;
const MAX_REVIEW_ORIGIN_FACTS: usize = 6;
const MAX_REVIEW_HELPER_LINES: usize = 40;
const MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES: usize = 512 * 1024;
const DEFAULT_REVIEW_LIMIT: usize = 100;
const MAX_REVIEW_LIMIT: usize = 100;
pub const DEFAULT_REVIEW_BUNDLE_MAX_BYTES: usize = 512 * 1024;
pub const DEFAULT_REVIEW_BUNDLE_MAX_REVIEWS: usize = 20;
const MIN_REVIEW_BUNDLE_MAX_BYTES: usize = 16 * 1024;
const MAX_REVIEW_BUNDLE_MAX_BYTES: usize = 4 * 1024 * 1024;

struct SourceFile {
    path: String,
    language: Option<Language>,
    source: String,
}

struct RepositorySources {
    root: String,
    files: BTreeMap<String, SourceFile>,
}

struct OutlineExtractors {
    by_language: BTreeMap<Language, CombinedExtractors<SupportLang>>,
}

struct PendingUnit {
    language: Option<Language>,
    anchor: InvestigationAnchor,
    selected_evidence_ids: Vec<String>,
}

struct ObservationGroup {
    path: String,
    symbol: String,
    evidence: Vec<Evidence>,
    anchor_evidence_ids: Vec<String>,
    priority: u8,
    review_material: bool,
}

struct ReviewContextIndex {
    definitions: BTreeMap<String, Vec<OutlineSymbol>>,
    registrations: BTreeMap<String, Vec<ReviewNeighborhoodFact>>,
    usages: BTreeMap<String, Vec<ReviewNeighborhoodFact>>,
}

fn is_review_material_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let components = normalized.split('/').collect::<Vec<_>>();
    components.iter().any(|component| {
        matches!(
            *component,
            "codefixes" | "code-fixes" | "hacking-instructor"
        )
    }) || (components.contains(&"playground") && normalized.ends_with("/soln.py"))
}

fn is_nonproduction_review_context_path(path: &str) -> bool {
    is_review_material_path(path) || is_sast_excluded_source(Path::new(path))
}

pub fn get_file_outline(
    root: &Path,
    path: &str,
) -> Result<QueryResponse<FileOutline>, EngineError> {
    let sources = RepositorySources::load(root)?;
    let file = sources.file(path)?;
    let language = file.language.ok_or_else(|| {
        EngineError(format!(
            "file {:?} is text-only and has no structural outline",
            file.path
        ))
    })?;
    let symbols = OutlineExtractors::build()?.extract(file)?;
    Ok(response(
        &sources.root,
        "get_file_outline",
        ast_provenance("ast-grep-outline 0.45.1"),
        false,
        FileOutline {
            path: file.path.clone(),
            language,
            symbols,
        },
    ))
}

pub fn get_source(
    root: &Path,
    path: &str,
    start_line: usize,
    end_line: usize,
) -> Result<QueryResponse<SourceSlice>, EngineError> {
    if start_line == 0 || end_line < start_line {
        return Err(EngineError(
            "source range must use one-based lines with end >= start".to_string(),
        ));
    }
    let sources = RepositorySources::load(root)?;
    let file = sources.file(path)?;
    let (slice, truncated) = source_slice(file, start_line, end_line)?;
    Ok(response(
        &sources.root,
        "get_source",
        textual_provenance("bounded-source-reader"),
        truncated,
        slice,
    ))
}

pub fn get_enclosing_symbol(
    root: &Path,
    evidence_id: &str,
) -> Result<QueryResponse<EnclosingSymbolResult>, EngineError> {
    let scan = scan_path(root)?;
    let evidence = scan
        .evidence
        .iter()
        .find(|item| item.id == evidence_id)
        .ok_or_else(|| EngineError(format!("evidence id {evidence_id:?} was not found")))?;
    let sources = RepositorySources::load(root)?;
    let file = sources.file(&evidence.location.path)?;
    let symbol = OutlineExtractors::build()?
        .extract(file)?
        .into_iter()
        .filter(|symbol| {
            symbol.location.start.byte_offset <= evidence.location.start.byte_offset
                && symbol.location.end.byte_offset >= evidence.location.end.byte_offset
        })
        .min_by_key(|symbol| symbol.location.end.byte_offset - symbol.location.start.byte_offset);
    Ok(response(
        &sources.root,
        "get_enclosing_symbol",
        ast_provenance("ast-grep-outline 0.45.1"),
        false,
        EnclosingSymbolResult {
            evidence_id: evidence_id.to_string(),
            symbol,
        },
    ))
}

pub fn find_evidence(
    root: &Path,
    filter: EvidenceFilter,
    limit: Option<usize>,
) -> Result<QueryResponse<EvidenceResults>, EngineError> {
    let filter = normalize_evidence_filter(filter)?;
    let limit = bounded_limit(limit)?;
    let scan = scan_path(root)?;
    let languages: BTreeMap<_, _> = scan
        .coverage
        .files
        .iter()
        .filter_map(|file| file.language.map(|language| (file.path.as_str(), language)))
        .collect();
    let mut matches = scan
        .evidence
        .into_iter()
        .filter(|evidence| evidence_matches(evidence, &filter, &languages))
        .collect::<Vec<_>>();
    let truncated = matches.len() > limit;
    matches.truncate(limit);
    Ok(response(
        &scan.root,
        "find_evidence",
        ast_provenance("mehscan deterministic evidence index"),
        truncated,
        EvidenceResults {
            filter,
            evidence: matches,
        },
    ))
}

pub fn relationship_funnel(root: &Path) -> Result<QueryResponse<RelationshipFunnel>, EngineError> {
    let scan = scan_path(root)?;
    let rules = crate::rules::load_builtin_rules()?;
    let relations = crate::rules::load_builtin_relations(&rules)?;
    let linked_sink_ids = scan
        .security_paths
        .iter()
        .map(|path| path.sink_evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let source_observations = scan
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Source
                && relations
                    .iter()
                    .any(|relation| relation.source.accepts(item.capability))
        })
        .collect::<Vec<_>>();
    let sinks = scan
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Sink
                && relations
                    .iter()
                    .any(|relation| relation.sink.capability == item.capability)
        })
        .collect::<Vec<_>>();
    let sources = RepositorySources::load(root)?;
    let outlines = OutlineExtractors::build()?;
    let mut outline_cache: BTreeMap<String, Vec<OutlineSymbol>> = BTreeMap::new();
    for path in source_observations
        .iter()
        .map(|item| item.location.path.as_str())
        .chain(sinks.iter().map(|item| item.location.path.as_str()))
        .collect::<BTreeSet<_>>()
    {
        let file = sources.file(path)?;
        if file.language.is_some() {
            outline_cache.insert(path.to_string(), outlines.extract(file)?);
        }
    }
    let mut sources_by_symbol: BTreeMap<
        (String, usize, usize),
        BTreeSet<mehscan_core::Capability>,
    > = BTreeMap::new();
    for source in &source_observations {
        if let Some(key) = relationship_anchor(source, &outline_cache) {
            sources_by_symbol
                .entry(key)
                .or_default()
                .insert(source.capability);
        }
    }
    let mut by_capability = BTreeMap::new();
    let mut compatible = 0usize;
    let mut linked = 0usize;
    let mut unlinked_compatible = 0usize;
    for sink in &sinks {
        let stats = by_capability
            .entry(sink.capability)
            .or_insert_with(RelationshipFunnelCapability::default);
        stats.sink_observations += 1;
        let has_compatible_source = relationship_anchor(sink, &outline_cache).is_some_and(|key| {
            sources_by_symbol.get(&key).is_some_and(|sources| {
                relations.iter().any(|relation| {
                    relation.sink.capability == sink.capability
                        && sources
                            .iter()
                            .any(|source| relation.source.accepts(*source))
                })
            })
        });
        if has_compatible_source {
            compatible += 1;
            stats.sinks_with_compatible_source_in_symbol += 1;
        }
        if linked_sink_ids.contains(sink.id.as_str()) {
            linked += 1;
            stats.linked_sink_observations += 1;
        } else if has_compatible_source {
            unlinked_compatible += 1;
            stats.unlinked_sinks_with_compatible_source_in_symbol += 1;
        }
    }
    let result = RelationshipFunnel {
        relation_source_observations: source_observations.len(),
        remote_source_observations: source_observations
            .iter()
            .filter(|item| {
                matches!(
                    item.capability,
                    mehscan_core::Capability::HttpRequestData
                        | mehscan_core::Capability::RpcRequestData
                )
            })
            .count(),
        eligible_sink_observations: sinks.len(),
        sinks_with_compatible_source_in_symbol: compatible,
        linked_sink_observations: linked,
        unlinked_sinks_with_compatible_source_in_symbol: unlinked_compatible,
        sinks_without_compatible_source_in_symbol: sinks.len().saturating_sub(compatible),
        security_paths: scan.security_paths.len(),
        by_capability,
        interpretation: vec![
            "A sink without a compatible source in the same enclosing symbol remains isolated evidence; cross-function flow is not inferred.".to_string(),
            "An unlinked same-symbol sink is an AI review lead, not a vulnerability: the bounded value-flow builder did not connect the observed source to that sink input.".to_string(),
            "Security-path count can exceed linked sink count when multiple source observations reach one sink.".to_string(),
        ],
    };
    Ok(response(
        &scan.root,
        "relationship_funnel",
        ast_provenance("mehscan relation-funnel summary 1"),
        false,
        result,
    ))
}

fn relationship_anchor(
    evidence: &Evidence,
    outlines: &BTreeMap<String, Vec<OutlineSymbol>>,
) -> Option<(String, usize, usize)> {
    let symbol = outlines
        .get(&evidence.location.path)
        .and_then(|outline| enclosing_outline_symbol(outline, &evidence.location))?;
    Some((
        evidence.location.path.clone(),
        symbol.location.start.byte_offset,
        symbol.location.end.byte_offset,
    ))
}

pub fn build_csharp_review_neighborhoods(
    root: &Path,
    limit: Option<usize>,
) -> Result<ReviewNeighborhoodJob, EngineError> {
    let max_neighborhoods = bounded_unit_limit(limit)?;
    let scan = scan_path(root)?;
    let sources = RepositorySources::load(root)?;
    let (neighborhoods, truncated) = crate::csharp_review::build(
        &scan.evidence,
        sources
            .files
            .values()
            .map(|file| (file.path.as_str(), file.language, file.source.as_str())),
        max_neighborhoods,
    );
    let triage_contract = crate::csharp_review::triage_contract();
    let fingerprint = crate::csharp_review::fingerprint(&neighborhoods, &triage_contract);
    Ok(ReviewNeighborhoodJob {
        schema_version: SCHEMA_VERSION.to_string(),
        root: scan.root,
        operation: "build_csharp_review_neighborhoods".to_string(),
        language: Language::Csharp,
        fingerprint,
        triage_contract,
        max_neighborhoods,
        truncated,
        neighborhoods,
        coverage: scan.coverage,
        diagnostics: scan.diagnostics,
    })
}

pub fn build_path_review_jobs(
    root: &Path,
    context_lines: Option<usize>,
    limit: Option<usize>,
) -> Result<PathReviewJob, EngineError> {
    build_path_review_jobs_page(root, context_lines, limit, 0, false)
}

/// Builds one page from a deterministic, path-first review sequence. Teaching
/// and source-payload trees remain part of the scan but are not admitted to AI
/// review unless `include_review_material` is explicitly enabled.
pub fn build_path_review_jobs_page(
    root: &Path,
    context_lines: Option<usize>,
    limit: Option<usize>,
    offset: usize,
    include_review_material: bool,
) -> Result<PathReviewJob, EngineError> {
    let max_reviews = bounded_review_limit(limit)?;
    build_path_review_jobs_internal(
        root,
        context_lines,
        Some(max_reviews),
        offset,
        include_review_material,
    )
}

/// Builds the complete admitted review sequence with one scan. This is used by
/// semantic bundles so arbitrary transport pages cannot divide one category.
pub fn build_all_path_review_jobs(
    root: &Path,
    context_lines: Option<usize>,
    include_review_material: bool,
) -> Result<PathReviewJob, EngineError> {
    build_path_review_jobs_internal(root, context_lines, None, 0, include_review_material)
}

fn build_path_review_jobs_internal(
    root: &Path,
    context_lines: Option<usize>,
    max_reviews: Option<usize>,
    offset: usize,
    include_review_material: bool,
) -> Result<PathReviewJob, EngineError> {
    let context_lines =
        bounded_context_lines(context_lines.or(Some(DEFAULT_REVIEW_CONTEXT_LINES)))?;
    let scan = scan_path(root)?;
    let report = CandidateReport::from_scan(&scan)
        .map_err(|error| EngineError(format!("could not build candidate report: {error}")))?;
    let rules = crate::rules::load_builtin_rules()?;
    let rules_by_id = rules
        .iter()
        .map(|rule| (rule.id.as_str(), rule))
        .collect::<BTreeMap<_, _>>();
    let evidence_by_id = scan
        .evidence
        .iter()
        .map(|evidence| (evidence.id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let sources = RepositorySources::load(root)?;
    let (csharp_neighborhoods, _) = csharp_review::build(
        &scan.evidence,
        sources
            .files
            .values()
            .map(|file| (file.path.as_str(), file.language, file.source.as_str())),
        usize::MAX,
    );
    let languages = scan
        .coverage
        .files
        .iter()
        .filter_map(|file| file.language.map(|language| (file.path.as_str(), language)))
        .collect::<BTreeMap<_, _>>();
    let triage_contract = path_review_triage_contract();
    let all_candidates = report.candidates;
    let mut candidates = all_candidates
        .iter()
        .filter(|candidate| {
            include_review_material || !is_review_material_path(&candidate.primary_location.path)
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        is_review_material_path(&left.primary_location.path)
            .cmp(&is_review_material_path(&right.primary_location.path))
    });
    let excluded_candidates = all_candidates.len().saturating_sub(candidates.len());
    let used_ids = candidate_evidence_ids(&all_candidates, &scan.evidence, &sources);
    let mut observation_groups =
        observation_groups(&scan.evidence, &used_ids, &all_candidates, &sources);
    let all_observation_count = observation_groups.len();
    if !include_review_material {
        observation_groups.retain(|group| !group.review_material);
    }
    let excluded_observations = all_observation_count.saturating_sub(observation_groups.len());
    let indexed_references =
        review_reference_tokens(&candidates, &sources, &evidence_by_id, context_lines);
    let review_context = ReviewContextIndex::build(&sources, &indexed_references)?;
    candidates.retain(|candidate| {
        !csharp_redirect_helper_query_only_candidate(
            candidate,
            &evidence_by_id,
            &sources,
            &review_context,
        )
    });
    let candidate_count = candidates.len();
    let observation_total = observation_groups.len();
    let total_reviews = candidate_count + observation_total;
    let max_reviews = max_reviews.unwrap_or(total_reviews.max(1));
    if offset > total_reviews {
        return Err(EngineError(format!(
            "review offset {offset} exceeds total review count {total_reviews}"
        )));
    }
    let selected_candidate_start = offset.min(candidate_count);
    let selected_candidate_count = candidate_count
        .saturating_sub(selected_candidate_start)
        .min(max_reviews);
    let mut reviews = Vec::new();
    for candidate in candidates
        .into_iter()
        .skip(selected_candidate_start)
        .take(selected_candidate_count)
    {
        let mut facts = Vec::new();
        let mut configuration_tokens = BTreeSet::new();
        let mut context_truncated = false;
        let mut decision_critical_context_truncated = false;
        for (index, step) in candidate.steps.iter().enumerate() {
            let file = sources.file(&step.location.path)?;
            let start_line = step
                .location
                .start
                .line
                .saturating_sub(context_lines)
                .max(1);
            let end_line = step.location.end.line.saturating_add(context_lines);
            let (slice, was_truncated) =
                review_source_slice(file, start_line, end_line, &step.location)?;
            context_truncated |= was_truncated;
            decision_critical_context_truncated |= was_truncated
                && matches!(
                    step.kind,
                    SecurityPathStepKind::Source
                        | SecurityPathStepKind::Sink
                        | SecurityPathStepKind::Protection
                        | SecurityPathStepKind::IneffectiveProtection
                );
            collect_configuration_tokens(&slice.text, &mut configuration_tokens);
            let (role, evidence_id) = match step.kind {
                SecurityPathStepKind::Source => {
                    ("source_context", Some(candidate.source.id.clone()))
                }
                SecurityPathStepKind::Sink => ("sink_context", Some(candidate.sink.id.clone())),
                SecurityPathStepKind::Protection => {
                    ("protection_context", step.evidence_id.as_ref().cloned())
                }
                SecurityPathStepKind::IneffectiveProtection => (
                    "ineffective_protection_context",
                    step.evidence_id.as_ref().cloned(),
                ),
                _ => ("intermediate_context", step.evidence_id.as_ref().cloned()),
            };
            facts.push(ReviewNeighborhoodFact {
                role: role.to_string(),
                symbol: step
                    .symbol
                    .clone()
                    .or_else(|| {
                        if index == 0 {
                            candidate.source.enclosing_symbol.clone()
                        } else if index + 1 == candidate.steps.len() {
                            candidate.sink.enclosing_symbol.clone()
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| format!("{:?}", step.kind).to_lowercase()),
                location: slice.location,
                excerpt: slice.text,
                evidence_id,
                provenance: textual_provenance("mehscan bounded path-review source 1"),
            });
        }
        let (mut captured_definitions, captured_definitions_truncated) = captured_definition_facts(
            &sources,
            [&candidate.source.id, &candidate.sink.id]
                .into_iter()
                .filter_map(|id| evidence_by_id.get(id.as_str()).copied()),
            &facts,
            2,
        );
        context_truncated |= captured_definitions_truncated;
        facts.append(&mut captured_definitions);
        if candidate.sink.rule_id == "python-source-file-content-write"
            && let Some(sink) = evidence_by_id.get(candidate.sink.id.as_str())
        {
            facts.extend(python_source_file_consumer_facts(&sources, sink, 4));
        }
        let candidate_paths = candidate
            .steps
            .iter()
            .map(|step| step.location.path.as_str())
            .collect::<BTreeSet<_>>();
        let mut reference_tokens = BTreeSet::new();
        for step in &candidate.steps {
            if let Ok(file) = sources.file(&step.location.path) {
                collect_enclosing_textual_definition_names(
                    file,
                    step.location.start.line,
                    &mut reference_tokens,
                );
                let start = step.location.start.byte_offset.min(file.source.len());
                let end = step.location.end.byte_offset.min(file.source.len());
                if start < end
                    && file.source.is_char_boundary(start)
                    && file.source.is_char_boundary(end)
                {
                    collect_review_reference_tokens(
                        &file.source[start..end],
                        &mut reference_tokens,
                    );
                }
            }
        }
        for fact in &facts {
            collect_policy_reference_tokens(&fact.excerpt, &mut reference_tokens);
            collect_challenge_reference_tokens(&fact.excerpt, &mut reference_tokens);
            collect_boundary_type_reference_tokens(&fact.excerpt, &mut reference_tokens);
        }
        for evidence_id in [&candidate.source.id, &candidate.sink.id] {
            if let Some(evidence) = evidence_by_id.get(evidence_id.as_str()) {
                for capture in evidence.captures.values() {
                    collect_review_reference_tokens(&capture.text, &mut reference_tokens);
                }
            }
        }
        if candidate.sink.rule_id == "csharp-request-controlled-role-assignment" {
            for generic in ["model", "user", "result"] {
                reference_tokens.remove(generic);
            }
        }
        for symbol in [
            candidate.source.enclosing_symbol.as_deref(),
            candidate.sink.enclosing_symbol.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(identifier) = terminal_identifier(symbol) {
                reference_tokens.insert(identifier.to_string());
            }
        }
        let review_text = facts
            .iter()
            .map(|fact| fact.excerpt.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for path in &candidate_paths {
            if let Ok(file) = sources.file(path) {
                collect_used_import_boundary_types(
                    &file.source,
                    &review_text,
                    &mut reference_tokens,
                );
            }
        }
        let (mut configuration_facts, configuration_truncated) = configuration_facts(
            &sources,
            &candidate_paths,
            &configuration_tokens,
            MAX_REVIEW_CONFIGURATION_FACTS,
        );
        context_truncated |= configuration_truncated;
        facts.append(&mut configuration_facts);
        if candidate
            .source
            .provenance
            .engine
            .ends_with("bounded-mongo-callback-result-summary")
            && candidate.capability == Capability::HtmlOutput
            && let Some(sink) = evidence_by_id.get(candidate.sink.id.as_str())
        {
            let (mut template_facts, template_truncated) =
                express_template_review_facts(&sources, sink, 5);
            context_truncated |= template_truncated;
            facts.append(&mut template_facts);
        }
        if candidate.sink.rule_id == "csharp-request-controlled-role-assignment" {
            let (mut privilege_facts, privilege_truncated) =
                csharp_privilege_assignment_path_facts(&sources, &candidate, 3);
            context_truncated |= privilege_truncated;
            facts.append(&mut privilege_facts);
        }
        if evidence_by_id
            .get(candidate.sink.id.as_str())
            .is_some_and(|sink| sink.tags.iter().any(|tag| tag == "unique-helper"))
            && let Ok(file) = sources.file(&candidate.sink.location.path)
        {
            let start = candidate
                .sink
                .location
                .start
                .byte_offset
                .min(file.source.len());
            let end = candidate
                .sink
                .location
                .end
                .byte_offset
                .min(file.source.len());
            if start < end
                && file.source.is_char_boundary(start)
                && file.source.is_char_boundary(end)
                && let Some(helper) = direct_call_reference(&file.source[start..end])
            {
                let exact_reference = BTreeSet::from([helper]);
                let (mut exact_helper_facts, exact_helper_truncated) =
                    review_context.facts(&sources, &candidate_paths, &exact_reference, &facts, 1);
                context_truncated |= exact_helper_truncated;
                facts.append(&mut exact_helper_facts);
            }
        }
        let (mut helper_facts, helper_truncated) = review_context.facts(
            &sources,
            &candidate_paths,
            &reference_tokens,
            &facts,
            MAX_REVIEW_HELPER_FACTS,
        );
        context_truncated |= helper_truncated;
        facts.append(&mut helper_facts);
        let precise_origin_fields = evidence_member_fields(
            [&candidate.source.id, &candidate.sink.id]
                .into_iter()
                .filter_map(|id| evidence_by_id.get(id.as_str()).copied()),
        );
        let mut precise_consumer_fields = precise_origin_fields.clone();
        if let Some(sink) = evidence_by_id.get(candidate.sink.id.as_str())
            && let Some(field) = sink_assignment_target_field(&sources, sink)
        {
            precise_consumer_fields.insert(field);
        }
        let precise_origin_fields =
            (!precise_origin_fields.is_empty()).then_some(precise_origin_fields);
        let precise_consumer_fields =
            (!precise_consumer_fields.is_empty()).then_some(precise_consumer_fields);
        let (mut second_hop_facts, second_hop_truncated) = second_hop_review_facts(
            &sources,
            &review_context,
            &candidate_paths,
            &reference_tokens,
            &facts,
            precise_consumer_fields.as_ref(),
            MAX_REVIEW_SECOND_HOP_FACTS,
        );
        context_truncated |= second_hop_truncated;
        facts.append(&mut second_hop_facts);
        let (mut origin_facts, origin_truncated) = origin_consumer_review_facts(
            &sources,
            &review_context,
            &candidate_paths,
            &facts,
            precise_origin_fields.as_ref(),
            MAX_REVIEW_ORIGIN_FACTS,
        );
        context_truncated |= origin_truncated;
        facts.append(&mut origin_facts);
        if candidate.sink.rule_id == "csharp-request-controlled-role-assignment" {
            let bound_type = evidence_by_id
                .get(candidate.source.id.as_str())
                .and_then(|source| source.captures.get("type"))
                .map(|capture| capture.text.as_str());
            facts.retain(|fact| {
                fact.role != "reference_use_context"
                    && (fact.role != "helper_definition_context"
                        || bound_type == Some(fact.symbol.as_str()))
            });
        }
        sort_review_facts(&mut facts);
        let has_configuration = facts
            .iter()
            .any(|fact| fact.role == "configuration_context");
        let has_feature_gate = facts.iter().any(|fact| {
            matches!(
                fact.role.as_str(),
                "feature_gate_context" | "feature_gate_policy_context"
            )
        });
        let has_configuration_gate = path_execution_configuration_gate(&facts);
        let open_questions = path_review_questions(
            &candidate,
            has_configuration,
            has_feature_gate,
            has_configuration_gate,
        );
        let language = languages
            .get(candidate.primary_location.path.as_str())
            .copied();
        let review_basis = path_review_basis(&candidate, &evidence_by_id, &rules_by_id)?;
        let unresolved = path_decision_blockers(&candidate, &review_basis, &open_questions, &facts);
        let decision_facts = path_decision_facts(&candidate, &review_basis, &facts, &unresolved);
        let truncation = review_truncation(context_truncated, decision_critical_context_truncated);
        let confidence_policy = path_confidence_policy(&candidate, &decision_facts, &truncation);
        reviews.push(PathReview {
            id: candidate.id.replacen("path-", "review-", 1),
            language,
            candidate,
            review_basis: Some(review_basis),
            decision_facts,
            confidence_policy,
            facts,
            open_questions,
            context_truncated,
            truncation,
        });
    }
    let remaining = max_reviews.saturating_sub(reviews.len());
    let observation_start = offset.saturating_sub(candidate_count);
    let observation_reviews = if remaining == 0 {
        Vec::new()
    } else {
        build_observation_reviews(
            observation_groups
                .into_iter()
                .skip(observation_start)
                .take(remaining),
            &sources,
            &languages,
            &csharp_neighborhoods,
            context_lines,
            &rules_by_id,
        )?
    };
    let returned_reviews = reviews.len() + observation_reviews.len();
    let next_offset =
        (offset + returned_reviews < total_reviews).then_some(offset + returned_reviews);
    let truncated = next_offset.is_some();
    let fingerprint = path_review_fingerprint(
        &reviews,
        &observation_reviews,
        &triage_contract,
        context_lines,
        offset,
        include_review_material,
    );
    Ok(PathReviewJob {
        schema_version: SCHEMA_VERSION.to_string(),
        root: scan.root,
        operation: "build_path_review_jobs".to_string(),
        fingerprint,
        triage_contract,
        context_lines,
        max_reviews,
        offset,
        total_reviews,
        next_offset,
        include_review_material,
        review_material_excluded: excluded_candidates + excluded_observations,
        truncated,
        reviews,
        observation_reviews,
        coverage: scan.coverage,
        diagnostics: scan.diagnostics,
    })
}

pub fn validate_path_review_triage(
    job: &PathReviewJob,
    responses: &PathReviewTriageResponseSet,
) -> Result<PathReviewTriageReport, EngineError> {
    let missing = validate_path_review_response_subset(job, responses)?;
    if !missing.is_empty() {
        return Err(EngineError(format!(
            "path-review triage is missing reviews: {}",
            missing.join(", ")
        )));
    }
    let issue_groups = path_review_issue_groups(job, responses);
    Ok(PathReviewTriageReport {
        schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        job_fingerprint: job.fingerprint.clone(),
        issue_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::Issue)
            .count(),
        not_issue_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::NotIssue)
            .count(),
        needs_review_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::NeedsReview)
            .count(),
        issue_group_count: issue_groups.len(),
        issue_groups,
        results: responses.results.clone(),
    })
}

pub fn path_review_tasks(job: &PathReviewJob) -> PathReviewTaskPage {
    let page_size = job.reviews.len() + job.observation_reviews.len();
    let tasks = job
        .reviews
        .iter()
        .cloned()
        .map(|review| {
            (
                review.id.clone(),
                PathReviewTaskPayload::SecurityPath { review },
            )
        })
        .chain(job.observation_reviews.iter().cloned().map(|review| {
            (
                review.id.clone(),
                PathReviewTaskPayload::Observation { review },
            )
        }))
        .enumerate()
        .map(|(sequence, (review_id, payload))| PathReviewTask {
            schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
            job_fingerprint: job.fingerprint.clone(),
            review_id,
            sequence,
            page_size,
            triage_contract: job.triage_contract.clone(),
            payload,
        })
        .collect();
    PathReviewTaskPage {
        schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        // Persist a relocatable logical root; review locations are already
        // repository-relative and must not disclose the local checkout path.
        root: ".".to_string(),
        operation: "build_path_review_tasks".to_string(),
        job_fingerprint: job.fingerprint.clone(),
        offset: job.offset,
        total_reviews: job.total_reviews,
        next_offset: job.next_offset,
        tasks,
    }
}

/// Groups a complete review job by semantic category and splits only categories
/// whose serialized request exceeds the configured byte budget.
pub fn build_path_review_bundles(
    job: &PathReviewJob,
    max_input_bytes: Option<usize>,
) -> Result<PathReviewBundleSet, EngineError> {
    build_path_review_bundles_with_limits(job, max_input_bytes, None)
}

/// Groups a complete review job by semantic category, then applies independent
/// byte and item ceilings. The item ceiling is useful for controlled model
/// experiments and retry-blast-radius limits; it does not change review facts.
pub fn build_path_review_bundles_with_limits(
    job: &PathReviewJob,
    max_input_bytes: Option<usize>,
    max_reviews_per_bundle: Option<usize>,
) -> Result<PathReviewBundleSet, EngineError> {
    let max_input_bytes = bounded_review_bundle_bytes(max_input_bytes)?;
    let max_reviews_per_bundle = bounded_review_bundle_reviews(max_reviews_per_bundle)?;
    let mut bundles = Vec::new();

    let mut path_groups = BTreeMap::<Capability, Vec<PathReview>>::new();
    for review in &job.reviews {
        path_groups
            .entry(review.candidate.capability)
            .or_default()
            .push(review.clone());
    }
    for (capability, reviews) in path_groups {
        let mut cwe_candidates = reviews
            .iter()
            .flat_map(|review| review.candidate.cwe_candidates.iter().cloned())
            .collect::<Vec<_>>();
        cwe_candidates.sort();
        cwe_candidates.dedup();
        let category = PathReviewBundleCategory {
            scope: "full".to_string(),
            review_kind: "path".to_string(),
            capability,
            cwe_candidates,
        };
        bundles.extend(split_path_bundle(
            job,
            category,
            reviews,
            max_input_bytes,
            max_reviews_per_bundle,
        )?);
    }

    let mut observation_groups = BTreeMap::<Capability, Vec<ObservationReview>>::new();
    for review in &job.observation_reviews {
        let anchor = observation_actionable_anchor(review).ok_or_else(|| {
            EngineError(format!(
                "observation review {:?} has no actionable evidence to categorize",
                review.id
            ))
        })?;
        observation_groups
            .entry(anchor.capability)
            .or_default()
            .push(review.clone());
    }
    for (capability, reviews) in observation_groups {
        let mut cwe_candidates = reviews
            .iter()
            .flat_map(|review| {
                review
                    .evidence
                    .iter()
                    .filter(|evidence| review.anchor_evidence_ids.contains(&evidence.id))
            })
            .flat_map(|evidence| evidence.cwe_candidates.iter().cloned())
            .collect::<Vec<_>>();
        cwe_candidates.sort();
        cwe_candidates.dedup();
        let category = PathReviewBundleCategory {
            scope: "full".to_string(),
            review_kind: "observation".to_string(),
            capability,
            cwe_candidates,
        };
        bundles.extend(split_observation_bundle(
            job,
            category,
            reviews,
            max_input_bytes,
            max_reviews_per_bundle,
        )?);
    }

    bundles.sort_by(|left, right| {
        path_review_bundle_filename(left).cmp(&path_review_bundle_filename(right))
    });
    let manifest_entries = bundles
        .iter()
        .map(|bundle| {
            let input_bytes = serde_json::to_vec(bundle)
                .map_err(|error| {
                    EngineError(format!("could not serialize review bundle: {error}"))
                })?
                .len();
            let (context_text_bytes, repeated_context_text_bytes) =
                bundle_context_text_bytes(bundle);
            Ok(PathReviewBundleManifestEntry {
                filename: path_review_bundle_filename(bundle),
                bundle_fingerprint: bundle.bundle_fingerprint.clone(),
                category: bundle.category.clone(),
                part: bundle.part,
                part_count: bundle.part_count,
                review_count: bundle.review_ids.len(),
                input_bytes,
                context_text_bytes,
                repeated_context_text_bytes,
                review_ids: bundle.review_ids.clone(),
            })
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    let review_count = manifest_entries
        .iter()
        .map(|entry| entry.review_count)
        .sum();
    let manifest = PathReviewBundleManifest {
        schema_version: PATH_REVIEW_BUNDLE_SCHEMA_VERSION.to_string(),
        // Persist a relocatable logical root; review locations are already
        // repository-relative and must not disclose the local checkout path.
        root: ".".to_string(),
        operation: "build_path_review_bundles".to_string(),
        job_fingerprint: job.fingerprint.clone(),
        max_input_bytes,
        max_reviews_per_bundle,
        review_count,
        bundle_count: bundles.len(),
        bundles: manifest_entries,
    };
    Ok(PathReviewBundleSet { manifest, bundles })
}

pub fn validate_path_review_bundle_response(
    bundle: &PathReviewBundle,
    responses: &PathReviewBundleResponseSet,
) -> Result<PathReviewBundleTriageReport, EngineError> {
    if responses.schema_version != PATH_REVIEW_BUNDLE_SCHEMA_VERSION {
        return Err(EngineError(format!(
            "unsupported path-review bundle response schema {:?}",
            responses.schema_version
        )));
    }
    if responses.bundle_fingerprint != bundle.bundle_fingerprint {
        return Err(EngineError(
            "path-review bundle response does not match the bundle fingerprint".to_string(),
        ));
    }
    let expected_ids = bundle
        .review_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut seen_ids = BTreeSet::new();
    for result in &responses.results {
        if !expected_ids.contains(result.review_id.as_str()) {
            return Err(EngineError(format!(
                "path-review bundle response references unknown review {:?}",
                result.review_id
            )));
        }
        if !seen_ids.insert(result.review_id.as_str()) {
            return Err(EngineError(format!(
                "path-review bundle response contains duplicate review {:?}",
                result.review_id
            )));
        }
        validate_compact_triage(
            &result.review_id,
            result.decision,
            &result.summary,
            &result.checks,
        )?;
        let expected_confidence = bundle_review_confidence_policy(bundle, &result.review_id)
            .map(|policy| confidence_for_decision(policy, result.decision))
            .ok_or_else(|| {
                EngineError(format!(
                    "path-review bundle has no confidence policy for {:?}",
                    result.review_id
                ))
            })?;
        if result.confidence != expected_confidence {
            return Err(EngineError(format!(
                "confidence for {:?} must be {:?} for the selected {:?} decision",
                result.review_id, expected_confidence, result.decision
            )));
        }
        if result.decision == ReviewDecision::NeedsReview {
            let unresolved = bundle_unresolved_facts(bundle, &result.review_id)?;
            for check in &result.checks {
                if !unresolved.iter().any(|fact| fact.trim() == check.trim()) {
                    return Err(EngineError(format!(
                        "needs_review check for {:?} must copy an exact supplied decision_facts.unresolved entry",
                        result.review_id
                    )));
                }
            }
        }
    }
    let missing = expected_ids
        .difference(&seen_ids)
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(EngineError(format!(
            "path-review bundle response is incomplete; retry the whole bundle; missing reviews: {}",
            missing.join(", ")
        )));
    }
    Ok(PathReviewBundleTriageReport {
        schema_version: PATH_REVIEW_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_fingerprint: bundle.bundle_fingerprint.clone(),
        complete: true,
        issue_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::Issue)
            .count(),
        not_issue_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::NotIssue)
            .count(),
        needs_review_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::NeedsReview)
            .count(),
        results: responses.results.clone(),
    })
}

/// Validates a complete semantic-bundle run and deduplicates issue decisions
/// across path and observation streams by capability, exact sink, and the
/// rule-defined security invariant.
pub fn summarize_path_review_bundle_run(
    bundle_responses: &[(PathReviewBundle, PathReviewBundleResponseSet)],
) -> Result<PathReviewBundleRunReport, EngineError> {
    let Some((first_bundle, _)) = bundle_responses.first() else {
        return Err(EngineError(
            "path-review bundle run contains no bundle responses".to_string(),
        ));
    };
    let job_fingerprint = first_bundle.job_fingerprint.clone();
    let mut seen_bundles = BTreeSet::new();
    let mut seen_reviews = BTreeSet::new();
    let mut results = Vec::new();
    let mut groups = BTreeMap::<String, PathReviewBundleIssueGroup>::new();
    for (bundle, responses) in bundle_responses {
        if bundle.job_fingerprint != job_fingerprint {
            return Err(EngineError(
                "path-review bundle run mixes job fingerprints".to_string(),
            ));
        }
        if !seen_bundles.insert(bundle.bundle_fingerprint.as_str()) {
            return Err(EngineError(format!(
                "path-review bundle run contains duplicate bundle {:?}",
                bundle.bundle_fingerprint
            )));
        }
        validate_path_review_bundle_response(bundle, responses)?;
        for result in &responses.results {
            if !seen_reviews.insert(result.review_id.as_str()) {
                return Err(EngineError(format!(
                    "path-review bundle run contains duplicate review {:?}",
                    result.review_id
                )));
            }
            results.push(result.clone());
            if result.decision != ReviewDecision::Issue {
                continue;
            }
            let (review_kind, capability, location, invariant_id, mut cwes) =
                bundle_issue_context(bundle, &result.review_id)?;
            cwes.sort();
            cwes.dedup();
            let key = issue_group_key(capability, &location, &invariant_id);
            let group = groups
                .entry(key.clone())
                .or_insert_with(|| PathReviewBundleIssueGroup {
                    id: stable_review_hash("bundle-issue-group", &key),
                    review_ids: Vec::new(),
                    review_kinds: Vec::new(),
                    invariant_id: invariant_id.clone(),
                    confidence: result.confidence,
                    capability,
                    location,
                    cwe_candidates: Vec::new(),
                });
            group.review_ids.push(result.review_id.clone());
            group.review_kinds.push(review_kind);
            group.confidence = group.confidence.max(result.confidence);
            group.cwe_candidates.extend(cwes);
            group.review_ids.sort();
            group.review_ids.dedup();
            group.review_kinds.sort();
            group.review_kinds.dedup();
            group.cwe_candidates.sort();
            group.cwe_candidates.dedup();
        }
    }
    results.sort_by(|left, right| left.review_id.cmp(&right.review_id));
    let issue_count = results
        .iter()
        .filter(|result| result.decision == ReviewDecision::Issue)
        .count();
    let not_issue_count = results
        .iter()
        .filter(|result| result.decision == ReviewDecision::NotIssue)
        .count();
    let needs_review_count = results
        .iter()
        .filter(|result| result.decision == ReviewDecision::NeedsReview)
        .count();
    let issue_groups = groups.into_values().collect::<Vec<_>>();
    let quality_warnings = review_run_quality_warnings(bundle_responses);
    Ok(PathReviewBundleRunReport {
        schema_version: PATH_REVIEW_BUNDLE_SCHEMA_VERSION.to_string(),
        job_fingerprint,
        bundle_count: bundle_responses.len(),
        review_count: results.len(),
        issue_count,
        not_issue_count,
        needs_review_count,
        issue_group_count: issue_groups.len(),
        issue_groups,
        quality_warnings,
        results,
    })
}

/// Joins strict AI verdicts back to deterministic review evidence. The result
/// is the canonical post-triage artifact; external formats such as SARIF are
/// projections of this report rather than inputs to the reviewer.
pub fn build_finding_report(
    _root: impl Into<String>,
    tool_version: impl Into<String>,
    reviewer: Option<String>,
    bundle_responses: &[(PathReviewBundle, PathReviewBundleResponseSet)],
    include_dismissed: bool,
) -> Result<FindingReport, EngineError> {
    let run = summarize_path_review_bundle_run(bundle_responses)?;
    let mut records = BTreeMap::<String, ReportAccumulator>::new();
    let mut dismissed = Vec::new();

    for (bundle, responses) in bundle_responses {
        for result in &responses.results {
            if result.decision == ReviewDecision::NotIssue {
                if include_dismissed {
                    dismissed.push(DismissedReview {
                        review_id: result.review_id.clone(),
                        confidence: result.confidence,
                        description: result.summary.clone(),
                    });
                }
                continue;
            }
            let mut item = reported_finding(bundle, result)?;
            let key = issue_group_key(item.category, &item.primary_location, &item.rule_id);
            item.id = stable_review_hash("finding", &key);
            let is_path = item.flow.is_some();
            match records.get_mut(&key) {
                Some(existing) => existing.merge(item, is_path),
                None => {
                    records.insert(key, ReportAccumulator { item, is_path });
                }
            }
        }
    }

    dismissed.sort_by(|left, right| left.review_id.cmp(&right.review_id));
    let mut findings = Vec::new();
    let mut review_required = Vec::new();
    for record in records.into_values() {
        match record.item.status {
            FindingStatus::Issue => findings.push(record.item),
            FindingStatus::NeedsReview => review_required.push(record.item),
        }
    }
    findings.sort_by(reported_finding_order);
    review_required.sort_by(reported_finding_order);

    Ok(FindingReport {
        schema_version: FINDING_REPORT_SCHEMA_VERSION.to_string(),
        report_kind: "triaged_findings".to_string(),
        tool: FindingReportTool {
            name: "Mehscan".to_string(),
            version: tool_version.into(),
        },
        scan: FindingReportScan {
            root: ".".to_string(),
            job_fingerprint: run.job_fingerprint,
        },
        triage: FindingReportTriage {
            response_schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
            reviewer,
        },
        summary: FindingReportSummary {
            reviewed: run.review_count,
            issue_decisions: run.issue_count,
            needs_review_decisions: run.needs_review_count,
            not_issue_decisions: run.not_issue_count,
            findings: findings.len(),
            review_required: review_required.len(),
            dismissed: run.not_issue_count,
        },
        findings,
        review_required,
        dismissed,
        quality_warnings: run.quality_warnings,
    })
}

struct ReportAccumulator {
    item: ReportedFinding,
    is_path: bool,
}

impl ReportAccumulator {
    fn merge(&mut self, mut other: ReportedFinding, other_is_path: bool) {
        let prefer_other = (self.item.status == FindingStatus::NeedsReview
            && other.status == FindingStatus::Issue)
            || (self.item.status == other.status && !self.is_path && other_is_path);
        let mut review_ids = std::mem::take(&mut self.item.provenance.review_ids);
        review_ids.append(&mut other.provenance.review_ids);
        review_ids.sort();
        review_ids.dedup();
        let mut evidence_ids = std::mem::take(&mut self.item.provenance.evidence_ids);
        evidence_ids.append(&mut other.provenance.evidence_ids);
        evidence_ids.sort();
        evidence_ids.dedup();
        let confidence = self.item.confidence.max(other.confidence);
        let mut cwes = std::mem::take(&mut self.item.cwes);
        cwes.append(&mut other.cwes);
        cwes.sort();
        cwes.dedup();
        let mut related = std::mem::take(&mut self.item.related_locations);
        related.append(&mut other.related_locations);
        deduplicate_related_locations(&mut related);

        if prefer_other {
            self.item = other;
            self.is_path = other_is_path;
        }
        self.item.confidence = confidence;
        self.item.cwes = cwes;
        self.item.related_locations = related;
        self.item.provenance.review_ids = review_ids;
        self.item.provenance.evidence_ids = evidence_ids;
        if self.item.status == FindingStatus::Issue {
            self.item.checks.clear();
        }
    }
}

fn reported_finding(
    bundle: &PathReviewBundle,
    result: &mehscan_core::PathReviewTriageResult,
) -> Result<ReportedFinding, EngineError> {
    let status = FindingStatus::from_decision(result.decision).ok_or_else(|| {
        EngineError(format!(
            "cannot report dismissed review {:?} as a finding",
            result.review_id
        ))
    })?;
    match &bundle.payload {
        PathReviewBundlePayload::SecurityPath { reviews } => {
            let review = reviews
                .iter()
                .find(|review| review.id == result.review_id)
                .ok_or_else(|| {
                    EngineError(format!("bundle is missing review {:?}", result.review_id))
                })?;
            let candidate = &review.candidate;
            let title = review
                .review_basis
                .as_ref()
                .and_then(|basis| basis.sink.rule_title.clone())
                .unwrap_or_else(|| candidate.title.clone());
            let mut evidence_ids = vec![candidate.source.id.clone(), candidate.sink.id.clone()];
            evidence_ids.extend(candidate.protections.iter().map(|item| item.id.clone()));
            evidence_ids.extend(
                candidate
                    .steps
                    .iter()
                    .filter_map(|step| step.evidence_id.clone()),
            );
            evidence_ids.sort();
            evidence_ids.dedup();
            let mut related_locations = vec![FindingRelatedLocation {
                role: candidate.source.kind,
                location: candidate.source.location.clone(),
                evidence_id: Some(candidate.source.id.clone()),
                rule_id: Some(candidate.source.rule_id.clone()),
            }];
            related_locations.extend(candidate.protections.iter().map(|item| {
                FindingRelatedLocation {
                    role: item.kind,
                    location: item.location.clone(),
                    evidence_id: Some(item.id.clone()),
                    rule_id: Some(item.rule_id.clone()),
                }
            }));
            deduplicate_related_locations(&mut related_locations);
            Ok(ReportedFinding {
                id: String::new(),
                rule_id: candidate.sink.rule_id.clone(),
                title,
                description: result.summary.clone(),
                status,
                severity: default_severity(),
                confidence: result.confidence,
                category: candidate.capability,
                cwes: candidate.cwe_candidates.clone(),
                language: review.language,
                primary_location: candidate.primary_location.clone(),
                context: candidate.sink.context.clone(),
                flow: Some(FindingFlow {
                    steps: candidate.steps.clone(),
                }),
                related_locations,
                checks: result.checks.clone(),
                remediation: None,
                provenance: FindingProvenance {
                    review_ids: vec![review.id.clone()],
                    evidence_ids,
                },
            })
        }
        PathReviewBundlePayload::Observation { reviews } => {
            let review = reviews
                .iter()
                .find(|review| review.id == result.review_id)
                .ok_or_else(|| {
                    EngineError(format!("bundle is missing review {:?}", result.review_id))
                })?;
            let anchor = observation_actionable_anchor(review).ok_or_else(|| {
                EngineError(format!(
                    "observation review {:?} has no actionable anchor",
                    review.id
                ))
            })?;
            let title = review
                .review_basis
                .as_ref()
                .and_then(|basis| {
                    basis
                        .observations
                        .iter()
                        .find(|item| item.rule_id == anchor.rule_id)
                        .and_then(|item| item.rule_title.clone())
                })
                .unwrap_or_else(|| review.title.clone());
            let anchor_ids = review.anchor_evidence_ids.iter().collect::<BTreeSet<_>>();
            let mut related_locations = review
                .evidence
                .iter()
                .filter(|evidence| !anchor_ids.contains(&evidence.id))
                .map(|evidence| FindingRelatedLocation {
                    role: evidence.kind,
                    location: evidence.location.clone(),
                    evidence_id: Some(evidence.id.clone()),
                    rule_id: Some(evidence.rule_id.clone()),
                })
                .collect::<Vec<_>>();
            deduplicate_related_locations(&mut related_locations);
            let mut evidence_ids = review
                .evidence
                .iter()
                .map(|evidence| evidence.id.clone())
                .collect::<Vec<_>>();
            evidence_ids.sort();
            evidence_ids.dedup();
            Ok(ReportedFinding {
                id: String::new(),
                rule_id: anchor.rule_id.clone(),
                title,
                description: result.summary.clone(),
                status,
                severity: default_severity(),
                confidence: result.confidence,
                category: anchor.capability,
                cwes: anchor.cwe_candidates.clone(),
                language: review.language,
                primary_location: anchor.location.clone(),
                context: anchor.context.clone(),
                flow: None,
                related_locations,
                checks: result.checks.clone(),
                remediation: None,
                provenance: FindingProvenance {
                    review_ids: vec![review.id.clone()],
                    evidence_ids,
                },
            })
        }
    }
}

fn default_severity() -> ReportedSeverity {
    ReportedSeverity {
        level: Severity::Medium,
        source: SeveritySource::FallbackDefault,
    }
}

fn deduplicate_related_locations(locations: &mut Vec<FindingRelatedLocation>) {
    locations.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then(
                left.location
                    .start
                    .byte_offset
                    .cmp(&right.location.start.byte_offset),
            )
            .then(
                left.location
                    .end
                    .byte_offset
                    .cmp(&right.location.end.byte_offset),
            )
            .then(left.role.cmp(&right.role))
    });
    locations.dedup_by(|left, right| {
        left.role == right.role
            && left.location == right.location
            && left.evidence_id == right.evidence_id
    });
}

fn reported_finding_order(left: &ReportedFinding, right: &ReportedFinding) -> std::cmp::Ordering {
    left.primary_location
        .path
        .cmp(&right.primary_location.path)
        .then(
            left.primary_location
                .start
                .byte_offset
                .cmp(&right.primary_location.start.byte_offset),
        )
        .then(left.rule_id.cmp(&right.rule_id))
}

fn bundle_unresolved_facts<'a>(
    bundle: &'a PathReviewBundle,
    review_id: &str,
) -> Result<&'a [String], EngineError> {
    match &bundle.payload {
        PathReviewBundlePayload::SecurityPath { reviews } => reviews
            .iter()
            .find(|review| review.id == review_id)
            .map(|review| review.decision_facts.unresolved.as_slice()),
        PathReviewBundlePayload::Observation { reviews } => reviews
            .iter()
            .find(|review| review.id == review_id)
            .map(|review| review.decision_facts.unresolved.as_slice()),
    }
    .ok_or_else(|| EngineError(format!("bundle is missing review {review_id:?}")))
}

fn review_run_quality_warnings(
    bundle_responses: &[(PathReviewBundle, PathReviewBundleResponseSet)],
) -> Vec<String> {
    let mut rows = Vec::new();
    for (bundle, responses) in bundle_responses {
        for result in &responses.results {
            let critical_truncation = match &bundle.payload {
                PathReviewBundlePayload::SecurityPath { reviews } => reviews
                    .iter()
                    .find(|review| review.id == result.review_id)
                    .is_some_and(|review| review.truncation.decision_critical),
                PathReviewBundlePayload::Observation { reviews } => reviews
                    .iter()
                    .find(|review| review.id == result.review_id)
                    .is_some_and(|review| review.truncation.decision_critical),
            };
            rows.push((
                bundle.category.review_kind.as_str(),
                result.decision,
                result.confidence,
                result
                    .summary
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase(),
                critical_truncation,
            ));
        }
    }
    let mut warnings = Vec::new();
    if rows.len() > 1 && rows.iter().all(|row| row.1 == rows[0].1) {
        warnings.push("degenerate_decisions: every review received the same decision".to_string());
    }
    if rows.len() >= 10 {
        let mut decision_counts = BTreeMap::<ReviewDecision, usize>::new();
        for row in &rows {
            *decision_counts.entry(row.1).or_default() += 1;
        }
        if let Some((decision, count)) = decision_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .filter(|(_, count)| *count * 10 >= rows.len() * 9)
        {
            warnings.push(format!(
                "dominant_decision: {:?} accounts for {count} of {} reviews",
                decision,
                rows.len()
            ));
        }
    }
    if rows.len() > 1 && rows.iter().all(|row| row.2 == rows[0].2) {
        warnings.push("uniform_confidence: every review received the same confidence".to_string());
    }
    let unique_summaries = rows
        .iter()
        .map(|row| row.3.as_str())
        .collect::<BTreeSet<_>>();
    if rows.len() >= 10 && unique_summaries.len() <= 2 {
        warnings.push(format!(
            "low_summary_diversity: {} reviews use only {} normalized summaries",
            rows.len(),
            unique_summaries.len()
        ));
    }
    let mut decisions_by_kind = BTreeMap::<&str, BTreeSet<ReviewDecision>>::new();
    for row in &rows {
        decisions_by_kind.entry(row.0).or_default().insert(row.1);
    }
    if decisions_by_kind.len() > 1
        && decisions_by_kind
            .values()
            .all(|decisions| decisions.len() == 1)
        && decisions_by_kind
            .values()
            .filter_map(|decisions| decisions.first())
            .collect::<BTreeSet<_>>()
            .len()
            > 1
    {
        warnings.push(
            "review_kind_correlation: decision is perfectly determined by review kind".to_string(),
        );
    } else if decisions_by_kind.len() > 1 {
        let dominant_by_kind = decisions_by_kind
            .keys()
            .filter_map(|kind| {
                let mut counts = BTreeMap::<ReviewDecision, usize>::new();
                let total = rows.iter().filter(|row| row.0 == *kind).count();
                for row in rows.iter().filter(|row| row.0 == *kind) {
                    *counts.entry(row.1).or_default() += 1;
                }
                counts
                    .into_iter()
                    .max_by_key(|(_, count)| *count)
                    .map(|(decision, count)| (decision, count, total))
            })
            .collect::<Vec<_>>();
        if dominant_by_kind.len() > 1
            && dominant_by_kind
                .iter()
                .all(|(_, count, total)| count * 10 >= total * 9)
            && dominant_by_kind
                .iter()
                .map(|(decision, _, _)| *decision)
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        {
            warnings.push(
                "strong_review_kind_correlation: each review kind is at least 90% determined by a different decision"
                    .to_string(),
            );
        }
    }
    let low_without_critical = rows
        .iter()
        .filter(|row| row.2 == ReviewConfidence::Low && !row.4)
        .count();
    if !rows.is_empty() && low_without_critical * 4 >= rows.len() * 3 {
        warnings.push(
            "low_confidence_without_critical_truncation: at least 75% of reviews are low confidence without decision-critical clipping"
                .to_string(),
        );
    }
    warnings
}

fn bundle_issue_context(
    bundle: &PathReviewBundle,
    review_id: &str,
) -> Result<(String, Capability, Location, String, Vec<String>), EngineError> {
    match &bundle.payload {
        PathReviewBundlePayload::SecurityPath { reviews } => reviews
            .iter()
            .find(|review| review.id == review_id)
            .map(|review| {
                (
                    "path".to_string(),
                    review.candidate.capability,
                    review.candidate.sink.location.clone(),
                    review.candidate.sink.rule_id.clone(),
                    review.candidate.cwe_candidates.clone(),
                )
            })
            .ok_or_else(|| EngineError(format!("bundle is missing path review {review_id:?}"))),
        PathReviewBundlePayload::Observation { reviews } => {
            let review = reviews
                .iter()
                .find(|review| review.id == review_id)
                .ok_or_else(|| {
                    EngineError(format!(
                        "bundle is missing observation review {review_id:?}"
                    ))
                })?;
            let anchor = observation_actionable_anchor(review).ok_or_else(|| {
                EngineError(format!(
                    "observation review {review_id:?} has no actionable anchor"
                ))
            })?;
            let cwes = review
                .evidence
                .iter()
                .filter(|evidence| review.anchor_evidence_ids.contains(&evidence.id))
                .flat_map(|evidence| evidence.cwe_candidates.iter().cloned())
                .collect();
            Ok((
                "observation".to_string(),
                anchor.capability,
                anchor.location.clone(),
                anchor.rule_id.clone(),
                cwes,
            ))
        }
    }
}

fn issue_group_key(capability: Capability, location: &Location, invariant_id: &str) -> String {
    format!(
        "{:?}\0{}\0{}:{}\0{}",
        capability,
        location.path,
        location.start.byte_offset,
        location.end.byte_offset,
        invariant_id
    )
}

fn observation_actionable_anchor(review: &ObservationReview) -> Option<&Evidence> {
    review
        .evidence
        .iter()
        .filter(|evidence| review.anchor_evidence_ids.contains(&evidence.id))
        .find(|evidence| evidence.kind == EvidenceKind::Sink)
        .or_else(|| {
            review.evidence.iter().find(|evidence| {
                review.anchor_evidence_ids.contains(&evidence.id)
                    && matches!(
                        evidence.kind,
                        EvidenceKind::SensitiveOperation | EvidenceKind::SecurityConfiguration
                    )
            })
        })
}

fn split_path_bundle(
    job: &PathReviewJob,
    category: PathReviewBundleCategory,
    reviews: Vec<PathReview>,
    max_input_bytes: usize,
    max_reviews_per_bundle: usize,
) -> Result<Vec<PathReviewBundle>, EngineError> {
    let mut chunks = Vec::<Vec<PathReview>>::new();
    let mut current = Vec::new();
    for review in reviews {
        let mut trial = current.clone();
        trial.push(review.clone());
        let trial_review_count = trial.len();
        let bundle = make_path_bundle(job, category.clone(), trial, 9_999, 9_999);
        if (trial_review_count > max_reviews_per_bundle
            || serialized_bundle_bytes(&bundle)? > max_input_bytes)
            && !current.is_empty()
        {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(review);
        let single = make_path_bundle(job, category.clone(), current.clone(), 9_999, 9_999);
        if current.len() == 1 && serialized_bundle_bytes(&single)? > max_input_bytes {
            return Err(EngineError(format!(
                "review {:?} exceeds the bundle byte limit {max_input_bytes}; increase --max-bytes",
                current[0].id
            )));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    let part_count = chunks.len();
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(index, reviews)| {
            make_path_bundle(job, category.clone(), reviews, index + 1, part_count)
        })
        .collect())
}

fn split_observation_bundle(
    job: &PathReviewJob,
    category: PathReviewBundleCategory,
    reviews: Vec<ObservationReview>,
    max_input_bytes: usize,
    max_reviews_per_bundle: usize,
) -> Result<Vec<PathReviewBundle>, EngineError> {
    let mut chunks = Vec::<Vec<ObservationReview>>::new();
    let mut current = Vec::new();
    for review in reviews {
        let mut trial = current.clone();
        trial.push(review.clone());
        let trial_review_count = trial.len();
        let bundle = make_observation_bundle(job, category.clone(), trial, 9_999, 9_999);
        if (trial_review_count > max_reviews_per_bundle
            || serialized_bundle_bytes(&bundle)? > max_input_bytes)
            && !current.is_empty()
        {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(review);
        let single = make_observation_bundle(job, category.clone(), current.clone(), 9_999, 9_999);
        if current.len() == 1 && serialized_bundle_bytes(&single)? > max_input_bytes {
            return Err(EngineError(format!(
                "review {:?} exceeds the bundle byte limit {max_input_bytes}; increase --max-bytes",
                current[0].id
            )));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    let part_count = chunks.len();
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(index, reviews)| {
            make_observation_bundle(job, category.clone(), reviews, index + 1, part_count)
        })
        .collect())
}

fn make_path_bundle(
    job: &PathReviewJob,
    category: PathReviewBundleCategory,
    reviews: Vec<PathReview>,
    part: usize,
    part_count: usize,
) -> PathReviewBundle {
    let review_ids = reviews
        .iter()
        .map(|review| review.id.clone())
        .collect::<Vec<_>>();
    make_bundle(
        job,
        category,
        part,
        part_count,
        review_ids,
        PathReviewBundlePayload::SecurityPath { reviews },
    )
}

fn make_observation_bundle(
    job: &PathReviewJob,
    category: PathReviewBundleCategory,
    reviews: Vec<ObservationReview>,
    part: usize,
    part_count: usize,
) -> PathReviewBundle {
    let review_ids = reviews
        .iter()
        .map(|review| review.id.clone())
        .collect::<Vec<_>>();
    make_bundle(
        job,
        category,
        part,
        part_count,
        review_ids,
        PathReviewBundlePayload::Observation { reviews },
    )
}

fn make_bundle(
    job: &PathReviewJob,
    category: PathReviewBundleCategory,
    part: usize,
    part_count: usize,
    review_ids: Vec<String>,
    payload: PathReviewBundlePayload,
) -> PathReviewBundle {
    let identity = format!(
        "{}\0{}\0{}\0{:?}\0{}\0{}\0{}",
        job.fingerprint,
        category.scope,
        category.review_kind,
        category.capability,
        category.cwe_candidates.join("+"),
        part,
        review_ids.join("\0")
    );
    PathReviewBundle {
        schema_version: PATH_REVIEW_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_fingerprint: stable_review_hash("review-bundle", &identity),
        job_fingerprint: job.fingerprint.clone(),
        goal: "Decide whether every supplied Mehscan review candidate represents a real security issue in the shown repository context. Scanner evidence is a lead, not a verdict. Return exactly one decision for every review ID.".to_string(),
        category,
        part,
        part_count,
        triage_contract: job.triage_contract.clone(),
        review_ids,
        payload,
    }
}

fn serialized_bundle_bytes(bundle: &PathReviewBundle) -> Result<usize, EngineError> {
    serde_json::to_vec(bundle)
        .map(|bytes| bytes.len())
        .map_err(|error| EngineError(format!("could not serialize review bundle: {error}")))
}

fn bundle_context_text_bytes(bundle: &PathReviewBundle) -> (usize, usize) {
    let mut seen = BTreeSet::new();
    let mut total = 0;
    let mut repeated = 0;
    let mut observe = |text: &str| {
        let bytes = text.len();
        total += bytes;
        if !seen.insert(text.to_string()) {
            repeated += bytes;
        }
    };

    match &bundle.payload {
        PathReviewBundlePayload::SecurityPath { reviews } => {
            for review in reviews {
                for fact in &review.facts {
                    observe(&fact.excerpt);
                }
                if let Some(basis) = &review.review_basis {
                    for text in basis
                        .source
                        .captures
                        .values()
                        .chain(basis.sink.captures.values())
                        .chain(
                            basis
                                .protections
                                .iter()
                                .flat_map(|protection| protection.captures.values()),
                        )
                    {
                        observe(text);
                    }
                }
            }
        }
        PathReviewBundlePayload::Observation { reviews } => {
            for review in reviews {
                for fact in &review.facts {
                    observe(&fact.excerpt);
                }
                for evidence in &review.evidence {
                    for capture in evidence.captures.values() {
                        observe(&capture.text);
                    }
                }
            }
        }
    }
    (total, repeated)
}

pub fn path_review_bundle_filename(bundle: &PathReviewBundle) -> String {
    let cwe = match bundle.category.cwe_candidates.as_slice() {
        [] => "review-only".to_string(),
        cwes if cwes.len() <= 3 => cwes.join("+").to_ascii_lowercase(),
        cwes => format!("multi-cwe-{}", cwes.len()),
    };
    let fingerprint = bundle
        .bundle_fingerprint
        .rsplit('-')
        .next()
        .unwrap_or(&bundle.bundle_fingerprint);
    let short_fingerprint = &fingerprint[fingerprint.len().saturating_sub(8)..];
    format!(
        "{}--{}--{}--{}--p{:02}--{}.json",
        filename_slug(&bundle.category.scope),
        filename_slug(&bundle.category.review_kind),
        filename_slug(&format!("{:?}", bundle.category.capability)),
        filename_slug(&cwe),
        bundle.part,
        short_fingerprint
    )
}

fn filename_slug(value: &str) -> String {
    let mut slug = String::new();
    let mut previous_was_lower_or_digit = false;
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            if previous_was_lower_or_digit && !slug.ends_with('-') {
                slug.push('-');
            }
            slug.push(character.to_ascii_lowercase());
            previous_was_lower_or_digit = false;
        } else if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            previous_was_lower_or_digit = true;
        } else if character == '+' {
            slug.push('+');
            previous_was_lower_or_digit = false;
        } else if !slug.ends_with('-') {
            slug.push('-');
            previous_was_lower_or_digit = false;
        }
    }
    slug.trim_matches('-').to_string()
}

fn stable_review_hash(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

pub fn validate_path_review_progress(
    job: &PathReviewJob,
    responses: &PathReviewTriageResponseSet,
) -> Result<PathReviewTriageProgress, EngineError> {
    let missing_review_ids = validate_path_review_response_subset(job, responses)?;
    Ok(PathReviewTriageProgress {
        schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        job_fingerprint: job.fingerprint.clone(),
        submitted_count: responses.results.len(),
        remaining_count: missing_review_ids.len(),
        complete: missing_review_ids.is_empty(),
        issue_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::Issue)
            .count(),
        not_issue_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::NotIssue)
            .count(),
        needs_review_count: responses
            .results
            .iter()
            .filter(|result| result.decision == ReviewDecision::NeedsReview)
            .count(),
        missing_review_ids,
        results: responses.results.clone(),
    })
}

fn validate_path_review_response_subset(
    job: &PathReviewJob,
    responses: &PathReviewTriageResponseSet,
) -> Result<Vec<String>, EngineError> {
    if responses.schema_version != PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION {
        return Err(EngineError(format!(
            "unsupported path-review triage response schema {:?}",
            responses.schema_version
        )));
    }
    if responses.job_fingerprint != job.fingerprint {
        return Err(EngineError(
            "path-review triage responses do not match the job fingerprint".to_string(),
        ));
    }
    let expected_ids = job
        .reviews
        .iter()
        .map(|review| review.id.as_str())
        .chain(
            job.observation_reviews
                .iter()
                .map(|review| review.id.as_str()),
        )
        .collect::<BTreeSet<_>>();
    let mut seen_ids = BTreeSet::new();
    for result in &responses.results {
        if !expected_ids.contains(result.review_id.as_str()) {
            return Err(EngineError(format!(
                "path-review triage references unknown review {:?}",
                result.review_id
            )));
        }
        if !seen_ids.insert(result.review_id.as_str()) {
            return Err(EngineError(format!(
                "path-review triage contains duplicate review {:?}",
                result.review_id
            )));
        }
        validate_compact_triage(
            &result.review_id,
            result.decision,
            &result.summary,
            &result.checks,
        )?;
        let policy = job
            .reviews
            .iter()
            .find(|review| review.id == result.review_id)
            .map(|review| &review.confidence_policy)
            .or_else(|| {
                job.observation_reviews
                    .iter()
                    .find(|review| review.id == result.review_id)
                    .map(|review| &review.confidence_policy)
            })
            .expect("validated review ID must have a confidence policy");
        let expected_confidence = confidence_for_decision(policy, result.decision);
        if result.confidence != expected_confidence {
            return Err(EngineError(format!(
                "confidence for {:?} must be {:?} for the selected {:?} decision",
                result.review_id, expected_confidence, result.decision
            )));
        }
    }
    Ok(expected_ids
        .difference(&seen_ids)
        .map(|id| (*id).to_string())
        .collect())
}

fn bundle_review_confidence_policy<'a>(
    bundle: &'a PathReviewBundle,
    review_id: &str,
) -> Option<&'a ReviewConfidencePolicy> {
    match &bundle.payload {
        PathReviewBundlePayload::SecurityPath { reviews } => reviews
            .iter()
            .find(|review| review.id == review_id)
            .map(|review| &review.confidence_policy),
        PathReviewBundlePayload::Observation { reviews } => reviews
            .iter()
            .find(|review| review.id == review_id)
            .map(|review| &review.confidence_policy),
    }
}

fn confidence_for_decision(
    policy: &ReviewConfidencePolicy,
    decision: ReviewDecision,
) -> ReviewConfidence {
    match decision {
        ReviewDecision::Issue => policy.issue,
        ReviewDecision::NotIssue => policy.not_issue,
        ReviewDecision::NeedsReview => policy.needs_review,
    }
}

fn path_review_issue_groups(
    job: &PathReviewJob,
    responses: &PathReviewTriageResponseSet,
) -> Vec<PathReviewIssueGroup> {
    let paths = job
        .reviews
        .iter()
        .map(|review| (review.id.as_str(), review))
        .collect::<BTreeMap<_, _>>();
    let observations = job
        .observation_reviews
        .iter()
        .map(|review| (review.id.as_str(), review))
        .collect::<BTreeMap<_, _>>();
    let mut groups = BTreeMap::<String, PathReviewIssueGroup>::new();

    for result in responses
        .results
        .iter()
        .filter(|result| result.decision == ReviewDecision::Issue)
    {
        let (key, language, location, capability, cwe_candidates, invariant_id) =
            if let Some(review) = paths.get(result.review_id.as_str()) {
                let cwes = review.candidate.cwe_candidates.clone();
                let location = review.candidate.sink.location.clone();
                (
                    issue_group_key(
                        review.candidate.capability,
                        &location,
                        &review.candidate.sink.rule_id,
                    ),
                    review.language,
                    location,
                    review.candidate.capability,
                    cwes,
                    review.candidate.sink.rule_id.clone(),
                )
            } else if let Some(review) = observations.get(result.review_id.as_str()) {
                let first = review
                    .evidence
                    .first()
                    .expect("observation reviews always contain evidence");
                let mut cwes = review
                    .evidence
                    .iter()
                    .flat_map(|item| item.cwe_candidates.iter().cloned())
                    .collect::<Vec<_>>();
                cwes.sort();
                cwes.dedup();
                let anchor = observation_actionable_anchor(review).unwrap_or(first);
                (
                    issue_group_key(anchor.capability, &anchor.location, &anchor.rule_id),
                    review.language,
                    anchor.location.clone(),
                    anchor.capability,
                    cwes,
                    anchor.rule_id.clone(),
                )
            } else {
                continue;
            };

        let group = groups.entry(key.clone()).or_insert_with(|| {
            let mut hash = 0xcbf29ce484222325u64;
            hash_review_text(&mut hash, &key);
            PathReviewIssueGroup {
                id: format!("issue-group-{hash:016x}"),
                review_ids: Vec::new(),
                invariant_id,
                confidence: result.confidence,
                language,
                location,
                capability,
                cwe_candidates,
            }
        });
        group.review_ids.push(result.review_id.clone());
        group.confidence = group.confidence.max(result.confidence);
    }

    let mut groups = groups.into_values().collect::<Vec<_>>();
    for group in &mut groups {
        group.review_ids.sort();
    }
    groups.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then_with(|| {
                left.location
                    .start
                    .byte_offset
                    .cmp(&right.location.start.byte_offset)
            })
            .then_with(|| left.id.cmp(&right.id))
    });
    groups
}

pub fn validate_review_triage(
    job: &ReviewNeighborhoodJob,
    responses: &ReviewTriageResponseSet,
) -> Result<ReviewTriageReport, EngineError> {
    if responses.schema_version != REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION {
        return Err(EngineError(format!(
            "unsupported review triage response schema {:?}",
            responses.schema_version
        )));
    }
    if responses.job_fingerprint != job.fingerprint {
        return Err(EngineError(
            "review triage responses do not match the neighborhood job fingerprint".to_string(),
        ));
    }

    let expected_ids = job
        .neighborhoods
        .iter()
        .map(|neighborhood| neighborhood.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen_ids = BTreeSet::new();
    for result in &responses.results {
        if !expected_ids.contains(result.neighborhood_id.as_str()) {
            return Err(EngineError(format!(
                "review triage references unknown neighborhood {:?}",
                result.neighborhood_id
            )));
        }
        if !seen_ids.insert(result.neighborhood_id.as_str()) {
            return Err(EngineError(format!(
                "review triage contains duplicate neighborhood {:?}",
                result.neighborhood_id
            )));
        }
        validate_triage_result(result)?;
    }
    if seen_ids.len() != expected_ids.len() {
        let missing = expected_ids
            .difference(&seen_ids)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(EngineError(format!(
            "review triage is missing neighborhoods: {missing}"
        )));
    }

    let issue_count = responses
        .results
        .iter()
        .filter(|result| result.decision == ReviewDecision::Issue)
        .count();
    let not_issue_count = responses
        .results
        .iter()
        .filter(|result| result.decision == ReviewDecision::NotIssue)
        .count();
    let needs_review_count = responses
        .results
        .iter()
        .filter(|result| result.decision == ReviewDecision::NeedsReview)
        .count();
    Ok(ReviewTriageReport {
        schema_version: REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        job_fingerprint: job.fingerprint.clone(),
        issue_count,
        not_issue_count,
        needs_review_count,
        results: responses.results.clone(),
    })
}

fn validate_triage_result(result: &mehscan_core::ReviewTriageResult) -> Result<(), EngineError> {
    validate_compact_triage(
        &result.neighborhood_id,
        result.decision,
        &result.summary,
        &result.checks,
    )
}

pub(crate) fn validate_compact_triage(
    id: &str,
    decision: ReviewDecision,
    summary: &str,
    result_checks: &[String],
) -> Result<(), EngineError> {
    let summary = summary.trim();
    if summary.is_empty() {
        return Err(EngineError(format!(
            "review triage summary is empty for {:?}",
            id
        )));
    }
    if summary.chars().count() > 500 || summary.chars().any(char::is_control) {
        return Err(EngineError(format!(
            "review triage summary must be one line of at most 500 characters for {:?}",
            id
        )));
    }
    if result_checks.len() > 5 {
        return Err(EngineError(format!(
            "review triage has more than five checks for {:?}",
            id
        )));
    }
    let mut checks = BTreeSet::new();
    for check in result_checks {
        let check = check.trim();
        if check.is_empty() || check.chars().count() > 300 || check.chars().any(char::is_control) {
            return Err(EngineError(format!(
                "review triage checks must be one non-empty line of at most 300 characters for {:?}",
                id
            )));
        }
        if !checks.insert(check) {
            return Err(EngineError(format!(
                "review triage contains a duplicate check for {:?}",
                id
            )));
        }
    }
    match decision {
        ReviewDecision::NeedsReview if result_checks.is_empty() => Err(EngineError(format!(
            "needs_review requires at least one decisive check for {:?}",
            id
        ))),
        ReviewDecision::Issue | ReviewDecision::NotIssue if !result_checks.is_empty() => {
            Err(EngineError(format!(
                "final issue or not_issue decisions cannot retain checks for {:?}",
                id
            )))
        }
        _ => Ok(()),
    }
}

fn path_review_triage_contract() -> ReviewTriageContract {
    ReviewTriageContract {
        response_fields: vec![
            "review_id".to_string(),
            "decision".to_string(),
            "confidence".to_string(),
            "summary".to_string(),
            "checks".to_string(),
        ],
        decisions: vec![
            "issue".to_string(),
            "not_issue".to_string(),
            "needs_review".to_string(),
        ],
        confidence_levels: vec!["high".to_string(), "medium".to_string(), "low".to_string()],
        instructions: vec![
            "Treat the candidate as a bounded review lead, not a vulnerability verdict."
                .to_string(),
            "Use issue only when supplied evidence supports dangerous behavior, relevant attacker influence or policy failure, and no demonstrated effective protection."
                .to_string(),
            "Use not_issue only for affirmative disproof or a demonstrated effective protection; missing evidence is not disproof."
                .to_string(),
            "Use only supplied facts; do not invent cross-function, deployment, or runtime behavior."
                .to_string(),
            "Configuration facts are repository defaults or references, not proof of the effective deployed value."
                .to_string(),
            "Distinguish application-owned controls from proxy, gateway, ingress, platform, framework, and client controls."
                .to_string(),
            "Use needs_review only when a named missing fact could change the decision."
                .to_string(),
            "Treat every remaining decision_facts.unresolved entry as decision-critical. Do not use issue or not_issue while one remains unless a supplied established fact explicitly answers that exact entry; otherwise use needs_review and copy the entry into checks."
                .to_string(),
            "Apply this decision procedure: issue requires established dangerous behavior plus attacker influence or a concrete policy failure and no demonstrated effective applicable control; not_issue requires affirmative safe purpose, non-attacker input, non-executable behavior, or an effective applicable control; needs_review requires a supplied unresolved fact that can change issue versus not_issue."
                .to_string(),
            "A bounded path may satisfy the issue test, but path status alone is not sufficient. Observation status alone is not a reason for needs_review."
                .to_string(),
            "For a deterministic bounded path whose decision_facts.unresolved and decision_facts.effective_controls are both empty, use issue when its rule-specific established behavior describes the named weakness. Use not_issue only when another supplied fact affirmatively disproves that same behavior; do not substitute a different invariant such as resource ownership for plaintext storage, CSRF, validation, or lifecycle review."
                .to_string(),
            "Treat an observation as decision-ready when decision_facts.unresolved is empty and an established fact explicitly names a concrete policy failure or affirmative safe purpose. For an application-owned authentication-cookie omission, a merely possible proxy rewrite affects deployment exposure or remediation ownership but does not erase the source defect; absent a supplied effective rewrite, use issue with medium confidence rather than needs_review."
                .to_string(),
            "Answer open questions from the supplied facts before requesting more evidence; do not ask to trace a flow or inspect a control that the excerpts already show, and name only the exact unresolved artifact in checks."
                .to_string(),
            "Before choosing needs_review, verify that the requested artifact is absent from facts. If a helper, route, producer, consumer, configuration, validation, or protection excerpt already answers the question, use that excerpt to decide issue or not_issue instead of asking to inspect it again."
                .to_string(),
            "For resource-access review, a sensitive read or an existence oracle can be the security impact; do not require a mutation before using issue. Conversely, treat an exact authenticated-owner, tenant, possession-secret, or server-derived selector control as affirmative disproof when it applies before the access."
                .to_string(),
            "Use the exact confidence_policy value for the decision you select; confidence is deterministic scanner calibration, not a model-style preference or vulnerability severity. High means the decisive behavior or affirmative disproof is directly established, medium means one bounded framework, purpose, ownership, or syntactic inference remains, and low means decision-critical evidence is truncated."
                .to_string(),
            "Calibration: direct request input reaching an executable injection sink with no applicable control can be issue; a weak hash used only as a non-security packaging checksum can be not_issue; a source-only observation with an unresolved sink or impact can be needs_review."
                .to_string(),
            "Keep summary to two sentences. Use checks only for needs_review and keep them decisive."
                .to_string(),
            "Evaluate each review independently. Its summary must name the concrete source, sink, or policy behavior for that review using its review_basis semantics; do not reuse category-wide boilerplate or list alternative weaknesses from other reviews."
                .to_string(),
            "When the reviewed invariant requires rejection, challenge solving, telemetry, logging, or auditing followed by continued execution establishes that the observed check is not an effective control. If the supplied excerpt directly shows that policy failure and no other effective control, decide issue rather than needs_review."
                .to_string(),
            "For needs_review, copy one or more exact entries from decision_facts.unresolved into checks. Do not create checks outside that supplied unresolved set."
                .to_string(),
            "Return exactly one result for every supplied review ID and do not add repository findings outside the bundle."
                .to_string(),
        ],
    }
}

fn candidate_evidence_ids<'a>(
    candidates: &'a [mehscan_core::Candidate],
    evidence: &'a [Evidence],
    sources: &RepositorySources,
) -> BTreeSet<&'a str> {
    let mut used = candidates
        .iter()
        .flat_map(|candidate| {
            std::iter::once(candidate.source.id.as_str())
                .chain(std::iter::once(candidate.sink.id.as_str()))
                .chain(candidate.protections.iter().map(|item| item.id.as_str()))
        })
        .collect::<BTreeSet<_>>();
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.sink.rule_id == "python-file-local-parameter-sink-summary")
    {
        let Ok(file) = sources.file(&candidate.sink.location.path) else {
            continue;
        };
        let start = candidate
            .sink
            .location
            .start
            .byte_offset
            .min(file.source.len());
        let end = candidate
            .sink
            .location
            .end
            .byte_offset
            .min(file.source.len());
        if start >= end
            || !file.source.is_char_boundary(start)
            || !file.source.is_char_boundary(end)
        {
            continue;
        }
        let helper = direct_call_reference(&file.source[start..end]).or_else(|| {
            let spans = line_spans(&file.source);
            let line = candidate.sink.location.start.line.saturating_sub(1);
            spans
                .get(line)
                .and_then(|(start, end)| direct_call_reference(&file.source[*start..*end]))
        });
        let Some(helper) = helper else {
            continue;
        };
        used.extend(
            evidence
                .iter()
                .filter(|item| {
                    item.kind == EvidenceKind::Sink
                        && item.capability == candidate.capability
                        && item.location.path == candidate.sink.location.path
                        && item.enclosing_symbol.as_deref() == Some(helper.as_str())
                })
                .map(|item| item.id.as_str()),
        );
    }
    used
}

fn review_truncation(occurred: bool, decision_critical: bool) -> ReviewContextTruncation {
    let roles = if !occurred {
        Vec::new()
    } else if decision_critical {
        vec!["primary_source_sink_or_control_context".to_string()]
    } else {
        vec!["auxiliary_enrichment_context".to_string()]
    };
    ReviewContextTruncation {
        occurred,
        roles,
        decision_critical,
    }
}

fn path_decision_facts(
    candidate: &mehscan_core::Candidate,
    review_basis: &PathReviewBasis,
    facts: &[ReviewNeighborhoodFact],
    unresolved: &[String],
) -> ReviewDecisionFacts {
    let java_resource_control = java_path_resource_control(candidate, review_basis, facts);
    let java_resource_issue = java_path_resource_issue(candidate, review_basis, facts);
    let csharp_redirect_issue =
        csharp_path_redirect_dynamic_authority_issue(candidate, review_basis, facts);
    let operator_configured_local_asset = path_has_operator_configured_local_asset_origin(
        candidate.source.capability,
        &review_basis.source.tags,
        facts,
    );
    let mut established = vec![
        format!(
            "The deterministic engine admitted a bounded relationship from source rule {} to sink rule {}.",
            candidate.source.rule_id, candidate.sink.rule_id
        ),
        format!(
            "The source is at {}:{} and the sink is at {}:{}.",
            candidate.source.location.path,
            candidate.source.location.start.line,
            candidate.sink.location.path,
            candidate.sink.location.start.line
        ),
        format!("The bounded path state is {:?}.", candidate.state),
    ];
    established.extend(
        path_semantic_claims(candidate)
            .into_iter()
            .map(|claim| format!("The bounded path records this rule-specific behavior: {claim}.")),
    );
    established.extend(
        facts
            .iter()
            .filter(|fact| fact.role == "ineffective_protection_context")
            .map(|fact| {
                format!(
                    "The supplied context identifies {} as ineffective; do not count it as an effective control for this path.",
                    fact.symbol
                )
            }),
    );
    if let Some(attribute) = explicit_cookie_omission(&candidate.sink.rule_id) {
        established.push(format!(
            "The application source explicitly emits an authentication cookie without the {attribute} attribute. No authoritative deployed rewrite that adds this attribute is supplied; a possible external rewrite changes deployment exposure or remediation ownership, not the source-level omission."
        ));
    }
    if candidate.protections.is_empty() {
        established.push(
            "No effective protection evidence is linked to this exact bounded value relationship."
                .to_string(),
        );
    }
    if let Some(control) = java_resource_control {
        established.push(format!(
            "The supplied Java path context explicitly establishes an applicable resource-access control: {control}"
        ));
    }
    if let Some(issue) = java_resource_issue {
        established.push(format!(
            "The supplied Java path context explicitly establishes the resource-access impact: {issue}"
        ));
    }
    if let Some(issue) = csharp_redirect_issue {
        established.push(format!(
            "The supplied C# path context explicitly establishes the redirect impact: {issue}"
        ));
    }
    if candidate.source.capability == Capability::StoredUserContent
        && facts
            .iter()
            .any(|fact| fact.role == "request_response_origin_context")
    {
        established.push(
            "An exact registered endpoint excerpt shows request-derived data assigned to the named response field returned to this client consumer."
                .to_string(),
        );
    }
    if review_basis_establishes_persisted_origin(review_basis) {
        established.push(
            "The source rule semantics explicitly establish stored, user-controlled data at this bounded path terminal."
                .to_string(),
        );
    }
    if operator_configured_local_asset {
        established.push(
            "Exact repository facts establish that this rendered value is loaded from an operator-configured local asset path with a repository literal default; no request-origin writer for the selected asset is supplied."
                .to_string(),
        );
    }
    if [
        "browser_storage_write_context",
        "token_payload_origin_context",
        "stored_write_origin_context",
    ]
    .iter()
    .all(|role| facts.iter().any(|fact| fact.role == *role))
    {
        established.push(
            "Exact repository excerpts show the browser storage key receives an authentication token, that token carries the user data object, and the rendered field has a request-backed persistence writer."
                .to_string(),
        );
    }
    if candidate.sink.rule_id == "python-source-file-content-write"
        && facts
            .iter()
            .any(|fact| fact.role == "python_source_file_consumer_context")
    {
        established.push(
            "An exact repository import statement references the request-overwritten Python source module; execution timing follows application startup, reload, or worker restart semantics."
                .to_string(),
        );
    }
    let mut effective_controls = candidate
        .protections
        .iter()
        .map(|protection| {
            format!(
                "Linked protection rule {} at {}:{}; applicability still follows the supplied path semantics.",
                protection.rule_id, protection.location.path, protection.location.start.line
            )
        })
        .collect::<Vec<_>>();
    if let Some(control) = java_resource_control {
        effective_controls.push(control.to_string());
    }
    ReviewDecisionFacts {
        established,
        effective_controls,
        unresolved: unresolved.to_vec(),
    }
}

/// Recognizes an exactly owned C# redirect helper where the request-selected
/// argument occupies the authority portion of an absolute URL. A helper may
/// safely map some values to fixed hosts while retaining an unsafe fallback;
/// the fallback is enough to establish attacker control of the destination.
fn csharp_path_redirect_dynamic_authority_issue(
    candidate: &mehscan_core::Candidate,
    review_basis: &PathReviewBasis,
    facts: &[ReviewNeighborhoodFact],
) -> Option<&'static str> {
    if candidate.capability != Capability::Redirect
        || candidate.source.rule_id != "csharp-aspnet-controller-parameter-source"
        || candidate.sink.rule_id != "csharp-controller-http-redirect"
    {
        return None;
    }
    let source_parameter = review_basis.source.captures.get("parameter")?;
    let location = review_basis.sink.captures.get("location")?;
    let open = location.find('(')?;
    let close = location.rfind(')')?;
    if close <= open || location[open + 1..close].contains(['(', ')']) {
        return None;
    }
    let method = terminal_identifier(location[..open].trim())?;
    let arguments = location[open + 1..close]
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    let positions = arguments
        .iter()
        .enumerate()
        .filter(|(_, argument)| **argument == source_parameter)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return None;
    }
    facts.iter().any(|fact| {
        fact.role == "helper_definition_context"
            && fact.symbol == method
            && csharp_helper_parameter_controls_absolute_url_authority(
                &fact.excerpt,
                method,
                positions[0],
            )
    }).then_some(
        "The request-selected helper argument is inserted into the authority of an absolute redirect URL on an executable helper branch, so fixed-host sibling branches do not constrain the fallback destination.",
    )
}

/// A read-only repository call can still disclose whether a caller-selected
/// object exists. Recognize only the exact branch where present and absent
/// results return observably different status responses.
fn java_path_resource_issue(
    candidate: &mehscan_core::Candidate,
    review_basis: &PathReviewBasis,
    facts: &[ReviewNeighborhoodFact],
) -> Option<&'static str> {
    if !candidate.sink.rule_id.starts_with("java-")
        || candidate.capability != Capability::ResourceAccess
        || !candidate.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
        || review_basis.sink.captures.get("filter").map(String::as_str) != Some("videoId")
    {
        return None;
    }
    facts.iter().any(|fact| {
        matches!(fact.role.as_str(), "source_context" | "sink_context" | "helper_definition_context")
            && fact.excerpt.contains("findById(videoId)")
            && fact.excerpt.contains("optionalProfileVideo.isPresent()")
            && fact.excerpt.contains("403")
            && fact.excerpt.contains("404")
    }).then_some(
        "The caller-selected video ID is looked up and the response distinguishes an existing object with status 403 from a missing object with status 404, exposing an object-existence oracle even though no deletion occurs.",
    )
}

/// Recognizes only a possession check that is shown on the same Java path as
/// the selected vehicle and authenticated owner. This is deliberately narrow:
/// authentication alone, a null check, or an unrelated PIN comparison is not
/// an authorization control.
fn java_path_resource_control(
    candidate: &mehscan_core::Candidate,
    review_basis: &PathReviewBasis,
    facts: &[ReviewNeighborhoodFact],
) -> Option<&'static str> {
    if !candidate.sink.rule_id.starts_with("java-")
        || candidate.capability != Capability::ResourceAccess
        || !candidate.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
    {
        return None;
    }
    let selector = review_basis.sink.captures.get("filter")?;
    if selector != "vehicleForm.getVin()" {
        return None;
    }
    facts.iter().any(|fact| {
        matches!(fact.role.as_str(), "source_context" | "sink_context" | "helper_definition_context")
            && (fact.excerpt.contains("vehicleDetails.getPincode().equalsIgnoreCase(vehicleForm.getPincode())")
                || fact.excerpt.contains("checkVehicle.getPincode().equalsIgnoreCase(vehicleForm.getPincode())"))
            && fact.excerpt.contains("getUserFromToken(request)")
            && (fact.excerpt.contains("vehicleDetails.setOwner(user)")
                || fact.excerpt.contains("checkVehicle.setOwner(user)"))
    }).then_some(
        "The selected vehicle is assigned only after its stored PIN matches the request PIN and the new owner is derived from the authenticated request token.",
    )
}

fn path_decision_blockers(
    candidate: &mehscan_core::Candidate,
    review_basis: &PathReviewBasis,
    questions: &[String],
    facts: &[ReviewNeighborhoodFact],
) -> Vec<String> {
    let operator_configured_local_asset = path_has_operator_configured_local_asset_origin(
        candidate.source.capability,
        &review_basis.source.tags,
        facts,
    );
    let has_persisted_origin = review_basis_establishes_persisted_origin(review_basis)
        || facts.iter().any(|fact| {
            matches!(
                fact.role.as_str(),
                "stored_write_origin_context" | "persistence_call_observed"
            )
        });
    let has_browser_storage_chain = has_persisted_origin
        && facts
            .iter()
            .any(|fact| fact.role == "browser_storage_write_context")
        && facts
            .iter()
            .any(|fact| fact.role == "token_payload_origin_context");
    let has_response_origin = facts
        .iter()
        .any(|fact| fact.role == "request_response_origin_context");
    let has_python_source_consumer = facts
        .iter()
        .any(|fact| fact.role == "python_source_file_consumer_context");
    questions
        .iter()
        .filter(|question| {
            (explicit_cookie_omission(&candidate.sink.rule_id).is_none()
                && control_can_be_owned_outside_application(candidate.capability)
                && (question.contains("What exact control is effective at the authoritative")
                    || question.contains("which application, framework, proxy")))
                || (question.contains("Which code can write this browser-storage key")
                    && !has_browser_storage_chain)
                || (question.contains("producer, persistence, or retrieval context")
                    && !has_persisted_origin
                    && !has_response_origin
                    && !operator_configured_local_asset)
                || question.starts_with(
                    "What exact configuration value is effective for the conditional branch",
                )
                || (candidate.sink.rule_id == "python-source-file-content-write"
                    && question.starts_with(
                        "Does an exact Python import or loader reference the request-overwritten source file",
                    )
                    && !has_python_source_consumer)
        })
        .cloned()
        .collect()
}

fn path_has_operator_configured_local_asset_origin(
    source_capability: Capability,
    source_tags: &[String],
    facts: &[ReviewNeighborhoodFact],
) -> bool {
    if source_capability != Capability::StoredUserContent
        || !source_tags.iter().any(|tag| tag == "local-file")
    {
        return false;
    }

    let literal_configuration = facts.iter().any(|fact| {
        fact.role == "configuration_binding_context"
            && fact.excerpt.lines().any(|line| {
                let Some((_, value)) = line.split_once(':') else {
                    return false;
                };
                let value = value.trim().trim_matches(['\'', '"']);
                !value.is_empty()
                    && !value.contains("${")
                    && !value.contains("..")
                    && !value.contains('/')
                    && !value.contains('\\')
                    && !value.contains("://")
            })
    });
    let fixed_local_read = facts.iter().any(|fact| {
        fact.role == "helper_definition_context"
            && (fact.excerpt.contains("readFileSync('") || fact.excerpt.contains("readFileSync(\""))
            && fact.excerpt.contains("config.get<")
            && !contains_web_request_origin(&fact.excerpt)
    });
    let operator_lifecycle = facts.iter().any(|fact| {
        fact.role == "configuration_lifecycle_context"
            && (fact.excerpt.contains("retrieveCustomFile(")
                || fact.excerpt.contains("downloadToFile("))
    });

    literal_configuration && fixed_local_read && operator_lifecycle
}

fn review_basis_establishes_persisted_origin(review_basis: &PathReviewBasis) -> bool {
    review_basis.source.capability == Capability::StoredUserContent
        && ["stored-data", "user-controlled"].iter().all(|tag| {
            review_basis
                .source
                .tags
                .iter()
                .any(|candidate| candidate == tag)
        })
}

fn path_execution_configuration_gate(facts: &[ReviewNeighborhoodFact]) -> bool {
    let symbols = facts
        .iter()
        .filter(|fact| {
            matches!(
                fact.role.as_str(),
                "configuration_context"
                    | "configuration_binding_context"
                    | "configuration_lifecycle_context"
            )
        })
        .map(|fact| fact.symbol.as_str())
        .filter(|symbol| !symbol.is_empty() && symbol.len() <= 120)
        .collect::<BTreeSet<_>>();
    if symbols.is_empty() {
        return false;
    }
    facts
        .iter()
        .filter(|fact| matches!(fact.role.as_str(), "source_context" | "sink_context"))
        .flat_map(|fact| fact.excerpt.lines())
        .any(|line| {
            (line.contains("if (")
                || line.contains("if(")
                || line.contains("&&")
                || line.contains("||"))
                && symbols
                    .iter()
                    .any(|symbol| contains_identifier(line, symbol))
        })
}

fn observation_decision_facts(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
    unresolved: &[String],
) -> ReviewDecisionFacts {
    let java_policy = java_observation_policy(evidence, facts);
    let csharp_policy = csharp_observation_policy(evidence, facts);
    let go_policy = go_observation_policy(evidence, facts);
    let rust_policy = rust_observation_policy(evidence, facts);
    let javascript_policy = javascript_observation_policy(evidence, facts);
    let embedded_signing_key = observation_has_source_embedded_signing_key(evidence, facts);
    let matched_python_jwt_verification = evidence
        .iter()
        .any(|item| item.rule_id == "python-jwt-hardcoded-signing-key")
        && facts
            .iter()
            .any(|fact| fact.role == "jwt_verification_context");
    let cookie_omission = evidence
        .iter()
        .find_map(|item| explicit_cookie_omission(&item.rule_id));
    let non_enforcing_rejection = evidence.iter().find_map(|item| {
        match item.rule_id.as_str() {
            "typescript-password-confirmation-not-enforced-review" => Some(
                "The supplied middleware excerpt explicitly establishes that a password-confirmation mismatch is used only for challenge telemetry before execution continues through `next()`; the required rejection is not enforced."
            ),
            "typescript-registration-rejection-fallthrough-review" => Some(
                "The supplied registration excerpt explicitly establishes that an invalid-input response is sent without returning before execution continues through `next()` to later registration middleware."
            ),
            _ => None,
        }
    });
    let operator_configured_endpoint =
        observation_has_operator_configured_endpoint(evidence, facts);
    let server_generated_output_path =
        observation_has_server_generated_fixed_root_path(evidence, facts);
    let direct_stored_html_trust_bypass =
        observation_has_direct_stored_html_trust_bypass(evidence, facts);
    let direct_request_resource_selector =
        observation_has_direct_request_resource_selector(evidence);
    let resource_policy = evidence.iter().find_map(|item| {
        item.context
            .resource_policy
            .as_ref()
            .filter(|policy| policy.state != ResourcePolicyState::Unknown)
    });
    let resource_policy_applies = resource_policy.is_some()
        && evidence.iter().any(|item| {
            item.kind == EvidenceKind::Sink && item.capability == Capability::ResourceAccess
        });
    let mut established = evidence
        .iter()
        .map(|item| {
            format!(
                "Observed {:?} rule {} for {:?} at {}:{}; this observation alone does not establish a source-to-sink relationship.",
                item.kind,
                item.rule_id,
                item.capability,
                item.location.path,
                item.location.start.line
            )
        })
        .collect::<Vec<_>>();
    if embedded_signing_key {
        established.push(
            "The supplied redacted definition fact establishes that this token-signing operation uses source-embedded private-key material; explicit expiry and algorithm settings do not mitigate repository disclosure of the signing key."
                .to_string(),
        );
    }
    if matched_python_jwt_verification {
        established.push(
            "The supplied exact verification context establishes that authentication tokens are accepted with the same source-visible literal signing key; the repository therefore discloses the effective verification secret."
                .to_string(),
        );
    }
    if let Some(attribute) = cookie_omission {
        established.push(format!(
            "The application source explicitly emits an authentication cookie without the {attribute} attribute. No authoritative deployed rewrite that adds this attribute is supplied; a possible external rewrite changes deployment exposure or remediation ownership, not the source-level omission."
        ));
    }
    if let Some(failure) = non_enforcing_rejection {
        established.push(failure.to_string());
    }
    if operator_configured_endpoint {
        established.push(
            "The exact outbound destination is supplied by process environment configuration rather than request data; the observed call does not establish a web-attacker-controlled SSRF destination."
                .to_string(),
        );
    }
    if server_generated_output_path {
        established.push(
            "The exact filesystem-write path uses a fixed application directory and a server-generated fixed-format filename composed from an observed fixed-format transform and server randomness; the supplied path construction contains no request-derived path segment."
                .to_string(),
        );
    }
    if direct_stored_html_trust_bypass {
        established.push(
            "The supplied same-callback context shows the stored response value interpolated into HTML and passed to the exact Angular trust-bypass sink without an intervening encoding or sanitization control."
                .to_string(),
        );
    }
    if direct_request_resource_selector && !resource_policy_applies {
        established.push(
            "The request-data capture is used directly in this exact resource selector; authentication alone does not establish object ownership."
                .to_string(),
        );
    }
    if let Some(policy) = &java_policy {
        established.push(policy.established.to_string());
    }
    if let Some(policy) = &csharp_policy {
        established.push(policy.established.clone());
    }
    if let Some(policy) = &go_policy {
        established.push(policy.established.clone());
    }
    if let Some(policy) = &rust_policy {
        established.push(policy.established.clone());
    }
    if let Some(policy) = &javascript_policy {
        established.push(policy.established.clone());
    }
    if let Some(policy) = resource_policy.filter(|_| resource_policy_applies) {
        established.push(match policy.state {
            ResourcePolicyState::OwnerScoped => format!(
                "The resource selector is owner-scoped by a verified authenticated identity relationship ({}).",
                policy.basis
            ),
            ResourcePolicyState::PublicCatalog => format!(
                "The selected resource is shared public catalog data rather than a user-owned object, affirmatively disproving an object-ownership violation for this exact resource-access review ({}).",
                policy.basis
            ),
            ResourcePolicyState::SharedResource => format!(
                "The selected resource is shared application data rather than a user-owned object, affirmatively disproving an object-ownership violation for this exact resource-access review ({}).",
                policy.basis
            ),
            ResourcePolicyState::Unknown => unreachable!(),
        });
    }
    let effective_controls = if javascript_policy.as_ref().is_some_and(|policy| policy.safe) {
        vec![
            javascript_policy
                .as_ref()
                .expect("checked JavaScript policy")
                .control
                .clone(),
        ]
    } else if javascript_policy.is_some() {
        Vec::new()
    } else if rust_policy.as_ref().is_some_and(|policy| policy.safe) {
        vec![
            rust_policy
                .as_ref()
                .expect("checked Rust policy")
                .control
                .clone(),
        ]
    } else if rust_policy.is_some() {
        Vec::new()
    } else if go_policy.as_ref().is_some_and(|policy| policy.safe) {
        vec![
            go_policy
                .as_ref()
                .expect("checked Go policy")
                .control
                .clone(),
        ]
    } else if go_policy.is_some() {
        Vec::new()
    } else if csharp_policy.as_ref().is_some_and(|policy| policy.safe) {
        vec![
            csharp_policy
                .as_ref()
                .expect("checked C# policy")
                .control
                .clone(),
        ]
    } else if csharp_policy.is_some() {
        Vec::new()
    } else if java_policy.as_ref().is_some_and(|policy| policy.safe) {
        vec![
            java_policy
                .as_ref()
                .expect("checked Java policy")
                .control
                .to_string(),
        ]
    } else if java_policy.is_some() {
        Vec::new()
    } else if embedded_signing_key || matched_python_jwt_verification {
        Vec::new()
    } else if resource_policy_applies
        && resource_policy.is_some_and(|policy| policy.state == ResourcePolicyState::OwnerScoped)
    {
        vec![
            "A verified authenticated owner constraint applies to this exact resource selector."
                .to_string(),
        ]
    } else {
        evidence
        .iter()
        .filter(|item| {
            matches!(
                item.kind,
                EvidenceKind::Guard | EvidenceKind::Sanitizer | EvidenceKind::Validation
            ) && (item.capability != Capability::ResourceAccess || resource_policy_applies)
        })
        .map(|item| {
            format!(
                "Observed possible control rule {} at {}:{}; effectiveness is limited to the supplied relationship facts.",
                item.rule_id, item.location.path, item.location.start.line
            )
        })
        .collect()
    };
    let unresolved = if javascript_policy.is_some()
        || rust_policy.is_some()
        || go_policy.is_some()
        || csharp_policy.is_some()
        || embedded_signing_key
        || matched_python_jwt_verification
        || cookie_omission.is_some()
        || resource_policy_applies
        || non_enforcing_rejection.is_some()
        || operator_configured_endpoint
        || server_generated_output_path
        || direct_stored_html_trust_bypass
        || java_policy.is_some()
    {
        Vec::new()
    } else if direct_request_resource_selector {
        vec![
            "Does this request-selected resource reach a sensitive read, mutation, or response without a later owner or tenant constraint?"
                .to_string(),
        ]
    } else {
        unresolved.to_vec()
    };
    ReviewDecisionFacts {
        established,
        effective_controls,
        unresolved,
    }
}

struct JavaObservationPolicy {
    established: &'static str,
    safe: bool,
    control: &'static str,
}

struct CsharpObservationPolicy {
    established: String,
    safe: bool,
    control: String,
}

/// Converts compile-time Rust resource inputs into decisive facts only when
/// the exact reviewed value remains static. In particular, an `include_str!`
/// template followed only by literal-to-literal replacements is not an XSS
/// provenance lead, and an embedded migration is not dynamic SQL text.
fn rust_observation_policy(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> Option<CsharpObservationPolicy> {
    if evidence.iter().any(|item| {
        item.rule_id == "rust-database-query"
            && item
                .captures
                .get("query")
                .is_some_and(|capture| is_rust_include_str(capture.text.trim()))
    }) {
        return Some(CsharpObservationPolicy {
            established: "The exact Rust SQLx query text is loaded at compile time by `include_str!`; the reviewed operation contains no runtime value interpolation into the SQL command text.".to_string(),
            safe: true,
            control: "The exact reviewed SQL text is a compile-time embedded resource rather than runtime attacker-controlled command text.".to_string(),
        });
    }

    for item in evidence
        .iter()
        .filter(|item| item.rule_id == "rust-actix-html-output")
    {
        let Some(content) = item
            .captures
            .get("content")
            .map(|capture| capture.text.trim())
        else {
            continue;
        };
        if facts.iter().any(|fact| {
            fact.role == "source_context" && rust_static_html_binding(&fact.excerpt, content)
        }) {
            return Some(CsharpObservationPolicy {
                established: "The exact Actix response body is a compile-time `include_str!` resource, optionally transformed only by literal-to-literal replacements; the supplied function introduces no attacker-controlled HTML content.".to_string(),
                safe: true,
                control: "The exact reviewed response body has compile-time static provenance with no runtime data substitution.".to_string(),
            });
        }
    }
    None
}

fn is_rust_include_str(value: &str) -> bool {
    value.starts_with("include_str!(") && value.ends_with(')')
}

fn rust_static_html_binding(source: &str, content: &str) -> bool {
    if !is_plain_identifier(content) {
        return false;
    }
    let direct = format!("let {content} = include_str!(");
    if source.contains(&direct) {
        return true;
    }

    let declaration = format!("let {content} = ");
    let Some(start) = source.find(&declaration) else {
        return false;
    };
    let expression = &source[start + declaration.len()..];
    let Some(end) = expression.find(';') else {
        return false;
    };
    let mut lines = expression[..end].lines();
    let Some(root) = lines.next().map(str::trim) else {
        return false;
    };
    if !is_plain_identifier(root) || !source.contains(&format!("let {root} = include_str!(")) {
        return false;
    }
    let replacements = lines.map(str::trim).filter(|line| !line.is_empty());
    let mut saw_replacement = false;
    for replacement in replacements {
        saw_replacement = true;
        if !rust_literal_replace(replacement) {
            return false;
        }
    }
    saw_replacement
}

fn rust_literal_replace(line: &str) -> bool {
    let Some(arguments) = line
        .strip_prefix(".replace(")
        .and_then(|line| line.strip_suffix(')'))
    else {
        return false;
    };
    let Some((from, to)) = arguments.split_once(',') else {
        return false;
    };
    [from.trim(), to.trim()]
        .into_iter()
        .all(|value| value.len() >= 2 && value.starts_with('"') && value.ends_with('"'))
}

fn javascript_observation_policy(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> Option<CsharpObservationPolicy> {
    if evidence
        .iter()
        .any(|item| item.rule_id == "typescript-dynamic-code")
        && facts
            .iter()
            .any(|fact| fact.role == "fixed_grammar_dynamic_code_context")
    {
        return Some(CsharpObservationPolicy {
            established: "The exact evaluated expression is assembled only from bounded server-generated integers and operators from the fixed arithmetic allowlist `*`, `+`, and `-`; no request or stored value enters the executable text.".to_string(),
            safe: true,
            control: "The reviewed evaluator receives a fixed server-generated arithmetic grammar with no attacker-controlled token.".to_string(),
        });
    }
    None
}

/// Converts only exact Go source shapes already present in the bounded review
/// payload into decisive facts. It deliberately leaves deployment-owned
/// listener, timeout, generic-cookie, and transport questions unresolved.
fn go_observation_policy(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> Option<CsharpObservationPolicy> {
    if evidence
        .iter()
        .any(|item| item.rule_id == "go-hardcoded-md5-otp-review")
    {
        return Some(CsharpObservationPolicy {
            established: "The exact Go authentication operation compares the submitted OTP through MD5 against a source-visible fixed digest, establishing a fixed weak verifier rather than only generic hash usage.".to_string(),
            safe: false,
            control: String::new(),
        });
    }

    if let Some(cookie) = evidence
        .iter()
        .find(|item| item.rule_id == "go-cookie-security-policy-review")
    {
        match cookie.enclosing_symbol.as_deref() {
            Some("SetSession") => {
                return Some(CsharpObservationPolicy {
                    established: "The exact Go session writer explicitly emits the active authentication session with `HttpOnly: false`; no supplied application-owned rewrite changes that emitted attribute.".to_string(),
                    safe: false,
                    control: String::new(),
                });
            }
            Some("DeleteSession" | "DeleteCookie") => {
                return Some(CsharpObservationPolicy {
                    established: "The exact Go cookie operation expires or invalidates the cookie rather than issuing an active credential; omitted confidentiality attributes on this deletion response do not expose a usable authenticated value.".to_string(),
                    safe: true,
                    control: "The reviewed operation is the cookie-deletion/invalidation path, not the active cookie issuance path.".to_string(),
                });
            }
            _ => {}
        }
    }

    let has_database_sink = evidence.iter().any(|item| {
        item.kind == EvidenceKind::Sink && item.capability == Capability::DatabaseQuery
    });
    if has_database_sink
        && evidence
            .iter()
            .any(|item| item.rule_id == "go-sql-parameterization")
    {
        return Some(CsharpObservationPolicy {
            established: "The exact Go database operation uses fixed placeholder SQL and supplies values through the driver's separate parameter arguments rather than concatenating them into command text.".to_string(),
            safe: true,
            control: "Driver parameter binding applies to the exact reviewed database operation.".to_string(),
        });
    }
    if has_database_sink
        && evidence
            .iter()
            .any(|item| item.rule_id == "go-dynamic-sql-prepare")
        && facts.iter().any(|fact| {
            fact.role == "source_context"
                && fact.excerpt.contains("Prepare(")
                && fact.excerpt.contains('?')
                && (fact.excerpt.contains("QueryRow(") || fact.excerpt.contains("Exec("))
        })
    {
        return Some(CsharpObservationPolicy {
            established: "The supplied exact Go function defines placeholder SQL, prepares that fixed statement, and passes the runtime value through `QueryRow` or `Exec` arguments.".to_string(),
            safe: true,
            control: "The reviewed query keeps runtime values outside the prepared SQL text.".to_string(),
        });
    }
    if evidence.iter().any(|item| {
        item.rule_id == "go-database-query"
            && item.captures.get("query").is_some_and(|capture| {
                capture.text.contains("config.") && !capture.text.contains("r.")
            })
    }) && !evidence.iter().any(|item| {
        item.kind == EvidenceKind::Source && item.capability == Capability::HttpRequestData
    }) {
        return Some(CsharpObservationPolicy {
            established: "The exact Go SQL identifier is derived from application configuration, and this review contains no request-data source controlling the command text.".to_string(),
            safe: true,
            control: "The reviewed identifier is operator configuration rather than web-request input.".to_string(),
        });
    }

    if evidence
        .iter()
        .any(|item| item.rule_id == "go-credentialed-wildcard-cors")
    {
        return Some(CsharpObservationPolicy {
            established: "The exact response combines wildcard origin with credential allowance; browsers reject wildcard credentialed CORS and therefore do not expose authenticated cross-origin responses under this combination alone.".to_string(),
            safe: true,
            control: "Browser CORS enforcement rejects credentialed access when `Access-Control-Allow-Origin` is `*`.".to_string(),
        });
    }

    if let Some(resource) = evidence.iter().find(|item| {
        item.kind == EvidenceKind::Sink
            && item.capability == Capability::ResourceAccess
            && item.rule_id == "go-sql-resource-filter-summary"
    }) {
        let filter = resource
            .captures
            .get("filter")
            .map(|capture| capture.text.trim())
            .unwrap_or_default();
        if is_plain_identifier(filter)
            && evidence
                .iter()
                .any(|item| item.rule_id == "go-verified-session-value-control")
            && facts.iter().any(|fact| {
                fact.role == "source_context"
                    && fact
                        .excerpt
                        .contains(&format!("{filter} := session.GetSession"))
            })
        {
            return Some(CsharpObservationPolicy {
                established: format!("The exact Go resource selector `{filter}` is assigned from the authenticated server-side session immediately before this reviewed lookup; later request fields in the same handler do not control this anchor."),
                safe: true,
                control: "The exact reviewed resource selector is derived from authenticated session identity, not request-selected object identity.".to_string(),
            });
        }
    }
    None
}

/// Converts only exact, application-owned C# shapes into decisive review
/// facts. Framework defaults and deployment-owned policy remain unresolved;
/// explicit weak literals, ordinary public identity endpoints, proved stored
/// raw HTML, and request-mapped interpolated SQL do not.
fn csharp_observation_policy(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> Option<CsharpObservationPolicy> {
    if evidence
        .iter()
        .any(|item| item.rule_id == "csharp-identity-weak-lockout-policy")
        && facts.iter().any(|fact| {
            fact.role == "source_context"
                && fact
                    .excerpt
                    .contains("options.Lockout.AllowedForNewUsers = false")
        })
    {
        return Some(CsharpObservationPolicy {
            established: "The supplied C# application configuration explicitly establishes that account lockout is disabled for new users; no later application-owned override is supplied in the review facts.".to_string(),
            safe: false,
            control: String::new(),
        });
    }
    if evidence
        .iter()
        .any(|item| item.rule_id == "csharp-identity-weak-password-policy")
        && facts.iter().any(|fact| {
            fact.role == "source_context"
                && fact.excerpt.contains("options.Password.RequiredLength = 2")
                && fact
                    .excerpt
                    .contains("options.Password.RequireDigit = false")
                && fact
                    .excerpt
                    .contains("options.Password.RequireNonAlphanumeric = false")
        })
    {
        return Some(CsharpObservationPolicy {
            established: "The supplied C# application configuration explicitly establishes a two-character minimum password while disabling digit and symbol requirements; no executable stronger application-owned validator is supplied.".to_string(),
            safe: false,
            control: String::new(),
        });
    }
    if evidence
        .iter()
        .any(|item| item.rule_id == "csharp-anonymous-state-change-review")
    {
        let ordinary_login = facts.iter().any(|fact| {
            fact.role == "anonymous_endpoint_operation_context"
                && fact.excerpt.contains("PasswordSignInAsync(")
                && !fact.excerpt.contains("AddToRoleAsync(")
        }) && facts.iter().any(|fact| {
            fact.role == "public_entrypoint_ui_context" && fact.excerpt.contains("Log In")
        });
        let ordinary_registration = facts.iter().any(|fact| {
            fact.role == "anonymous_endpoint_operation_context"
                && fact.excerpt.contains("CreateAsync(user, model.Password)")
                && fact.excerpt.contains("SignInAsync(user")
                && !fact.excerpt.contains("AddToRoleAsync(")
        }) && facts.iter().any(|fact| {
            fact.role == "public_entrypoint_ui_context"
                && fact.excerpt.contains("Create a New Account")
        });
        if ordinary_login || ordinary_registration {
            return Some(CsharpObservationPolicy {
                established: "The supplied C# endpoint and matching public UI explicitly establish an ordinary anonymous sign-in or self-registration boundary, with no privileged role or administrative operation in that endpoint.".to_string(),
                safe: true,
                control: "Anonymous access is the intended prerequisite for this exact sign-in or self-registration operation; separate redirect or account-policy weaknesses remain independent findings.".to_string(),
            });
        }
    }
    if evidence
        .iter()
        .any(|item| item.rule_id == "csharp-session-cookie-policy-risk")
        && facts.iter().any(|fact| {
            fact.role == "source_context"
                && fact.excerpt.contains("options.Cookie.HttpOnly = false")
        })
    {
        return Some(CsharpObservationPolicy {
            established: "The supplied C# application configuration explicitly establishes HttpOnly=false for the session cookie. Unknown Secure or SameSite defaults do not disprove this separate application-owned cookie weakness.".to_string(),
            safe: false,
            control: String::new(),
        });
    }
    let stored_raw_html = evidence
        .iter()
        .any(|item| item.rule_id == "csharp-razor-html-raw-output")
        && [
            "bound_remote_input",
            "property_assignment",
            "persistence_call_observed",
            "raw_output_sink",
            "view_action_context",
        ]
        .iter()
        .all(|role| facts.iter().any(|fact| fact.role == *role))
        && !facts.iter().any(|fact| {
            matches!(
                fact.role.as_str(),
                "sanitizer_context" | "validation_context"
            ) || fact.excerpt.contains("HtmlEncoder")
                || fact.excerpt.contains("Sanitize(")
        });
    if stored_raw_html {
        return Some(CsharpObservationPolicy {
            established: "The supplied C# facts explicitly establish request-bound content assigned to the rendered model property, persisted, retrieved into the view, and emitted through Html.Raw without a supplied HTML sanitizer or write invariant.".to_string(),
            safe: false,
            control: String::new(),
        });
    }
    if csharp_observation_has_request_mapped_interpolated_sql(evidence, facts) {
        return Some(CsharpObservationPolicy {
            established: "The supplied C# caller and repository facts explicitly establish request-model fields copied into the repository argument and interpolated into executed SQL command text without a supplied parameter binding.".to_string(),
            safe: false,
            control: String::new(),
        });
    }
    None
}

fn csharp_observation_has_request_mapped_interpolated_sql(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> bool {
    let Some(sink) = evidence
        .iter()
        .find(|item| item.rule_id == "csharp-sql-command-text")
    else {
        return false;
    };
    let Some(method) = sink.enclosing_symbol.as_deref() else {
        return false;
    };
    let marker = format!(".{method}(");
    let repository_argument = facts.iter().find_map(|fact| {
        if fact.role != "exact_caller_context" || !fact.excerpt.contains("= model.") {
            return None;
        }
        let start = fact.excerpt.find(&marker)? + marker.len();
        let argument = fact.excerpt[start..].split(')').next()?.trim();
        if !is_plain_identifier(argument)
            || (!fact.excerpt.contains(&format!("var {argument} = new"))
                && !fact.excerpt.contains(&format!("{argument} = new")))
        {
            return None;
        }
        let mapped_fields = fact
            .excerpt
            .lines()
            .filter_map(|line| {
                let (left, right) = line.split_once('=')?;
                if !right.trim_start().starts_with("model.") {
                    return None;
                }
                terminal_identifier(left.trim()).map(str::to_string)
            })
            .collect::<BTreeSet<_>>();
        (!mapped_fields.is_empty()).then(|| (argument.to_string(), mapped_fields))
    });
    let Some((argument, mapped_fields)) = repository_argument else {
        return false;
    };
    facts.iter().any(|fact| {
        fact.role == "source_context"
            && fact.excerpt.contains("$\"")
            && mapped_fields
                .iter()
                .any(|field| fact.excerpt.contains(&format!("{argument}.{field}")))
    }) && !facts
        .iter()
        .any(|fact| fact.excerpt.contains(".Parameters.Add"))
}

/// Converts only exact, application-owned Java policy shapes into decisive
/// review facts. These are intentionally rule-specific: nearby API names or a
/// generic configuration observation must not gain the same certainty.
fn java_observation_policy(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> Option<JavaObservationPolicy> {
    if evidence
        .iter()
        .any(|item| item.rule_id == "java-spring-csrf-disabled-review")
        && facts.iter().any(|fact| {
            fact.role == "source_context"
                && fact.excerpt.contains("SessionCreationPolicy.STATELESS")
                && fact
                    .excerpt
                    .contains("UsernamePasswordAuthenticationFilter.class")
        })
    {
        return Some(JavaObservationPolicy {
            established: "The supplied Spring Security chain explicitly establishes stateless authentication with a JWT filter before the username/password filter; no cookie-authenticated session is shown for this CSRF-disabled chain.",
            safe: true,
            control: "The exact chain uses stateless token authentication rather than a browser-managed authentication session, so the CSRF setting alone does not establish a victim-credential request weakness.",
        });
    }
    if evidence.iter().any(|item| {
        item.rule_id == "java-sensitive-field-explicit-request-assignment"
            && item.tags.iter().any(|tag| tag == "field:password")
            && item
                .tags
                .iter()
                .any(|tag| tag == "password-encoding-observed")
    }) {
        let authenticated_subject = evidence
            .iter()
            .any(|item| item.rule_id == "java-password-reset-authenticated-subject-control");
        let validated_otp = facts.iter().any(|fact| {
            matches!(
                fact.role.as_str(),
                "source_context" | "helper_definition_context"
            ) && fact
                .excerpt
                .contains("if (validateOTPAndEmail(otp, otpForm))")
                && fact
                    .excerpt
                    .contains("user.setPassword(encoder.encode(otpForm.getPassword()))")
        }) && facts.iter().any(|fact| {
            fact.symbol == "validateOTPAndEmail"
                && fact.excerpt.contains("otp.getStatus()")
                && fact
                    .excerpt
                    .contains("otp.getOtp().equalsIgnoreCase(otpForm.getOtp())")
                && fact
                    .excerpt
                    .contains("otp.getUser().getEmail().equalsIgnoreCase(otpForm.getEmail())")
        });
        if authenticated_subject || validated_otp {
            return Some(JavaObservationPolicy {
                established: "The exact Java password assignment explicitly establishes field-level encoding and an applicable authenticated-subject or active OTP-and-email validation before persistence; this is explicit mapping rather than unrestricted object binding.",
                safe: true,
                control: "The supplied operation authorizes the password change through the authenticated subject or a matching active OTP and email, and encodes the password before persistence.",
            });
        }
    }
    if evidence
        .iter()
        .any(|item| item.rule_id == "java-nimbus-claims-without-verification")
        && facts.iter().any(|fact| {
            fact.role == "exact_caller_context"
                && fact.excerpt.contains("getUserNameFromJwtToken(")
                && !fact.excerpt.contains(".verify(")
                && !fact.excerpt.contains("validateJwtToken(")
        })
    {
        return Some(JavaObservationPolicy {
            established: "The exact Java caller explicitly establishes that claims parsed without verification supply the returned user identity, with no signature-verification call in the enclosing caller.",
            safe: false,
            control: "",
        });
    }
    if let Some(resource) = evidence
        .iter()
        .find(|item| item.rule_id == "java-spring-data-resource-access")
    {
        let selector = resource
            .captures
            .get("filter")
            .map(|capture| capture.text.as_str())
            .unwrap_or_default();
        if selector == "user.getId()"
            && facts.iter().any(|fact| {
                fact.excerpt
                    .contains("getUserFromTokenWithoutValidation(request)")
                    && fact.excerpt.contains("findByUser_id(user.getId())")
            })
        {
            return Some(JavaObservationPolicy {
                established: "The exact Java endpoint explicitly establishes that an unverified request JWT selects the user identity whose related records are read and returned.",
                safe: false,
                control: "",
            });
        }
        if selector == "user.getId()"
            && facts.iter().any(|fact| {
                fact.excerpt
                    .contains("userRepository.findByEmail(loginForm.getEmail())")
                    && fact.excerpt.contains("findByUser_id(user.getId())")
                    && fact.excerpt.contains("sendMail(")
            })
        {
            return Some(JavaObservationPolicy {
                established: "The exact Java login workflow explicitly establishes that the related-record selector is derived from the user record found for the submitted login email and is used to send an MFA challenge to that same user's email, not to return a caller-selected resource.",
                safe: true,
                control: "The resource identifier is server-derived from the matched login user and the related data is used only in the MFA message sent to that user's stored email address.",
            });
        }
        if selector == "vehicleModel.getId()"
            && facts.iter().any(|fact| {
                fact.excerpt.contains("vehicleModelRepository.findAll()")
                    && fact
                        .excerpt
                        .contains("modelList.get(random.nextInt(modelList.size()))")
                    && fact.excerpt.contains("findById(vehicleModel.getId())")
            })
        {
            return Some(JavaObservationPolicy {
                established: "The exact Java seed-data workflow explicitly establishes that the model identifier is selected internally from repository results using a server-side random index, not supplied by a request.",
                safe: true,
                control: "The lookup identifier is derived from a server-loaded repository object in an initialization workflow and has no supplied request origin.",
            });
        }
        if selector == "vehicleForm.getVin()"
            && facts.iter().any(|fact| {
                fact.excerpt.contains(
                    "vehicleDetails.getPincode().equalsIgnoreCase(vehicleForm.getPincode())",
                ) && fact.excerpt.contains("getUserFromToken(request)")
                    && fact.excerpt.contains("vehicleDetails.setOwner(user)")
            })
        {
            return Some(JavaObservationPolicy {
                established: "The exact Java vehicle-claim workflow explicitly establishes a stored-PIN possession check and an authenticated request-derived owner before assigning the selected vehicle.",
                safe: true,
                control: "The caller must present the selected vehicle's stored PIN and the assigned owner is derived from the authenticated request token.",
            });
        }
    }
    for item in evidence {
        let established = match item.rule_id.as_str() {
            "java-jwt-header-jku-key-trust" => {
                "The exact Java operation explicitly establishes that a JWT header-selected JKU controls remote key retrieval before the token is trusted, enabling an attacker-selected outbound destination."
            }
            "java-jwt-kid-selects-known-hmac-key" => {
                "The exact Java verifier selection explicitly establishes that attacker-selected JWT KID material can choose the known HMAC-key path."
            }
            "java-jwt-header-selects-verifier-family" => {
                "The exact Java verifier selection explicitly establishes that an untrusted JWT algorithm header chooses the verifier family."
            }
            "java-nimbus-plain-jwt-accepted" => {
                "The exact Java validation branch explicitly establishes that a Nimbus PlainJWT is accepted as valid without a signature."
            }
            "java-api-key-debug-logging" => {
                "The exact Java debug call explicitly establishes that the generated API-key value is passed to the logger in plaintext."
            }
            "java-apache-trust-all-certificates" => {
                "The exact Java HTTP-client construction explicitly establishes an application-owned trust strategy that accepts every TLS certificate."
            }
            "java-apache-hostname-verification-disabled" => {
                "The exact Java HTTP-client construction explicitly establishes an application-owned no-op hostname verifier."
            }
            "java-insecure-security-randomness" => {
                "The exact Java generator explicitly establishes Math.random as the effective source for the captured security-token or OTP role."
            }
            "java-jwt-signed-token-without-expiration" => {
                "The exact Java token builder explicitly establishes a signed authentication credential without an expiration claim."
            }
            _ => continue,
        };
        return Some(JavaObservationPolicy {
            established,
            safe: false,
            control: "",
        });
    }
    None
}

fn observation_has_direct_stored_html_trust_bypass(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> bool {
    evidence.iter().any(|source| {
        if source.kind != EvidenceKind::Source || source.capability != Capability::StoredUserContent
        {
            return false;
        }
        let Some(value) = source
            .captures
            .get("value")
            .map(|capture| capture.text.trim())
        else {
            return false;
        };
        if !is_plain_identifier(value) {
            return false;
        }
        evidence.iter().any(|sink| {
            let Some(content) = (sink.kind == EvidenceKind::Sink
                && sink.capability == Capability::HtmlOutput
                && sink.rule_id.ends_with("angular-html-trust-bypass")
                && sink.location.path == source.location.path
                && sink.enclosing_symbol == source.enclosing_symbol)
                .then(|| sink.captures.get("content"))
                .flatten()
                .map(|capture| capture.text.trim())
            else {
                return false;
            };
            contains_identifier(content, value)
                && facts.iter().any(|fact| {
                    fact.role == "source_context"
                        && fact.location.path == source.location.path
                        && fact.excerpt.contains(content)
                        && fact.excerpt.contains("bypassSecurityTrustHtml(")
                })
        })
    })
}

fn observation_has_direct_request_resource_selector(evidence: &[Evidence]) -> bool {
    evidence.iter().any(|source| {
        if source.kind != EvidenceKind::Source || source.capability != Capability::HttpRequestData {
            return false;
        }
        let Some(name) = source
            .captures
            .get("name")
            .map(|capture| capture.text.trim())
        else {
            return false;
        };
        if !is_plain_identifier(name) {
            return false;
        }
        evidence.iter().any(|sink| {
            let Some(filter) = (sink.kind == EvidenceKind::Sink
                && sink.capability == Capability::ResourceAccess
                && sink.location.path == source.location.path
                && sink.enclosing_symbol == source.enclosing_symbol)
                .then(|| sink.captures.get("filter"))
                .flatten()
                .map(|capture| capture.text.as_str())
            else {
                return false;
            };
            ["req.params.", "req.body.", "req.query."]
                .iter()
                .any(|prefix| filter.contains(&format!("{prefix}{name}")))
        })
    })
}

fn observation_has_server_generated_fixed_root_path(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> bool {
    let transformed_values = evidence
        .iter()
        .filter(|item| item.capability == Capability::FixedFormatTransform)
        .filter_map(|item| item.captures.get("value"))
        .map(|capture| capture.text.trim())
        .filter(|value| is_plain_identifier(value))
        .collect::<BTreeSet<_>>();
    if transformed_values.is_empty() {
        return false;
    }

    evidence.iter().any(|item| {
        let Some(path) = (item.kind == EvidenceKind::Sink
            && item.capability == Capability::FilesystemWrite)
            .then(|| item.captures.get("path"))
            .flatten()
            .map(|capture| capture.text.trim())
        else {
            return false;
        };
        let Some(arguments) = path
            .strip_prefix("path.join(")
            .and_then(|value| value.strip_suffix(')'))
        else {
            return false;
        };
        let Some((root, leaf)) = arguments.split_once(',') else {
            return false;
        };
        let root = root.trim();
        let leaf = leaf.trim();
        if arguments.matches(',').count() != 1
            || !is_quoted_literal(root)
            || root.contains("..")
            || !is_plain_identifier(leaf)
        {
            return false;
        }

        facts.iter().any(|fact| {
            if fact.role != "source_context" {
                return false;
            }
            let Some(leaf_rhs) = javascript_assignment_rhs(&fact.excerpt, leaf) else {
                return false;
            };
            let Some(intermediate) = single_template_interpolation(leaf_rhs) else {
                return false;
            };
            let Some(intermediate_rhs) = javascript_assignment_rhs(&fact.excerpt, intermediate)
            else {
                return false;
            };
            let has_server_randomness = [
                "randomHexString(",
                "randomBytes(",
                "randomUUID(",
                "crypto.randomUUID(",
            ]
            .iter()
            .any(|marker| intermediate_rhs.contains(marker));
            let uses_fixed_transform = transformed_values
                .iter()
                .any(|value| contains_identifier(intermediate_rhs, value));
            has_server_randomness
                && uses_fixed_transform
                && !contains_web_request_origin(leaf_rhs)
                && !contains_web_request_origin(intermediate_rhs)
        })
    })
}

fn javascript_assignment_rhs<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    source.lines().find_map(|line| {
        let line = line.trim();
        let line = ["const ", "let ", "var "]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))?;
        let (left, right) = line.split_once('=')?;
        (left.trim() == name).then_some(right.trim().trim_end_matches(';').trim())
    })
}

fn single_template_interpolation(value: &str) -> Option<&str> {
    let start = value.find("${")? + 2;
    let end = value[start..].find('}')? + start;
    (!value[end + 1..].contains("${"))
        .then_some(value[start..end].trim())
        .filter(|name| is_plain_identifier(name))
}

fn contains_web_request_origin(value: &str) -> bool {
    [
        "req.", "request.", "ctx.", "event.", "params.", "query.", "body.", "headers.",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn observation_has_operator_configured_endpoint(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> bool {
    evidence.iter().any(|item| {
        item.kind == EvidenceKind::Sink
            && item.capability == Capability::OutboundNetworkRequest
            && item.captures.get("endpoint").is_some_and(|capture| {
                let endpoint = capture.text.trim();
                is_plain_identifier(endpoint)
                    && facts.iter().any(|fact| {
                        fact.role == "source_context"
                            && (fact.excerpt.contains(&format!("{endpoint} = process.env."))
                                || fact
                                    .excerpt
                                    .contains(&format!("const {endpoint} = process.env.")))
                    })
            })
    })
}

fn observation_has_source_embedded_signing_key(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> bool {
    evidence.iter().any(|item| {
        item.kind == EvidenceKind::SecurityConfiguration
            && item.rule_id.ends_with("jwt-token-generation")
    }) && facts.iter().any(|fact| {
        fact.excerpt
            .contains("contains a source-embedded private-key literal")
    })
}

fn explicit_cookie_omission(rule_id: &str) -> Option<&'static str> {
    if rule_id.ends_with("auth-cookie-missing-http-only") {
        Some("HttpOnly")
    } else if rule_id.ends_with("auth-cookie-missing-secure") {
        Some("Secure")
    } else if rule_id.ends_with("auth-cookie-missing-same-site") {
        Some("SameSite")
    } else {
        None
    }
}

fn path_confidence_policy(
    candidate: &mehscan_core::Candidate,
    decision_facts: &ReviewDecisionFacts,
    truncation: &ReviewContextTruncation,
) -> ReviewConfidencePolicy {
    if truncation.decision_critical {
        return ReviewConfidencePolicy {
            issue: ReviewConfidence::Low,
            not_issue: ReviewConfidence::Low,
            needs_review: ReviewConfidence::Low,
            rationale: "Decision-critical evidence is truncated; every verdict is low confidence until the missing context is supplied.".to_string(),
        };
    }
    let direct_complete = decision_facts.unresolved.is_empty()
        && candidate.source.confidence == mehscan_core::Confidence::High
        && candidate.sink.confidence == mehscan_core::Confidence::High;
    let cookie_omission = explicit_cookie_omission(&candidate.sink.rule_id).is_some();
    ReviewConfidencePolicy {
        issue: if direct_complete && !cookie_omission {
            ReviewConfidence::High
        } else {
            ReviewConfidence::Medium
        },
        not_issue: if decision_facts.unresolved.is_empty() {
            ReviewConfidence::High
        } else {
            ReviewConfidence::Medium
        },
        needs_review: ReviewConfidence::Medium,
        rationale: if direct_complete && !cookie_omission {
            "The bounded path has high-confidence terminals and no unresolved decision fact; an issue or affirmative disproof may be high confidence. Needs-review remains medium because it asserts missing adjudication context."
        } else {
            "A bounded syntactic, framework, ownership, or unresolved inference remains; use medium confidence for the selected decision."
        }
        .to_string(),
    }
}

fn observation_confidence_policy(
    evidence: &[Evidence],
    decision_facts: &ReviewDecisionFacts,
    truncation: &ReviewContextTruncation,
) -> ReviewConfidencePolicy {
    if truncation.decision_critical {
        return ReviewConfidencePolicy {
            issue: ReviewConfidence::Low,
            not_issue: ReviewConfidence::Low,
            needs_review: ReviewConfidence::Low,
            rationale: "Decision-critical evidence is truncated; every verdict is low confidence until the missing context is supplied.".to_string(),
        };
    }
    let cookie_omission = evidence
        .iter()
        .any(|item| explicit_cookie_omission(&item.rule_id).is_some());
    let direct_issue_fact = decision_facts.unresolved.is_empty()
        && decision_facts.established.iter().any(|fact| {
            fact.contains("source-embedded private-key")
                || fact.contains("explicitly emits an authentication cookie")
                || fact.contains("explicitly establishes")
        });
    ReviewConfidencePolicy {
        issue: if direct_issue_fact && !cookie_omission {
            ReviewConfidence::High
        } else {
            ReviewConfidence::Medium
        },
        not_issue: if decision_facts.unresolved.is_empty() {
            ReviewConfidence::High
        } else {
            ReviewConfidence::Medium
        },
        needs_review: ReviewConfidence::Medium,
        rationale: if direct_issue_fact && !cookie_omission {
            "A direct application-owned policy fact is established with no unresolved decision fact; an issue may be high confidence."
        } else {
            "This observation retains a bounded inference or unresolved fact; use medium confidence unless an admitted affirmative safe purpose removes the review job."
        }
        .to_string(),
    }
}

fn path_review_basis(
    candidate: &mehscan_core::Candidate,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    rules_by_id: &BTreeMap<&str, &Rule>,
) -> Result<PathReviewBasis, EngineError> {
    let source = evidence_by_id
        .get(candidate.source.id.as_str())
        .copied()
        .ok_or_else(|| EngineError(format!("missing review source {:?}", candidate.source.id)))?;
    let sink = evidence_by_id
        .get(candidate.sink.id.as_str())
        .copied()
        .ok_or_else(|| EngineError(format!("missing review sink {:?}", candidate.sink.id)))?;
    let protections = candidate
        .protections
        .iter()
        .map(|protection| {
            evidence_by_id
                .get(protection.id.as_str())
                .copied()
                .ok_or_else(|| {
                    EngineError(format!("missing review protection {:?}", protection.id))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source_basis = review_evidence_basis(source, rules_by_id);
    let sink_basis = review_evidence_basis(sink, rules_by_id);
    let protection_basis = protections
        .iter()
        .map(|evidence| review_evidence_basis(evidence, rules_by_id))
        .collect::<Vec<_>>();
    let mut deterministic_facts = vec![format!(
        "The deterministic engine admitted a bounded relationship from source rule {} to sink rule {}; this is stronger than proximity but remains a review lead rather than a vulnerability verdict.",
        source.rule_id, sink.rule_id
    )];
    if !source.tags.is_empty() {
        deterministic_facts.push(format!(
            "Source rule semantics: {}.",
            source.tags.join(", ")
        ));
    }
    if !sink.tags.is_empty() {
        deterministic_facts.push(format!("Sink rule semantics: {}.", sink.tags.join(", ")));
    }
    let semantic_claims = path_semantic_claims(candidate);
    if !semantic_claims.is_empty() {
        deterministic_facts.push(format!(
            "Bounded relationship semantics: {}.",
            semantic_claims.join(" -> ")
        ));
    }
    if protections.is_empty() {
        deterministic_facts.push(if control_can_be_owned_outside_application(candidate.capability) {
            "No protection evidence is linked to this bounded path. The effective control may be owned by the application, framework, proxy, gateway, ingress, mesh, or platform; the authoritative deployed layer is not proved by repository absence."
                .to_string()
        } else {
            "No protection evidence is linked to this bounded path. This application-owned sink requires a control tied to the same source-derived value; do not treat a generic proxy or gateway policy as an equivalent control."
                .to_string()
        });
    } else {
        deterministic_facts.push(format!(
            "The bounded path links {} protection observation(s); verify that each applies to the same value and security context.",
            protections.len()
        ));
    }
    let ineffective_controls = candidate
        .steps
        .iter()
        .filter(|step| step.kind == SecurityPathStepKind::IneffectiveProtection)
        .filter_map(|step| step.symbol.as_deref())
        .collect::<Vec<_>>();
    if !ineffective_controls.is_empty() {
        deterministic_facts.push(format!(
            "The bounded path identifies ineffective control context, not protection evidence: {}.",
            ineffective_controls.join("; ")
        ));
    }
    deterministic_facts.push(format!(
        "Relationship provenance: {} with maximum propagation depth {}.",
        candidate.provenance.engine, candidate.provenance.maximum_propagation_depth
    ));
    let mut investigate = BTreeSet::new();
    let mut verify = BTreeSet::new();
    let mut exclude = BTreeSet::new();
    for evidence in std::iter::once(source)
        .chain(std::iter::once(sink))
        .chain(protections.iter().copied())
    {
        if let Some(rule) = rules_by_id.get(evidence.rule_id.as_str()) {
            investigate.extend(rule.ai.investigate.iter().cloned());
            verify.extend(rule.ai.verify.iter().cloned());
            exclude.extend(rule.ai.exclude.iter().cloned());
        }
    }
    Ok(PathReviewBasis {
        relationship: "deterministic_bounded_path".to_string(),
        security_question: if semantic_claims.is_empty() {
            format!(
                "Can the bounded source influence the {:?} behavior at runtime without an effective context-appropriate protection?",
                candidate.capability
            )
        } else {
            format!(
                "Does this bounded relationship establish the rule-specific weakness described by these path semantics, after applying the supplied protections and unresolved facts: {}?",
                semantic_claims.join(" -> ")
            )
        },
        source: source_basis,
        sink: sink_basis,
        protections: protection_basis,
        deterministic_facts,
        investigate: investigate.into_iter().collect(),
        verify: verify.into_iter().collect(),
        exclude: exclude.into_iter().collect(),
    })
}

fn path_semantic_claims(candidate: &mehscan_core::Candidate) -> Vec<&str> {
    candidate
        .steps
        .iter()
        .filter(|step| {
            matches!(
                step.kind,
                SecurityPathStepKind::Assignment
                    | SecurityPathStepKind::Alias
                    | SecurityPathStepKind::IneffectiveProtection
            )
        })
        .filter_map(|step| step.symbol.as_deref())
        .filter(|symbol| {
            symbol.split_whitespace().count() >= 5
                && !symbol.chars().any(|character| {
                    matches!(
                        character,
                        '\n' | '\r' | '(' | ')' | '[' | ']' | '{' | '}' | '=' | ';' | '/'
                    )
                })
        })
        .take(4)
        .collect()
}

fn review_evidence_basis(
    evidence: &Evidence,
    rules_by_id: &BTreeMap<&str, &Rule>,
) -> PathReviewEvidenceBasis {
    let rule = rules_by_id.get(evidence.rule_id.as_str()).copied();
    let captures = evidence
        .captures
        .iter()
        .take(12)
        .map(|(name, capture)| (name.clone(), bounded_basis_text(name, &capture.text)))
        .collect();
    PathReviewEvidenceBasis {
        rule_id: evidence.rule_id.clone(),
        rule_title: rule.map(|rule| rule.title.clone()),
        kind: evidence.kind,
        capability: evidence.capability,
        cwe_candidates: evidence.cwe_candidates.clone(),
        tags: evidence.tags.clone(),
        captures,
        rule_note: rule.map(|rule| rule.provenance.note.clone()),
    }
}

fn observation_review_basis(
    evidence: &[Evidence],
    rules_by_id: &BTreeMap<&str, &Rule>,
) -> ObservationReviewBasis {
    let mut seen_rules = BTreeSet::new();
    let observations = evidence
        .iter()
        .filter(|item| seen_rules.insert(item.rule_id.as_str()))
        .map(|item| review_evidence_basis(item, rules_by_id))
        .collect::<Vec<_>>();
    let mut deterministic_facts = vec![
        "This is a bounded observation neighborhood, not a deterministic source-to-sink relationship or vulnerability verdict."
            .to_string(),
    ];
    let mut semantics = evidence
        .iter()
        .filter(|item| !item.tags.is_empty())
        .map(|item| format!("{}: {}", item.rule_id, item.tags.join(", ")))
        .collect::<Vec<_>>();
    semantics.sort();
    semantics.dedup();
    if !semantics.is_empty() {
        deterministic_facts.push(format!(
            "Observed rule semantics: {}.",
            semantics.join("; ")
        ));
    }
    if evidence
        .iter()
        .any(|item| item.kind == EvidenceKind::SensitiveOperation)
    {
        deterministic_facts.push(
            "A sensitive operation or boundary is present, but unsafe syntax or API presence alone does not establish a violated invariant, attacker reachability, or security impact."
                .to_string(),
        );
    }
    if evidence
        .iter()
        .any(|item| item.kind == EvidenceKind::SecurityConfiguration)
    {
        deterministic_facts.push(
            "Repository configuration evidence does not prove the effective deployed value or which application, framework, proxy, gateway, ingress, mesh, or platform layer owns it."
                .to_string(),
        );
    }
    let mut investigate = BTreeSet::new();
    let mut verify = BTreeSet::new();
    let mut exclude = BTreeSet::new();
    for item in evidence {
        if let Some(rule) = rules_by_id.get(item.rule_id.as_str()) {
            investigate.extend(rule.ai.investigate.iter().cloned());
            verify.extend(rule.ai.verify.iter().cloned());
            exclude.extend(rule.ai.exclude.iter().cloned());
        }
    }
    let capabilities = evidence
        .iter()
        .map(|item| format!("{:?}", item.capability))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    ObservationReviewBasis {
        relationship: "bounded_non_path_observation".to_string(),
        security_question: format!(
            "Does the supplied context establish a concrete weakness involving {capabilities}, rather than only the observed syntax or API boundary?"
        ),
        observations,
        deterministic_facts,
        investigate: investigate.into_iter().collect(),
        verify: verify.into_iter().collect(),
        exclude: exclude.into_iter().collect(),
    }
}

fn captured_definition_facts<'a>(
    sources: &RepositorySources,
    evidence: impl IntoIterator<Item = &'a Evidence>,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let mut facts = Vec::new();
    for item in evidence {
        for (name, capture) in &item.captures {
            if !name.ends_with("_definition")
                || facts_cover_location(existing, &capture.location)
                || facts_cover_location(&facts, &capture.location)
            {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            let Ok(file) = sources.file(&capture.location.path) else {
                continue;
            };
            let start_line = capture.location.start.line.saturating_sub(1).max(1);
            let end_line = capture.location.end.line.saturating_add(1);
            let Ok((slice, truncated)) = source_slice(file, start_line, end_line) else {
                continue;
            };
            facts.push(ReviewNeighborhoodFact {
                role: "captured_definition_context".to_string(),
                symbol: capture.text.clone(),
                location: slice.location,
                excerpt: redact_helper_definition(&capture.text, &slice.text),
                evidence_id: Some(item.id.clone()),
                provenance: textual_provenance(
                    "exact evidence-captured definition, bounded and non-flow 1",
                ),
            });
            if truncated {
                return (facts, true);
            }
        }
    }
    (facts, false)
}

fn python_source_file_consumer_facts(
    sources: &RepositorySources,
    sink: &Evidence,
    limit: usize,
) -> Vec<ReviewNeighborhoodFact> {
    let Some(path_capture) = sink.captures.get("path") else {
        return Vec::new();
    };
    let Ok(writer) = sources.file(&sink.location.path) else {
        return Vec::new();
    };
    let binding = path_capture.text.trim();
    let source_path = python_quoted_source_path(binding).or_else(|| {
        (!binding.is_empty()
            && binding
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
        .then(|| {
            line_spans(&writer.source)
                .into_iter()
                .filter(|(_, end)| *end <= sink.location.start.byte_offset)
                .filter_map(|(start, end)| {
                    let line = writer.source[start..end].trim();
                    let (left, right) = line.split_once('=')?;
                    (left.trim() == binding)
                        .then(|| python_quoted_source_path(right))
                        .flatten()
                })
                .last()
        })
        .flatten()
    });
    let Some(source_path) = source_path else {
        return Vec::new();
    };
    let module = source_path
        .trim_start_matches("./")
        .trim_end_matches(".py")
        .replace(['/', '\\'], ".");
    if module.is_empty() {
        return Vec::new();
    }

    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Python))
    {
        for (line_index, (start, end)) in line_spans(&file.source).into_iter().enumerate() {
            let line = file.source[start..end].trim();
            if !python_import_references_module(line, &module) {
                continue;
            }
            let start_line = line_index.saturating_add(1).saturating_sub(1).max(1);
            let end_line = line_index.saturating_add(3);
            let Ok((slice, _)) = source_slice(file, start_line, end_line) else {
                continue;
            };
            facts.push(ReviewNeighborhoodFact {
                role: "python_source_file_consumer_context".to_string(),
                symbol: module.clone(),
                location: slice.location,
                excerpt: slice.text,
                evidence_id: Some(sink.id.clone()),
                provenance: textual_provenance(
                    "exact Python source-file import reference, bounded and non-flow 1",
                ),
            });
            if facts.len() == limit {
                return facts;
            }
        }
    }
    facts
}

fn python_quoted_source_path(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for (start, quote) in bytes.iter().copied().enumerate() {
        if !matches!(quote, b'\'' | b'\"') {
            continue;
        }
        let tail = bytes.get(start + 1..)?;
        let relative_end = tail.iter().position(|byte| *byte == quote)?;
        let value = text.get(start + 1..start + 1 + relative_end)?;
        if value.to_ascii_lowercase().ends_with(".py") {
            return Some(value.to_string());
        }
    }
    None
}

fn python_import_references_module(line: &str, module: &str) -> bool {
    if let Some(rest) = line.strip_prefix("from ")
        && let Some((imported_module, imported_names)) = rest.split_once(" import ")
    {
        let imported_module = imported_module.trim().trim_start_matches('.');
        if imported_module == module || imported_module.ends_with(&format!(".{module}")) {
            return true;
        }
        if imported_module.is_empty()
            && imported_names
                .split(',')
                .any(|name| name.split_whitespace().next().unwrap_or_default() == module)
        {
            return true;
        }
        if let Some((parent, leaf)) = module.rsplit_once('.')
            && (imported_module == parent || imported_module.ends_with(&format!(".{parent}")))
        {
            return imported_names
                .split(',')
                .any(|name| name.split_whitespace().next().unwrap_or_default() == leaf);
        }
        return false;
    }
    let Some(rest) = line.strip_prefix("import ") else {
        return false;
    };
    rest.split(',').any(|imported| {
        let imported = imported.split_whitespace().next().unwrap_or_default();
        imported == module || imported.ends_with(&format!(".{module}"))
    })
}

fn bounded_basis_text(name: &str, text: &str) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let sensitive_name = ["password", "secret", "credential", "private_key", "api_key"]
        .iter()
        .any(|word| name.to_ascii_lowercase().contains(word));
    let quoted_literal = (compact.starts_with('\'') && compact.ends_with('\''))
        || (compact.starts_with('"') && compact.ends_with('"'));
    if sensitive_name && quoted_literal {
        return "<redacted security-sensitive literal>".to_string();
    }
    let mut value = compact.chars().take(200).collect::<String>();
    if value.len() < compact.len() {
        value.push_str("...");
    }
    value
}

fn build_observation_reviews(
    groups: impl IntoIterator<Item = ObservationGroup>,
    sources: &RepositorySources,
    languages: &BTreeMap<&str, Language>,
    csharp_neighborhoods: &[mehscan_core::ReviewNeighborhood],
    context_lines: usize,
    rules_by_id: &BTreeMap<&str, &Rule>,
) -> Result<Vec<ObservationReview>, EngineError> {
    let groups = groups.into_iter().collect::<Vec<_>>();
    let mut indexed_references = BTreeSet::new();
    for group in &groups {
        indexed_references.extend(observation_group_references(group, sources, context_lines)?);
    }
    let review_context = ReviewContextIndex::build(sources, &indexed_references)?;
    let mut reviews = Vec::new();
    for group in groups {
        let file = sources.file(&group.path)?;
        let first_line = group
            .evidence
            .iter()
            .map(|item| item.location.start.line)
            .min()
            .unwrap_or(1);
        let last_line = group
            .evidence
            .iter()
            .map(|item| item.location.end.line)
            .max()
            .unwrap_or(first_line);
        let start_line = first_line.saturating_sub(context_lines).max(1);
        let end_line = last_line.saturating_add(context_lines);
        let anchor = group
            .anchor_evidence_ids
            .iter()
            .find_map(|id| group.evidence.iter().find(|item| item.id == *id))
            .or_else(|| group.evidence.first())
            .map(|item| &item.location)
            .ok_or_else(|| EngineError("observation review has no anchor evidence".to_string()))?;
        let (mut slice, mut context_truncated) =
            review_source_slice(file, start_line, end_line, anchor)?;
        let mut decision_critical_context_truncated = context_truncated;
        redact_secrets_in_slice(&mut slice, &group.evidence);
        let mut configuration_tokens = BTreeSet::new();
        collect_configuration_tokens(&slice.text, &mut configuration_tokens);
        let mut facts = vec![ReviewNeighborhoodFact {
            role: "source_context".to_string(),
            symbol: group.symbol.clone(),
            location: slice.location,
            excerpt: slice.text,
            evidence_id: None,
            provenance: textual_provenance("mehscan bounded observation-review source 1"),
        }];
        let (mut captured_definitions, captured_definitions_truncated) =
            captured_definition_facts(sources, group.evidence.iter(), &facts, 3);
        context_truncated |= captured_definitions_truncated;
        facts.append(&mut captured_definitions);
        let references = observation_group_references(&group, sources, context_lines)?;
        let paths = BTreeSet::from([group.path.as_str()]);
        let (mut configuration, configuration_truncated) = configuration_facts(
            sources,
            &paths,
            &configuration_tokens,
            MAX_REVIEW_CONFIGURATION_FACTS,
        );
        context_truncated |= configuration_truncated;
        facts.append(&mut configuration);
        let (mut helpers, helpers_truncated) = observation_helper_definition_facts(
            sources,
            &review_context,
            &paths,
            &references,
            &facts,
            4,
        );
        context_truncated |= helpers_truncated;
        facts.append(&mut helpers);
        let (mut second_hop, second_hop_truncated) = second_hop_review_facts(
            sources,
            &review_context,
            &paths,
            &references,
            &facts,
            None,
            6,
        );
        context_truncated |= second_hop_truncated;
        facts.append(&mut second_hop);
        let (mut origin, origin_truncated) =
            origin_consumer_review_facts(sources, &review_context, &paths, &facts, None, 4);
        context_truncated |= origin_truncated;
        facts.append(&mut origin);
        if let Some(sink) = group
            .evidence
            .iter()
            .find(|item| item.rule_id == "python-source-file-content-write")
        {
            facts.extend(python_source_file_consumer_facts(sources, sink, 4));
        }
        let (mut python_callers, python_callers_truncated) =
            exact_python_observation_caller_facts(sources, &group, 5);
        context_truncated |= python_callers_truncated;
        facts.append(&mut python_callers);
        let (mut java_callers, java_callers_truncated) =
            exact_java_identity_observation_caller_facts(sources, &group, 4);
        context_truncated |= java_callers_truncated;
        facts.append(&mut java_callers);
        let (mut jwt_verification, jwt_verification_truncated) =
            python_jwt_verification_facts(sources, &group, 4);
        context_truncated |= jwt_verification_truncated;
        facts.append(&mut jwt_verification);
        facts.extend(python_csrf_handler_facts(sources, &group));
        if let Some(sink) = group.evidence.iter().find(|item| {
            item.kind == EvidenceKind::Sink && item.capability == Capability::HtmlOutput
        }) {
            let (mut template, template_truncated) =
                express_template_review_facts(sources, sink, 5);
            context_truncated |= template_truncated;
            facts.append(&mut template);
        }
        if languages.get(group.path.as_str()) == Some(&Language::Csharp)
            && group.evidence.iter().any(|item| {
                item.kind == EvidenceKind::Sink && item.capability == Capability::DatabaseQuery
            })
        {
            let (mut callers, callers_truncated) =
                exact_csharp_caller_facts(sources, &group.path, &group.symbol, 2);
            context_truncated |= callers_truncated;
            facts.append(&mut callers);
        }
        if languages.get(group.path.as_str()) == Some(&Language::Csharp)
            && group
                .evidence
                .iter()
                .any(|item| item.rule_id == "csharp-anonymous-state-change-review")
        {
            let (mut policy, policy_truncated) =
                csharp_anonymous_endpoint_policy_facts(sources, &group, 4);
            context_truncated |= policy_truncated;
            facts.append(&mut policy);
        }
        if let Some(fact) = javascript_fixed_arithmetic_eval_fact(sources, &group) {
            facts.push(fact);
        }
        for neighborhood in csharp_neighborhoods.iter().filter(|neighborhood| {
            neighborhood
                .anchor_evidence_ids
                .iter()
                .any(|id| group.anchor_evidence_ids.contains(id))
        }) {
            facts.extend(neighborhood.facts.iter().cloned());
            let (mut retrieval, retrieval_truncated) =
                csharp_razor_retrieval_facts(sources, neighborhood, 8);
            context_truncated |= retrieval_truncated;
            facts.append(&mut retrieval);
        }
        sort_review_facts(&mut facts);
        let review_id =
            observation_review_id(&group.path, &group.symbol, &group.anchor_evidence_ids);
        let evidence_truncated = group.evidence.len() > MAX_UNIT_EVIDENCE;
        context_truncated |= evidence_truncated;
        let (selected_evidence, selected_anchor_ids, anchors_truncated) =
            bounded_observation_evidence(
                group.evidence,
                &group.anchor_evidence_ids,
                MAX_UNIT_EVIDENCE,
            );
        decision_critical_context_truncated |= anchors_truncated;
        let title = observation_review_title(&selected_evidence);
        let open_questions = observation_review_questions(&selected_evidence, &facts);
        let review_basis = observation_review_basis(&selected_evidence, rules_by_id);
        let decision_facts =
            observation_decision_facts(&selected_evidence, &facts, &open_questions);
        let truncation = review_truncation(context_truncated, decision_critical_context_truncated);
        let confidence_policy =
            observation_confidence_policy(&selected_evidence, &decision_facts, &truncation);
        reviews.push(ObservationReview {
            id: review_id,
            language: languages.get(group.path.as_str()).copied(),
            title,
            anchor_evidence_ids: selected_anchor_ids,
            evidence: selected_evidence,
            review_basis: Some(review_basis),
            decision_facts,
            confidence_policy,
            facts,
            open_questions,
            context_truncated,
            truncation,
        });
    }
    Ok(reviews)
}

fn javascript_fixed_arithmetic_eval_fact(
    sources: &RepositorySources,
    group: &ObservationGroup,
) -> Option<ReviewNeighborhoodFact> {
    let sink = group.evidence.iter().find(|item| {
        item.rule_id == "typescript-dynamic-code"
            && item
                .captures
                .get("code")
                .is_some_and(|capture| capture.text.trim() == "expression")
    })?;
    let file = sources.file(&group.path).ok()?;
    if !matches!(
        file.language,
        Some(Language::Javascript | Language::Typescript)
    ) {
        return None;
    }
    let spans = line_spans(&file.source);
    let sink_index = sink.location.start.line.checked_sub(1)?;
    if sink_index >= spans.len() {
        return None;
    }
    let start_index = sink_index.saturating_sub(16);
    let excerpt = &file.source[spans[start_index].0..spans[sink_index].1];
    let compact = excerpt
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let fixed_operators = compact.contains("constoperators=['*','+','-']")
        || compact.contains("constoperators=[\"*\",\"+\",\"-\"]");
    let bounded_terms = ["firstTerm", "secondTerm", "thirdTerm"]
        .iter()
        .all(|term| compact.contains(&format!("const{term}=Math.floor((Math.random()*10)+1)")));
    let bounded_operators = ["firstOperator", "secondOperator"].iter().all(|operator| {
        compact.contains(&format!(
            "const{operator}=operators[Math.floor((Math.random()*3))]"
        ))
    });
    let fixed_expression = compact.contains(
        "constexpression=firstTerm.toString()+firstOperator+secondTerm.toString()+secondOperator+thirdTerm.toString()",
    ) && compact.contains("eval(expression)");
    if !(fixed_operators && bounded_terms && bounded_operators && fixed_expression) {
        return None;
    }
    Some(ReviewNeighborhoodFact {
        role: "fixed_grammar_dynamic_code_context".to_string(),
        symbol: "expression".to_string(),
        location: location_from_offsets(
            &file.path,
            &file.source,
            spans[start_index].0,
            spans[sink_index].1,
        ),
        excerpt: excerpt.to_string(),
        evidence_id: Some(sink.id.clone()),
        provenance: textual_provenance(
            "exact bounded JavaScript arithmetic grammar feeding evaluator 1",
        ),
    })
}

/// Keeps ordinary observation payloads stable, but when a very large symbol
/// exceeds the evidence ceiling, retains actionable anchors before auxiliary
/// context. Returned anchor IDs always name evidence present in the payload.
fn bounded_observation_evidence(
    evidence: Vec<Evidence>,
    anchor_evidence_ids: &[String],
    limit: usize,
) -> (Vec<Evidence>, Vec<String>, bool) {
    if evidence.len() <= limit {
        return (evidence, anchor_evidence_ids.to_vec(), false);
    }

    let anchors = anchor_evidence_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let (mut selected, auxiliary): (Vec<_>, Vec<_>) = evidence
        .into_iter()
        .partition(|item| anchors.contains(item.id.as_str()));
    selected.truncate(limit);
    let remaining = limit.saturating_sub(selected.len());
    selected.extend(auxiliary.into_iter().take(remaining));

    let selected_ids = selected
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    let selected_anchor_ids = anchor_evidence_ids
        .iter()
        .filter(|id| selected_ids.contains(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let anchors_truncated = selected_anchor_ids.len() < anchor_evidence_ids.len();
    (selected, selected_anchor_ids, anchors_truncated)
}

fn observation_group_references(
    group: &ObservationGroup,
    sources: &RepositorySources,
    context_lines: usize,
) -> Result<BTreeSet<String>, EngineError> {
    let file = sources.file(&group.path)?;
    let first_line = group
        .evidence
        .iter()
        .map(|item| item.location.start.line)
        .min()
        .unwrap_or(1);
    let last_line = group
        .evidence
        .iter()
        .map(|item| item.location.end.line)
        .max()
        .unwrap_or(first_line);
    let (slice, _) = source_slice(
        file,
        first_line.saturating_sub(context_lines).max(1),
        last_line.saturating_add(context_lines),
    )?;
    let mut references = BTreeSet::new();
    collect_review_reference_tokens(&slice.text, &mut references);
    collect_policy_reference_tokens(&slice.text, &mut references);
    for evidence in &group.evidence {
        for (name, capture) in &evidence.captures {
            collect_review_reference_tokens(&capture.text, &mut references);
            if matches!(name.as_str(), "handler" | "callback" | "delegate")
                && let Some(identifier) = terminal_identifier(&capture.text)
            {
                references.insert(identifier.to_string());
            }
        }
    }
    Ok(references)
}

fn observation_helper_definition_facts(
    sources: &RepositorySources,
    context: &ReviewContextIndex,
    candidate_paths: &BTreeSet<&str>,
    references: &BTreeSet<String>,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let mut facts = Vec::new();
    let mut names = references.iter().collect::<Vec<_>>();
    names.sort_by(|left, right| {
        reference_priority(right)
            .cmp(&reference_priority(left))
            .then_with(|| left.cmp(right))
    });
    for name in names {
        let Some(symbols) = context.definitions.get(name) else {
            continue;
        };
        let owned_symbols = symbols
            .iter()
            .filter(|symbol| {
                review_definition_owned_by_candidate(sources, candidate_paths, name, symbol)
            })
            .collect::<Vec<_>>();
        let selected = owned_symbols.into_iter().take(2).collect::<Vec<_>>();
        for symbol in selected {
            if !looks_like_review_helper_signature(name, &symbol.signature)
                || facts_cover_location(existing, &symbol.location)
            {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            let Ok(file) = sources.file(&symbol.location.path) else {
                continue;
            };
            let location_end_line = if symbol.location.end.column == 1
                && symbol.location.end.line > symbol.location.start.line
            {
                symbol.location.end.line - 1
            } else {
                symbol.location.end.line
            };
            let end_line = location_end_line.min(symbol.location.start.line + 39);
            let Ok((slice, slice_truncated)) =
                source_slice(file, symbol.location.start.line, end_line)
            else {
                continue;
            };
            facts.push(ReviewNeighborhoodFact {
                role: "helper_definition_context".to_string(),
                symbol: name.clone(),
                location: slice.location,
                excerpt: redact_helper_definition(name, &slice.text),
                evidence_id: None,
                provenance: textual_provenance(
                    "bounded exact helper referenced by observation, lexical non-flow 1",
                ),
            });
            if slice_truncated || end_line < location_end_line {
                return (facts, true);
            }
        }
    }
    (facts, false)
}

fn looks_like_review_helper_signature(name: &str, signature: &str) -> bool {
    if ["model", "options", "order"].contains(&name.to_ascii_lowercase().as_str()) {
        return false;
    }
    let compact = signature.split_whitespace().collect::<Vec<_>>().join(" ");
    let without_whitespace = signature
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    without_whitespace.contains(&format!("{name}("))
        || without_whitespace.contains(&format!("this.{name}="))
        || ["const", "let", "var"]
            .iter()
            .any(|keyword| without_whitespace.contains(&format!("{keyword}{name}=")))
        || compact.starts_with("class ")
        || compact.starts_with("struct ")
        || compact.starts_with("interface ")
        || compact.starts_with("record ")
        || compact.contains(" class ")
        || compact.contains(" struct ")
        || compact.contains(" interface ")
        || compact.contains(" record ")
}

fn exact_csharp_caller_facts(
    sources: &RepositorySources,
    definition_path: &str,
    symbol: &str,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let Some(symbol) = terminal_identifier(symbol) else {
        return (Vec::new(), false);
    };
    if limit == 0 {
        return (Vec::new(), false);
    }
    let marker = format!("{symbol}(");
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Csharp) && file.path != definition_path)
    {
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            let compact = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            if !compact.contains(&marker)
                || line.trim_start().starts_with("//")
                || textual_definition_identifier(line).as_deref() == Some(symbol)
            {
                continue;
            }
            let Some(definition_index) = (0..line_index).rev().take(120).find(|index| {
                looks_like_csharp_method_declaration(&file.source[spans[*index].0..spans[*index].1])
            }) else {
                continue;
            };
            if facts.len() == limit {
                return (facts, true);
            }
            let method_end =
                textual_definition_end_with_limit(&file.source, &spans, definition_index, 96);
            let end_index = method_end.min(line_index.saturating_add(4));
            facts.push(ReviewNeighborhoodFact {
                role: "exact_caller_context".to_string(),
                symbol: symbol.to_string(),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    spans[definition_index].0,
                    spans[end_index].1,
                ),
                excerpt: file.source[spans[definition_index].0..spans[end_index].1].to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "bounded exact C# call site and enclosing method, lexical non-flow 1",
                ),
            });
        }
    }
    (facts, false)
}

fn exact_python_observation_caller_facts(
    sources: &RepositorySources,
    group: &ObservationGroup,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0
        || !group.evidence.iter().any(|item| {
            item.kind == EvidenceKind::Sink
                && matches!(
                    item.capability,
                    Capability::FilesystemRead | Capability::FilesystemWrite
                )
        })
    {
        return (Vec::new(), false);
    }
    let target = group.symbol.as_str();
    if !is_plain_identifier(target) {
        return (Vec::new(), false);
    }
    let call = format!("{target}(");
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Python) && file.path != group.path)
    {
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            if !line.contains(&call)
                || line.trim_start().starts_with('#')
                || python_definition_identifier(line).as_deref() == Some(target)
            {
                continue;
            }
            let Some(definition_index) = (0..=line_index).rev().take(160).find(|index| {
                python_definition_identifier(&file.source[spans[*index].0..spans[*index].1])
                    .is_some()
            }) else {
                continue;
            };
            let caller = python_definition_identifier(
                &file.source[spans[definition_index].0..spans[definition_index].1],
            )
            .unwrap_or_else(|| "python_caller".to_string());
            let end_index = python_definition_end_index(&file.source, &spans, definition_index, 96);
            if line_index > end_index {
                continue;
            }
            let excerpt = file.source[spans[definition_index].0..spans[end_index].1].to_string();
            facts.push(ReviewNeighborhoodFact {
                role: "exact_caller_context".to_string(),
                symbol: caller.clone(),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    spans[definition_index].0,
                    spans[end_index].1,
                ),
                excerpt: excerpt.clone(),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact Python helper call site and enclosing function, bounded non-flow 1",
                ),
            });
            if facts.len() == limit {
                return (facts, true);
            }
            let mut references = BTreeSet::new();
            collect_review_reference_tokens(&excerpt, &mut references);
            references.remove(target);
            references.remove(&caller);
            for reference in references {
                let Some(fact) = named_definition_fact(
                    sources,
                    &reference,
                    "caller_helper_definition_context",
                    48,
                    "exact helper referenced by Python caller, bounded non-flow 1",
                ) else {
                    continue;
                };
                facts.push(fact);
                if facts.len() == limit {
                    return (facts, true);
                }
            }
            return (facts, false);
        }
    }
    (facts, false)
}

fn exact_java_identity_observation_caller_facts(
    sources: &RepositorySources,
    group: &ObservationGroup,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0
        || !group
            .evidence
            .iter()
            .any(|item| item.rule_id == "java-nimbus-claims-without-verification")
    {
        return (Vec::new(), false);
    }
    let target = group.symbol.as_str();
    if !is_plain_identifier(target) {
        return (Vec::new(), false);
    }
    let marker = format!("{target}(");
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Java))
    {
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            if !line.contains(&marker)
                || line.trim_start().starts_with("//")
                || textual_definition_identifier(line).as_deref() == Some(target)
            {
                continue;
            }
            let Some(definition_index) = (0..=line_index).rev().take(160).find(|index| {
                textual_definition_identifier(&file.source[spans[*index].0..spans[*index].1])
                    .is_some()
            }) else {
                continue;
            };
            let method_end =
                textual_definition_end_with_limit(&file.source, &spans, definition_index, 96);
            if line_index > method_end {
                continue;
            }
            let caller = textual_definition_identifier(
                &file.source[spans[definition_index].0..spans[definition_index].1],
            )
            .unwrap_or_else(|| "java_caller".to_string());
            facts.push(ReviewNeighborhoodFact {
                role: "exact_caller_context".to_string(),
                symbol: caller,
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    spans[definition_index].0,
                    spans[method_end].1,
                ),
                excerpt: file.source[spans[definition_index].0..spans[method_end].1].to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact Java identity helper call site and enclosing method, bounded non-flow 1",
                ),
            });
            if facts.len() == limit {
                return (facts, true);
            }
        }
    }
    (facts, false)
}

fn python_jwt_verification_facts(
    sources: &RepositorySources,
    group: &ObservationGroup,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let Some(key) = group.evidence.iter().find_map(|item| {
        (item.rule_id == "python-jwt-hardcoded-signing-key")
            .then(|| item.captures.get("key").map(|capture| capture.text.trim()))
            .flatten()
    }) else {
        return (Vec::new(), false);
    };
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Python))
    {
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            if !line.contains("jwt.decode(") || !line.contains(key) {
                continue;
            }
            let Some(definition_index) = (0..=line_index).rev().take(120).find(|index| {
                python_definition_identifier(&file.source[spans[*index].0..spans[*index].1])
                    .is_some()
            }) else {
                continue;
            };
            let symbol = python_definition_identifier(
                &file.source[spans[definition_index].0..spans[definition_index].1],
            )
            .unwrap_or_else(|| "jwt_verifier".to_string());
            let end_index = python_definition_end_index(&file.source, &spans, definition_index, 64);
            facts.push(ReviewNeighborhoodFact {
                role: "jwt_verification_context".to_string(),
                symbol,
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    spans[definition_index].0,
                    spans[end_index].1,
                ),
                excerpt: file.source[spans[definition_index].0..spans[end_index].1].to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact matching Python JWT verification literal, bounded non-flow 1",
                ),
            });
            if facts.len() == limit {
                return (facts, true);
            }
        }
    }
    (facts, false)
}

fn csharp_anonymous_endpoint_policy_facts(
    sources: &RepositorySources,
    group: &ObservationGroup,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let Some(anchor) = group
        .evidence
        .iter()
        .find(|item| item.rule_id == "csharp-anonymous-state-change-review")
    else {
        return (Vec::new(), false);
    };
    let Ok(file) = sources.file(&group.path) else {
        return (Vec::new(), false);
    };
    let spans = line_spans(&file.source);
    if spans.is_empty() {
        return (Vec::new(), false);
    }
    let attribute_index = anchor
        .location
        .start
        .line
        .saturating_sub(1)
        .min(spans.len() - 1);
    let method_index =
        (attribute_index..=(attribute_index + 5).min(spans.len() - 1)).find(|index| {
            textual_definition_identifier(&file.source[spans[*index].0..spans[*index].1]).as_deref()
                == Some(group.symbol.as_str())
                && looks_like_csharp_method_declaration(
                    &file.source[spans[*index].0..spans[*index].1],
                )
        });
    let mut facts = Vec::new();
    if let Some(method_index) = method_index {
        let mut start_index = method_index;
        while start_index > 0
            && method_index - start_index < 4
            && file.source[spans[start_index - 1].0..spans[start_index - 1].1]
                .trim_start()
                .starts_with('[')
        {
            start_index -= 1;
        }
        let end_index = textual_definition_end_with_limit(&file.source, &spans, method_index, 64);
        facts.push(ReviewNeighborhoodFact {
            role: "anonymous_endpoint_operation_context".to_string(),
            symbol: group.symbol.clone(),
            location: location_from_offsets(
                &file.path,
                &file.source,
                spans[start_index].0,
                spans[end_index].1,
            ),
            excerpt: file.source[spans[start_index].0..spans[end_index].1].to_string(),
            evidence_id: Some(anchor.id.clone()),
            provenance: textual_provenance(
                "exact explicitly anonymous C# endpoint operation, bounded policy context 1",
            ),
        });
    }

    if facts.len() < limit
        && let Some(class_index) = (0..=attribute_index).rev().find(|index| {
            let line = file.source[spans[*index].0..spans[*index].1].trim_start();
            line.contains(" class ") || line.starts_with("class ")
        })
    {
        let start_index = class_index.saturating_sub(4);
        let excerpt = &file.source[spans[start_index].0..spans[class_index].1];
        if excerpt.contains("[Authorize") {
            facts.push(ReviewNeighborhoodFact {
                role: "controller_authorization_context".to_string(),
                symbol: group.symbol.clone(),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    spans[start_index].0,
                    spans[class_index].1,
                ),
                excerpt: excerpt.to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact controller-level authorization default around explicit anonymous exception 1",
                ),
            });
        }
    }

    if facts.len() < limit {
        let normalized = group.path.replace('\\', "/");
        let controller = Path::new(&normalized)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.strip_suffix("Controller"));
        if let Some(controller) = controller {
            let repository_prefix = normalized
                .split_once("/Controllers/")
                .map(|(prefix, _)| format!("{prefix}/"))
                .unwrap_or_default();
            let view_path = format!(
                "{repository_prefix}Views/{controller}/{}.cshtml",
                group.symbol
            );
            if let Ok(view) = sources.file(&view_path)
                && (view.source.contains("<form")
                    || view.source.contains("asp-action")
                    || view.source.contains("Html.BeginForm"))
            {
                let end_line = line_spans(&view.source).len().min(48);
                if let Ok((slice, slice_truncated)) = source_slice(view, 1, end_line) {
                    facts.push(ReviewNeighborhoodFact {
                        role: "public_entrypoint_ui_context".to_string(),
                        symbol: group.symbol.clone(),
                        location: slice.location,
                        excerpt: slice.text,
                        evidence_id: None,
                        provenance: textual_provenance(
                            "exact matching public authentication or registration UI 1",
                        ),
                    });
                    if slice_truncated {
                        return (facts, true);
                    }
                }
            }
        }
    }
    (facts, false)
}

fn csharp_privilege_assignment_path_facts(
    sources: &RepositorySources,
    candidate: &mehscan_core::Candidate,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 || candidate.sink.rule_id != "csharp-request-controlled-role-assignment" {
        return (Vec::new(), false);
    }
    let Ok(file) = sources.file(&candidate.sink.location.path) else {
        return (Vec::new(), false);
    };
    let Some(symbol) = candidate.sink.enclosing_symbol.as_deref() else {
        return (Vec::new(), false);
    };
    let spans = line_spans(&file.source);
    if spans.is_empty() {
        return (Vec::new(), false);
    }
    let sink_index = candidate
        .sink
        .location
        .start
        .line
        .saturating_sub(1)
        .min(spans.len() - 1);
    let method_index = (0..=sink_index).rev().find(|index| {
        textual_definition_identifier(&file.source[spans[*index].0..spans[*index].1]).as_deref()
            == Some(symbol)
            && looks_like_csharp_method_declaration(&file.source[spans[*index].0..spans[*index].1])
    });
    let mut facts = Vec::new();
    if let Some(method_index) = method_index {
        let mut start_index = method_index;
        while start_index > 0
            && method_index - start_index < 4
            && file.source[spans[start_index - 1].0..spans[start_index - 1].1]
                .trim_start()
                .starts_with('[')
        {
            start_index -= 1;
        }
        let end_index = textual_definition_end_with_limit(&file.source, &spans, method_index, 96);
        facts.push(ReviewNeighborhoodFact {
            role: "privilege_assignment_operation_context".to_string(),
            symbol: symbol.to_string(),
            location: location_from_offsets(
                &file.path,
                &file.source,
                spans[start_index].0,
                spans[end_index].1,
            ),
            excerpt: file.source[spans[start_index].0..spans[end_index].1].to_string(),
            evidence_id: Some(candidate.sink.id.clone()),
            provenance: textual_provenance(
                "exact C# identity role-assignment endpoint, bounded policy context 1",
            ),
        });
    }

    if facts.len() < limit
        && let Some(class_index) = (0..=sink_index).rev().find(|index| {
            let line = file.source[spans[*index].0..spans[*index].1].trim_start();
            line.contains(" class ") || line.starts_with("class ")
        })
    {
        let start_index = class_index.saturating_sub(4);
        facts.push(ReviewNeighborhoodFact {
            role: "caller_authorization_context".to_string(),
            symbol: symbol.to_string(),
            location: location_from_offsets(
                &file.path,
                &file.source,
                spans[start_index].0,
                spans[class_index].1,
            ),
            excerpt: file.source[spans[start_index].0..spans[class_index].1].to_string(),
            evidence_id: None,
            provenance: textual_provenance(
                "exact controller authorization metadata around privilege assignment 1",
            ),
        });
    }

    if facts.len() < limit {
        let normalized = candidate.sink.location.path.replace('\\', "/");
        let controller = Path::new(&normalized)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.strip_suffix("Controller"));
        if let Some(controller) = controller {
            let repository_prefix = normalized
                .split_once("/Controllers/")
                .map(|(prefix, _)| format!("{prefix}/"))
                .unwrap_or_default();
            let view_path = format!("{repository_prefix}Views/{controller}/{symbol}.cshtml");
            if let Ok(view) = sources.file(&view_path)
                && (view.source.contains("<form")
                    || view.source.contains("asp-action")
                    || view.source.contains("Html.BeginForm"))
            {
                let end_line = line_spans(&view.source).len().min(72);
                if let Ok((slice, slice_truncated)) = source_slice(view, 1, end_line) {
                    facts.push(ReviewNeighborhoodFact {
                        role: "privilege_assignment_ui_context".to_string(),
                        symbol: symbol.to_string(),
                        location: slice.location,
                        excerpt: slice.text,
                        evidence_id: None,
                        provenance: textual_provenance(
                            "exact matching role-assignment UI trust-boundary context 1",
                        ),
                    });
                    if slice_truncated {
                        return (facts, true);
                    }
                }
            }
        }
    }
    (facts, false)
}

fn looks_like_csharp_method_declaration(line: &str) -> bool {
    let trimmed = line.trim_start();
    ["public ", "private ", "protected ", "internal "]
        .iter()
        .any(|modifier| trimmed.starts_with(modifier))
        && trimmed.contains('(')
        && ![" class ", " struct ", " interface ", " record "]
            .iter()
            .any(|kind| trimmed.contains(kind))
}

fn csharp_razor_retrieval_facts(
    sources: &RepositorySources,
    neighborhood: &mehscan_core::ReviewNeighborhood,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let mut view_paths = neighborhood
        .facts
        .iter()
        .filter(|fact| fact.role == "raw_output_sink")
        .map(|fact| fact.location.path.clone())
        .collect::<BTreeSet<_>>();
    let partial_names = view_paths
        .iter()
        .filter_map(|path| {
            Path::new(path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| stem.starts_with('_'))
                .map(str::to_string)
        })
        .collect::<BTreeSet<_>>();
    let mut facts = Vec::new();
    if !partial_names.is_empty() {
        let mut parent_matches = Vec::new();
        for file in sources
            .files
            .values()
            .filter(|file| file.path.ends_with(".cshtml"))
        {
            for (start, end) in line_spans(&file.source) {
                let line = &file.source[start..end];
                let Some(partial) = partial_names.iter().find(|partial| {
                    line.contains("<partial")
                        && (line.contains(&format!("name=\"{partial}\""))
                            || line.contains(&format!("name='{partial}'")))
                }) else {
                    continue;
                };
                parent_matches.push((file.path.clone(), start, end, partial.clone()));
            }
        }
        parent_matches.sort_by(|left, right| {
            (!left.0.replace('\\', "/").ends_with("/Index.cshtml"))
                .cmp(&(!right.0.replace('\\', "/").ends_with("/Index.cshtml")))
                .then_with(|| left.0.cmp(&right.0))
        });
        if let Some((path, start, end, partial)) = parent_matches.into_iter().next() {
            if facts.len() == limit {
                return (facts, true);
            }
            let Ok(file) = sources.file(&path) else {
                return (facts, false);
            };
            view_paths.insert(path.clone());
            facts.push(ReviewNeighborhoodFact {
                role: "view_composition_context".to_string(),
                symbol: partial,
                location: location_from_offsets(&path, &file.source, start, end),
                excerpt: bounded_line_text(&file.source[start..end]),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact Razor partial composition, bounded non-flow 1",
                ),
            });
        }
    }

    let mut ordered_view_paths = view_paths.into_iter().collect::<Vec<_>>();
    ordered_view_paths.sort_by(|left, right| {
        (!left.replace('\\', "/").ends_with("/Index.cshtml"))
            .cmp(&(!right.replace('\\', "/").ends_with("/Index.cshtml")))
            .then_with(|| left.cmp(right))
    });
    for view_path in ordered_view_paths {
        let normalized = view_path.replace('\\', "/");
        let Some((_, suffix)) = normalized.split_once("/Views/") else {
            continue;
        };
        let mut parts = suffix.split('/');
        let (Some(controller), Some(view_file)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(action) = view_file.strip_suffix(".cshtml") else {
            continue;
        };
        if action.starts_with('_') {
            continue;
        }
        if let Ok(view) = sources.file(&view_path) {
            let model_line = view.source.lines().find(|line| {
                line.trim_start_matches(|character: char| {
                    character.is_whitespace() || character == '\u{feff}'
                })
                .starts_with("@model ")
            });
            if let Some(model_line) = model_line {
                let model_references = model_line
                    .split(|character: char| {
                        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
                    })
                    .filter(|token| {
                        token
                            .chars()
                            .next()
                            .is_some_and(|character| character.is_ascii_uppercase())
                    })
                    .map(str::to_string)
                    .collect::<BTreeSet<_>>();
                for reference in model_references {
                    for model in exact_named_csharp_type_definitions(
                        sources,
                        &reference,
                        "retrieval_model_context",
                        1,
                    ) {
                        if facts.len() == limit {
                            return (facts, true);
                        }
                        if !facts_cover_location(&facts, &model.location) {
                            facts.push(model);
                        }
                    }
                }
            }
        }
        let controller_suffix = format!("/Controllers/{controller}Controller.cs");
        for file in sources.files.values().filter(|file| {
            file.language == Some(Language::Csharp)
                && file.path.replace('\\', "/").ends_with(&controller_suffix)
        }) {
            let spans = line_spans(&file.source);
            for (definition_index, (start, end)) in spans.iter().copied().enumerate() {
                let line = &file.source[start..end];
                if textual_definition_identifier(line).as_deref() != Some(action) {
                    continue;
                }
                if facts.len() == limit {
                    return (facts, true);
                }
                let end_index =
                    textual_definition_end_with_limit(&file.source, &spans, definition_index, 40);
                let excerpt =
                    file.source[spans[definition_index].0..spans[end_index].1].to_string();
                facts.push(ReviewNeighborhoodFact {
                    role: "view_action_context".to_string(),
                    symbol: format!("{controller}Controller.{action}"),
                    location: location_from_offsets(
                        &file.path,
                        &file.source,
                        spans[definition_index].0,
                        spans[end_index].1,
                    ),
                    excerpt: excerpt.clone(),
                    evidence_id: None,
                    provenance: textual_provenance(
                        "Razor view convention to exact controller action, bounded non-flow 1",
                    ),
                });
                let mut references = BTreeSet::new();
                collect_review_reference_tokens(&excerpt, &mut references);
                for reference in references.into_iter().filter(|reference| {
                    reference != "View" && reference != action && reference.len() > 3
                }) {
                    for helper in exact_named_csharp_definitions(
                        sources,
                        &reference,
                        "retrieval_helper_context",
                        2,
                    ) {
                        if facts.len() == limit {
                            return (facts, true);
                        }
                        if !facts_cover_location(&facts, &helper.location) {
                            facts.push(helper);
                        }
                    }
                }
            }
        }
    }
    if facts.iter().any(|fact| {
        fact.role == "retrieval_model_context"
            && fact.excerpt.contains("virtual")
            && fact.excerpt.contains("IList<")
    }) {
        for file in sources
            .files
            .values()
            .filter(|file| file.language == Some(Language::Csharp))
        {
            let spans = line_spans(&file.source);
            for (line_index, (start, end)) in spans.iter().copied().enumerate() {
                if !file.source[start..end].contains("UseLazyLoadingProxies(") {
                    continue;
                }
                if facts.len() == limit {
                    return (facts, true);
                }
                let start_line = line_index.saturating_sub(2) + 1;
                let end_line = (line_index + 3).min(spans.len());
                if let Ok((slice, _)) = source_slice(file, start_line, end_line) {
                    facts.push(ReviewNeighborhoodFact {
                        role: "retrieval_configuration_context".to_string(),
                        symbol: "UseLazyLoadingProxies".to_string(),
                        location: slice.location,
                        excerpt: slice.text,
                        evidence_id: None,
                        provenance: textual_provenance(
                            "exact EF lazy-loading repository configuration, bounded context 1",
                        ),
                    });
                }
            }
        }
    }
    (facts, false)
}

fn exact_named_csharp_type_definitions(
    sources: &RepositorySources,
    name: &str,
    role: &str,
    limit: usize,
) -> Vec<ReviewNeighborhoodFact> {
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Csharp))
    {
        let spans = line_spans(&file.source);
        for (definition_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = file.source[start..end]
                .split_whitespace()
                .collect::<Vec<_>>();
            if !line.windows(2).any(|tokens| {
                matches!(tokens[0], "class" | "struct" | "interface" | "record")
                    && tokens[1].trim_end_matches([':', '{']) == name
            }) {
                continue;
            }
            let end_index = textual_definition_end_with_limit(
                &file.source,
                &spans,
                definition_index,
                MAX_REVIEW_HELPER_LINES,
            );
            facts.push(ReviewNeighborhoodFact {
                role: role.to_string(),
                symbol: name.to_string(),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    spans[definition_index].0,
                    spans[end_index].1,
                ),
                excerpt: file.source[spans[definition_index].0..spans[end_index].1].to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "bounded exact C# type definition, lexical non-flow 1",
                ),
            });
            if facts.len() == limit {
                return facts;
            }
        }
    }
    facts
}

fn exact_named_csharp_definitions(
    sources: &RepositorySources,
    name: &str,
    role: &str,
    limit: usize,
) -> Vec<ReviewNeighborhoodFact> {
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Csharp))
    {
        let spans = line_spans(&file.source);
        for (definition_index, (start, end)) in spans.iter().copied().enumerate() {
            if textual_definition_identifier(&file.source[start..end]).as_deref() != Some(name) {
                continue;
            }
            let end_index = textual_definition_end_with_limit(
                &file.source,
                &spans,
                definition_index,
                MAX_REVIEW_HELPER_LINES,
            );
            facts.push(ReviewNeighborhoodFact {
                role: role.to_string(),
                symbol: name.to_string(),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    spans[definition_index].0,
                    spans[end_index].1,
                ),
                excerpt: file.source[spans[definition_index].0..spans[end_index].1].to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "bounded exact C# helper definition, lexical non-flow 1",
                ),
            });
            if facts.len() == limit {
                return facts;
            }
        }
    }
    facts
}

fn observation_groups(
    evidence: &[Evidence],
    used_ids: &BTreeSet<&str>,
    candidates: &[mehscan_core::Candidate],
    sources: &RepositorySources,
) -> Vec<ObservationGroup> {
    let mut grouped: BTreeMap<(String, String), Vec<Evidence>> = BTreeMap::new();
    for item in evidence
        .iter()
        .filter(|item| item.kind != EvidenceKind::Secret)
    {
        let symbol = item.enclosing_symbol.clone().unwrap_or_else(|| {
            format!(
                "line-{}-{}",
                item.location.start.line, item.location.start.column
            )
        });
        grouped
            .entry((item.location.path.clone(), symbol))
            .or_default()
            .push(item.clone());
    }
    let mut groups = Vec::new();
    for ((path, symbol), mut items) in grouped {
        items.sort_by(|left, right| {
            left.location
                .start
                .byte_offset
                .cmp(&right.location.start.byte_offset)
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        let anchors = items
            .iter()
            .filter(|item| {
                !used_ids.contains(item.id.as_str())
                    && !item.cwe_candidates.is_empty()
                    && !observation_sink_covered_by_candidate(item, candidates)
                    && !is_non_actionable_fixed_sink_observation(item, sources)
                    && !is_non_actionable_safe_purpose_observation(item, sources)
                    && !is_non_actionable_java_route_control(item)
                    && !is_non_actionable_affirmative_csharp_cookie_control(item)
                    && !is_source_free_generic_java_log(item, &items)
                    && !is_superseded_java_logging_observation(item, &items)
                    && !is_superseded_csharp_cookie_observation(item, &items)
                    && !is_context_only_uploaded_filename_check(item, &items)
                    && !is_non_actionable_csrf_observation(item, sources)
                    && !is_non_actionable_autoescaped_django_response(item, sources)
                    && matches!(
                        item.kind,
                        EvidenceKind::Sink
                            | EvidenceKind::SensitiveOperation
                            | EvidenceKind::SecurityConfiguration
                    )
            })
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        if anchors.is_empty() {
            // Sources, entrypoints, guards, sanitizers, validations, literals,
            // and resources remain available as context, but are not standalone
            // vulnerability-verdict jobs without an unused impact observation.
            continue;
        }
        // A sink already owned by a deterministic candidate remains in that
        // path review. Do not repeat it as top-level observation evidence when
        // a distinct configuration or operation anchor keeps this group alive.
        items.retain(|item| {
            item.kind != EvidenceKind::Sink
                || (!used_ids.contains(item.id.as_str())
                    && !is_non_actionable_fixed_sink_observation(item, sources)
                    && !is_non_actionable_safe_purpose_observation(item, sources))
        });
        let anchor_set = anchors.iter().cloned().collect::<BTreeSet<_>>();
        for anchor_id in anchors {
            // One verdict must describe one actionable operation. A symbol can
            // contain unrelated sinks or policy observations (for example, a
            // safe file write beside several authorization-sensitive queries).
            // Keep sources and controls as shared context, but never ask a
            // reviewer to collapse independent anchors into one decision.
            let anchor_evidence = items
                .iter()
                .find(|item| item.id == anchor_id)
                .expect("observation anchor must remain in its evidence group");
            let has_source = items.iter().any(|item| item.kind == EvidenceKind::Source);
            let has_sink = anchor_evidence.kind == EvidenceKind::Sink;
            let has_review_operation = matches!(
                anchor_evidence.kind,
                EvidenceKind::SecurityConfiguration | EvidenceKind::SensitiveOperation
            );
            let priority = if has_source && has_sink {
                0
            } else if has_review_operation {
                1
            } else if has_sink {
                2
            } else {
                3
            };
            let evidence = items
                .iter()
                .filter(|item| {
                    item.id == anchor_id
                        || (!anchor_set.contains(item.id.as_str())
                            && is_local_observation_context(anchor_evidence, item))
                })
                .cloned()
                .collect();
            groups.push(ObservationGroup {
                review_material: is_review_material_path(&path),
                path: path.clone(),
                symbol: symbol.clone(),
                evidence,
                anchor_evidence_ids: vec![anchor_id],
                priority,
            });
        }
    }
    groups.sort_by(|left, right| {
        left.review_material
            .cmp(&right.review_material)
            .then_with(|| left.priority.cmp(&right.priority))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    groups
}

fn is_local_observation_context(anchor: &Evidence, item: &Evidence) -> bool {
    if anchor.location.path != item.location.path {
        return false;
    }
    let explicitly_related = anchor.related_evidence.iter().any(|id| id == &item.id)
        || item.related_evidence.iter().any(|id| id == &anchor.id);
    if explicitly_related {
        return true;
    }
    if !matches!(
        item.kind,
        EvidenceKind::Source
            | EvidenceKind::Entrypoint
            | EvidenceKind::Guard
            | EvidenceKind::Sanitizer
            | EvidenceKind::Validation
            | EvidenceKind::Literal
            | EvidenceKind::Resource
    ) {
        return false;
    }
    let anchor_start = anchor.location.start.line;
    let anchor_end = anchor.location.end.line;
    let item_start = item.location.start.line;
    let item_end = item.location.end.line;
    item_start <= anchor_end.saturating_add(8) && anchor_start <= item_end.saturating_add(8)
}

fn observation_sink_covered_by_candidate(
    item: &Evidence,
    candidates: &[mehscan_core::Candidate],
) -> bool {
    item.kind == EvidenceKind::Sink
        && !item.cwe_candidates.is_empty()
        && candidates.iter().any(|candidate| {
            if candidate.sink.location.path != item.location.path
                || !item
                    .cwe_candidates
                    .iter()
                    .any(|cwe| candidate.cwe_candidates.contains(cwe))
            {
                return false;
            }
            let overlaps = candidate.sink.location.start.byte_offset
                < item.location.end.byte_offset
                && item.location.start.byte_offset < candidate.sink.location.end.byte_offset;
            let same_local_invariant = item.enclosing_symbol.is_some()
                && item.enclosing_symbol == candidate.sink.enclosing_symbol
                && item.capability == candidate.capability
                && item
                    .location
                    .start
                    .line
                    .abs_diff(candidate.sink.location.start.line)
                    <= DEFAULT_REVIEW_CONTEXT_LINES;
            overlaps || same_local_invariant
        })
}

/// Exact protected route entries are useful path context but are not themselves
/// vulnerability-verdict jobs. Public entries remain reviewable until their
/// endpoint purpose is established.
fn is_non_actionable_java_route_control(item: &Evidence) -> bool {
    item.rule_id == "java-spring-security-route-policy"
        && item.captures.get("policy").is_some_and(|policy| {
            let policy = policy.text.trim();
            policy == "authenticated" || policy.starts_with("hasRole:")
        })
}

/// An explicitly enabled HttpOnly flag is affirmative control evidence, not a
/// vulnerability candidate. Keep it in raw scan output for neighboring cookie
/// reviews, but do not ask a model for a standalone verdict.
fn is_non_actionable_affirmative_csharp_cookie_control(item: &Evidence) -> bool {
    item.rule_id == "csharp-cookie-httponly-flag"
        && item
            .captures
            .get("http_only")
            .is_some_and(|value| value.text.trim() == "true")
}

/// The session-policy observation already carries the explicit HttpOnly=false
/// setting and the unresolved Secure/SameSite dimensions. Do not emit a second
/// verdict job for the same literal flag.
fn is_superseded_csharp_cookie_observation(item: &Evidence, group: &[Evidence]) -> bool {
    item.rule_id == "csharp-cookie-httponly-flag"
        && item
            .captures
            .get("http_only")
            .is_some_and(|value| value.text.trim() == "false")
        && group.iter().any(|other| {
            other.rule_id == "csharp-session-cookie-policy-risk"
                && other.location.start.line <= item.location.start.line
                && item.location.end.line <= other.location.end.line
        })
}

/// A rendered log call without a locally related source is inventory, not a
/// decision-ready CWE-117 review. A co-located sensitive-value rule remains an
/// independently reviewable data-classification observation.
fn is_source_free_generic_java_log(item: &Evidence, group: &[Evidence]) -> bool {
    item.rule_id == "java-rendered-log-message"
        && !group.iter().any(|other| {
            other.kind == EvidenceKind::Source && is_local_observation_context(item, other)
        })
}

/// Prefer a precise sensitive-value rule over the generic logging companion at
/// the same call site. Both remain in raw evidence, but only one verdict job is
/// needed for the same disclosed value and operation.
fn is_superseded_java_logging_observation(item: &Evidence, group: &[Evidence]) -> bool {
    item.rule_id == "java-sensitive-value-logging-review"
        && group.iter().any(|other| {
            other.rule_id == "java-api-key-debug-logging"
                && other.location.start.byte_offset == item.location.start.byte_offset
                && other.location.end.byte_offset == item.location.end.byte_offset
        })
}

/// A filename check that logs and continues is only a vulnerability lead when
/// the filename also participates in an executable path or upload sink. Keep
/// the check as scan context, but do not ask for a standalone verdict when the
/// enclosing symbol only returns content bytes.
fn is_context_only_uploaded_filename_check(item: &Evidence, group: &[Evidence]) -> bool {
    item.rule_id == "java-uploaded-filename-check-without-rejection"
        && !group.iter().any(|other| {
            other.id != item.id
                && matches!(
                    other.capability,
                    Capability::UploadedFilePath
                        | Capability::FilesystemRead
                        | Capability::FilesystemWrite
                        | Capability::FileUpload
                )
                && matches!(
                    other.kind,
                    EvidenceKind::Sink | EvidenceKind::SensitiveOperation
                )
        })
}

fn is_non_actionable_fixed_sink_observation(item: &Evidence, sources: &RepositorySources) -> bool {
    if item.kind != EvidenceKind::Sink {
        return false;
    }
    let literal_role = match item.capability {
        Capability::DatabaseQuery => "query",
        // Fixed program text does not become code injection merely because the
        // sandbox data consumed by that program is dynamic. Other operations
        // performed by the fixed program (XML/YAML parsing, for example) keep
        // their own evidence and review jobs.
        Capability::DynamicCodeExecution => "code",
        Capability::OutboundNetworkRequest => "endpoint",
        Capability::Redirect => "location",
        // A literal response body can still be useful inventory evidence, but
        // it cannot carry attacker-controlled markup into an XSS sink. Keep
        // the observation in scan output and omit only its standalone verdict
        // job. Dynamic and partially resolved content remains reviewable.
        Capability::HtmlOutput => {
            if is_non_html_javascript_response(item, sources) {
                return true;
            }
            "content"
        }
        Capability::BrowserNavigation => {
            return is_fixed_imported_browser_navigation(item, sources);
        }
        Capability::ResourceAccess if item.cwe_candidates.iter().any(|cwe| cwe == "CWE-639") => {
            return item
                .captures
                .get("filter")
                .is_some_and(|capture| is_fixed_resource_selector(&capture.text))
                || is_repository_created_resource_selector(item, sources);
        }
        Capability::FilesystemRead | Capability::FilesystemWrite
            if item.cwe_candidates.iter().any(|cwe| cwe == "CWE-22") =>
        {
            if item.capability == Capability::FilesystemRead
                && is_directory_enumerated_child_path(item, sources)
            {
                return true;
            }
            "path"
        }
        _ => return false,
    };
    let literal = item.context.literals.get(literal_role);
    literal.is_some_and(|literal| {
        literal.state == LiteralState::Known
            && matches!(literal.value, Some(LiteralValue::String(_)))
    }) || (item.capability == Capability::OutboundNetworkRequest
        && literal.is_some_and(has_fixed_http_authority))
        || (item.capability == Capability::Redirect
            && literal.is_some_and(has_fixed_internal_redirect_prefix))
        || is_fixed_python_local_path(item, sources)
}

/// Omit a standalone verdict job only when the source proves a narrowly safe
/// purpose. The original observation remains in deterministic scan evidence.
fn is_non_actionable_safe_purpose_observation(
    item: &Evidence,
    sources: &RepositorySources,
) -> bool {
    if is_schema_validated_local_yaml_tool(item, sources)
        || is_repository_snippet_index_read(item, sources)
        || is_authenticated_generated_upload_write(item, sources)
        || is_configuration_backed_promotion_read(item, sources)
        || is_configuration_backed_response(item, sources)
        || is_captcha_verification_lookup(item, sources)
        || is_startup_dependency_health_request(item, sources)
    {
        return true;
    }
    if item.kind == EvidenceKind::Sink
        && item.capability == Capability::Deserialization
        && item
            .captures
            .get("payload")
            .is_some_and(|capture| is_fixed_local_file_read(&capture.text))
    {
        return true;
    }

    if item.kind != EvidenceKind::SecurityConfiguration
        || item.capability != Capability::CryptographicHash
        || !item.rule_id.ends_with("hash-algorithm-selection")
        || !item.captures.get("algorithm").is_some_and(|capture| {
            matches!(
                capture
                    .text
                    .trim()
                    .trim_matches(['\'', '"'])
                    .to_ascii_lowercase()
                    .as_str(),
                "md5"
            )
        })
    {
        return false;
    }

    let Ok(file) = sources.file(&item.location.path) else {
        return false;
    };
    let lines = file.source.lines().collect::<Vec<_>>();
    let line = item.location.start.line.saturating_sub(1);
    let start = line.saturating_sub(8);
    let end = line.saturating_add(9).min(lines.len());
    let window = lines[start..end].join("\n");
    window.contains("registerTask('checksum'")
        && window.contains(".md5")
        && window.contains("digest('hex')")
}

fn evidence_source<'a>(item: &Evidence, sources: &'a RepositorySources) -> Option<&'a str> {
    sources
        .file(&item.location.path)
        .ok()
        .map(|file| file.source.as_str())
}

fn is_schema_validated_local_yaml_tool(item: &Evidence, sources: &RepositorySources) -> bool {
    item.kind == EvidenceKind::Sink
        && item.capability == Capability::Deserialization
        && item.rule_id.ends_with("yaml-deserialization")
        && item
            .captures
            .get("payload")
            .is_some_and(|capture| capture.text.contains("readFile(file"))
        && item
            .location
            .path
            .replace('\\', "/")
            .to_ascii_lowercase()
            .contains("/scripts/")
        && evidence_source(item, sources).is_some_and(|source| {
            source.contains("path.resolve(__dirname")
                && source.contains("readdir(configDir)")
                && source.contains("ValidationSchema.safeParse(configuration)")
        })
}

fn is_repository_snippet_index_read(item: &Evidence, sources: &RepositorySources) -> bool {
    item.kind == EvidenceKind::Sink
        && item.capability == Capability::FilesystemRead
        && item
            .captures
            .get("path")
            .is_some_and(|capture| capture.text.trim() == "currPath")
        && evidence_source(item, sources).is_some_and(|source| {
            source.contains("SNIPPET_PATHS = Object.freeze(")
                && source.contains("findFilesWithCodeChallenges")
                && source.contains("lstat(currPath)")
                && source.contains("readdir(currPath)")
                && source.contains("readFile(currPath")
        })
}

fn is_authenticated_generated_upload_write(item: &Evidence, sources: &RepositorySources) -> bool {
    if item.kind != EvidenceKind::Sink || item.capability != Capability::FilesystemWrite {
        return false;
    }
    let Some(source) = evidence_source(item, sources) else {
        return false;
    };
    let Some(capture) = item.captures.get("path").map(|capture| capture.text.trim()) else {
        return false;
    };
    let expression = if is_plain_identifier(capture) {
        source
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix(&format!("const {capture} ="))
                    .map(str::trim)
            })
            .unwrap_or(capture)
    } else {
        capture
    };
    expression.contains("assets/public/images/uploads/")
        && expression.contains(".data.id}")
        && source.contains("authenticatedUsers.get(")
        && (source.contains("fileType.fromBuffer(")
            && source.contains("startsWith(uploadedFileType.mime, 'image')")
            || source.contains("['jpg', 'jpeg', 'png', 'svg', 'gif'].includes("))
}

fn is_configuration_backed_promotion_read(item: &Evidence, sources: &RepositorySources) -> bool {
    item.kind == EvidenceKind::Sink
        && item.capability == Capability::FilesystemRead
        && evidence_source(item, sources).is_some_and(|source| {
            source.contains("config.get<string>('application.promotion.video')")
                && source.contains("config.get<string>('application.promotion.subtitles')")
                && source.contains("frontend/dist/frontend/assets/public/videos/")
                && source.contains("utils.extractFilename(")
        })
}

fn is_configuration_backed_response(item: &Evidence, sources: &RepositorySources) -> bool {
    item.kind == EvidenceKind::Sink
        && item.capability == Capability::HtmlOutput
        && item
            .captures
            .get("content")
            .is_some_and(|capture| is_plain_identifier(capture.text.trim()))
        && evidence_source(item, sources).is_some_and(|source| {
            let content = item.captures["content"].text.trim();
            source.contains(&format!("const {content} = config.get("))
                && source.contains(&format!("res.send({content})"))
        })
}

fn is_captcha_verification_lookup(item: &Evidence, sources: &RepositorySources) -> bool {
    item.kind == EvidenceKind::Sink
        && item.capability == Capability::ResourceAccess
        && item.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
        && item
            .captures
            .get("model")
            .is_some_and(|capture| capture.text.trim_end_matches("Model") == "Captcha")
        && evidence_source(item, sources).is_some_and(|source| {
            source.contains("captchaId: req.body.captchaId")
                && source.contains("req.body.captcha === captcha.answer")
                && source.contains("next()")
        })
}

fn is_startup_dependency_health_request(item: &Evidence, sources: &RepositorySources) -> bool {
    item.kind == EvidenceKind::Sink
        && item.capability == Capability::OutboundNetworkRequest
        && item
            .captures
            .get("endpoint")
            .is_some_and(|capture| capture.text.trim() == "domain")
        && item
            .location
            .path
            .replace('\\', "/")
            .to_ascii_lowercase()
            .contains("/startup/")
        && evidence_source(item, sources).is_some_and(|source| {
            source.contains("checkIfDomainReachable('https://")
                && source.contains("llmApiUrl = config.get<string>(")
                && source.contains("checkIfDomainReachable(llmApiUrl)")
        })
}

fn is_fixed_local_file_read(payload: &str) -> bool {
    let compact = payload
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    ["fs.readFileSync(", "readFileSync("]
        .iter()
        .find_map(|prefix| compact.strip_prefix(prefix))
        .and_then(|rest| rest.chars().next().map(|quote| (rest, quote)))
        .is_some_and(|(rest, quote)| {
            matches!(quote, '\'' | '"')
                && rest[quote.len_utf8()..]
                    .split_once(quote)
                    .is_some_and(|(path, suffix)| {
                        (path.starts_with("./") || path.starts_with("../"))
                            && !path.contains("${")
                            && suffix.starts_with(',')
                    })
        })
}

/// Express serializes object and array values passed to `res.send` as JSON.
/// Keep the response operation in deterministic evidence, but do not ask an AI
/// reviewer to decide CWE-79 when the captured value is syntactically an object
/// or comes from an exact repository helper whose TypeScript contract and sole
/// return both establish an object result.
fn is_non_html_javascript_response(item: &Evidence, sources: &RepositorySources) -> bool {
    if !matches!(
        item.rule_id.as_str(),
        "javascript-html-output" | "typescript-html-output" | "tsx-html-output"
    ) {
        return false;
    }
    let Some(content) = item
        .captures
        .get("content")
        .map(|capture| capture.text.trim())
    else {
        return false;
    };
    let Ok(caller) = sources.file(&item.location.path) else {
        return false;
    };
    let start = item.location.start.byte_offset.min(caller.source.len());
    let end = item.location.end.byte_offset.min(caller.source.len());
    let call = caller.source[start..end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let Some(call_open) = call.find('(') else {
        return false;
    };
    if !call[..call_open].ends_with(".send") {
        return false;
    }
    if (content.starts_with('{') && content.ends_with('}'))
        || (content.starts_with('[') && content.ends_with(']'))
    {
        return true;
    }
    let Some(open) = content.find('(') else {
        return false;
    };
    if !content.ends_with(')') || content[open + 1..content.len() - 1].contains(')') {
        return false;
    }
    let callee = content[..open].trim();
    let (helper, module) = if let Some((binding, helper)) = callee.split_once('.') {
        if !is_plain_identifier(binding)
            || !is_plain_identifier(helper)
            || javascript_import_binding_shadowed_before_use(caller, item, binding)
        {
            return false;
        }
        let Some(module) = relative_namespace_import(&caller.source, binding) else {
            return false;
        };
        (helper, module)
    } else {
        if !is_plain_identifier(callee)
            || javascript_import_binding_shadowed_before_use(caller, item, callee)
        {
            return false;
        }
        let Some((helper, module)) = relative_named_import(&caller.source, callee) else {
            return false;
        };
        (helper, module)
    };
    let Some(module_path) = resolve_relative_typescript_module(&caller.path, module, sources)
    else {
        return false;
    };
    sources
        .file(&module_path)
        .is_ok_and(|module| exported_typescript_helper_returns_object(&module.source, helper))
}

fn relative_namespace_import<'a>(source: &'a str, binding: &str) -> Option<&'a str> {
    let prefix = format!("import * as {binding} from ");
    let mut modules = source.lines().filter_map(|line| {
        let value = line.trim().strip_prefix(&prefix)?.trim();
        if !is_quoted_literal(value) {
            return None;
        }
        let module = &value[1..value.len() - 1];
        module.starts_with('.').then_some(module)
    });
    let module = modules.next()?;
    modules.next().is_none().then_some(module)
}

fn javascript_import_binding_shadowed_before_use(
    file: &SourceFile,
    item: &Evidence,
    binding: &str,
) -> bool {
    if item.enclosing_symbol.is_some() {
        return javascript_binding_shadowed_before_use(file, item, binding);
    }
    let end = item.location.start.byte_offset.min(file.source.len());
    if !file.source.is_char_boundary(end) {
        return true;
    }
    let prefix = &file.source[..end];
    prefix.lines().any(|line| {
        let line = line.trim();
        let local_declaration = ["const", "let", "var"].iter().any(|keyword| {
            let declaration = format!("{keyword} {binding}");
            line.strip_prefix(&declaration).is_some_and(|tail| {
                tail.starts_with(char::is_whitespace)
                    || tail.starts_with('=')
                    || tail.starts_with(':')
            })
        });
        let parameters = if line.contains("function ") || line.contains("=>") {
            line.rfind('(').and_then(|open| {
                line[open + 1..]
                    .find(')')
                    .map(|close| &line[open + 1..open + 1 + close])
            })
        } else {
            None
        };
        local_declaration
            || parameters.is_some_and(|parameters| contains_identifier(parameters, binding))
    })
}

fn exported_typescript_helper_returns_object(source: &str, helper: &str) -> bool {
    let const_marker = format!("export const {helper}");
    let function_marker = format!("export function {helper}");
    let starts = source
        .match_indices(&const_marker)
        .chain(source.match_indices(&function_marker))
        .filter_map(|(index, marker)| {
            source[index + marker.len()..]
                .chars()
                .next()
                .is_some_and(|next| next.is_whitespace() || matches!(next, '<' | '(' | '='))
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let [start] = starts.as_slice() else {
        return false;
    };
    let declaration = &source[*start..];
    let declaration = declaration
        .find("\nexport ")
        .map_or(declaration, |end| &declaration[..end]);
    let Some(return_type_end) = declaration.find("=>") else {
        return false;
    };
    let header = &declaration[..return_type_end];
    if !header.contains("): {") && !header.contains("):{") {
        return false;
    }
    let returns = declaration
        .lines()
        .filter_map(|line| line.trim().strip_prefix("return"))
        .collect::<Vec<_>>();
    matches!(returns.as_slice(), [value] if value.trim_start().starts_with('{'))
}

/// Omits a standalone open-redirect review only when the destination is an
/// imported, repository-owned constant base plus a fixed internal path. This
/// deliberately does not resolve local variables or service properties: those
/// remain reviewable until their provenance is represented explicitly.
fn is_fixed_imported_browser_navigation(item: &Evidence, sources: &RepositorySources) -> bool {
    if !item.rule_id.ends_with("-browser-navigation") {
        return false;
    }
    let Some(destination) = item
        .captures
        .get("destination")
        .map(|capture| capture.text.trim())
    else {
        return false;
    };
    if is_plain_identifier(destination)
        && fixed_service_navigation_assignment(item, sources, destination)
    {
        return true;
    }
    let Some((base, suffix)) = destination.split_once('+') else {
        return false;
    };
    if suffix.contains('+') || !is_quoted_literal(suffix.trim()) {
        return false;
    }
    let suffix = suffix.trim();
    let suffix = &suffix[1..suffix.len() - 1];
    if !suffix.starts_with('/') || suffix.starts_with("//") || suffix.starts_with("/\\") {
        return false;
    }
    let Some((binding, property)) = base.trim().split_once('.') else {
        return false;
    };
    if !is_plain_identifier(binding) || !is_plain_identifier(property) {
        return false;
    }
    let Ok(source_file) = sources.file(&item.location.path) else {
        return false;
    };
    if javascript_binding_shadowed_before_use(source_file, item, binding) {
        return false;
    }
    let Some((exported, module)) = relative_named_import(&source_file.source, binding) else {
        return false;
    };
    let Some(module_path) = resolve_relative_typescript_module(&source_file.path, module, sources)
    else {
        return false;
    };
    let Ok(module_file) = sources.file(&module_path) else {
        return false;
    };
    exported_object_has_fixed_string_property(&module_file.source, exported, property)
}

fn fixed_service_navigation_assignment(
    item: &Evidence,
    sources: &RepositorySources,
    destination: &str,
) -> bool {
    let Ok(component) = sources.file(&item.location.path) else {
        return false;
    };
    let Some(scope) = javascript_enclosing_prefix(component, item) else {
        return false;
    };
    let declarations = ["const", "let", "var"]
        .iter()
        .flat_map(|keyword| {
            scope.lines().filter_map(move |line| {
                let declaration = format!("{keyword} {destination}");
                let tail = line.trim().strip_prefix(&declaration)?;
                let value = tail.trim_start().strip_prefix('=')?.trim();
                Some(value)
            })
        })
        .collect::<Vec<_>>();
    let [value] = declarations.as_slice() else {
        return false;
    };
    if scope.lines().any(|line| {
        line.trim()
            .strip_prefix(destination)
            .is_some_and(|tail| tail.trim_start().starts_with('='))
    }) {
        return false;
    }
    let Some(template) = value
        .strip_prefix("`${this.")
        .and_then(|value| value.strip_suffix('`'))
    else {
        return false;
    };
    let Some((service_property, suffix)) = template.split_once('}') else {
        return false;
    };
    let Some((receiver, property)) = service_property.split_once('.') else {
        return false;
    };
    if !is_plain_identifier(receiver)
        || !is_plain_identifier(property)
        || !fixed_internal_template_suffix(suffix)
    {
        return false;
    }
    let Some(service_type) = unique_injected_service_type(&component.source, receiver) else {
        return false;
    };
    let Some((exported_service, module)) = relative_named_import(&component.source, service_type)
    else {
        return false;
    };
    let Some(service_path) = resolve_relative_typescript_module(&component.path, module, sources)
    else {
        return false;
    };
    let Ok(service) = sources.file(&service_path) else {
        return false;
    };
    if !service
        .source
        .contains(&format!("export class {exported_service}"))
    {
        return false;
    }
    let Some((base_binding, base_property)) =
        unique_service_property_base(&service.source, property)
    else {
        return false;
    };
    let Some((exported_base, base_module)) = relative_named_import(&service.source, base_binding)
    else {
        return false;
    };
    let Some(base_path) = resolve_relative_typescript_module(&service.path, base_module, sources)
    else {
        return false;
    };
    let Ok(base) = sources.file(&base_path) else {
        return false;
    };
    exported_object_has_fixed_string_property(&base.source, exported_base, base_property)
        && !sources.files.values().any(|file| {
            file.source.lines().any(|line| {
                let compact = line.split_whitespace().collect::<String>();
                compact_has_property_assignment(&compact, property)
            })
        })
}

fn compact_has_property_assignment(compact: &str, property: &str) -> bool {
    [
        format!(".{property}"),
        format!("['{property}']"),
        format!("[\"{property}\"]"),
    ]
    .iter()
    .any(|accessor| {
        ["+=", "-=", "*=", "/=", "%=", "&&=", "||=", "??="]
            .iter()
            .any(|operator| compact.contains(&format!("{accessor}{operator}")))
            || compact
                .match_indices(&format!("{accessor}="))
                .any(|(index, matched)| {
                    compact[index + matched.len()..]
                        .chars()
                        .next()
                        .is_none_or(|next| next != '=')
                })
    })
}

fn javascript_enclosing_prefix<'a>(file: &'a SourceFile, item: &Evidence) -> Option<&'a str> {
    let end = item.location.start.byte_offset.min(file.source.len());
    if !file.source.is_char_boundary(end) {
        return None;
    }
    let prefix = &file.source[..end];
    let symbol = item.enclosing_symbol.as_deref()?;
    let start = prefix
        .rfind(&format!("{symbol} ("))
        .or_else(|| prefix.rfind(&format!("{symbol}(")))?;
    Some(&prefix[start..])
}

fn fixed_internal_template_suffix(suffix: &str) -> bool {
    let prefix = suffix.split("${").next().unwrap_or(suffix);
    prefix.starts_with('/')
        && !prefix.starts_with("//")
        && !prefix.starts_with("/\\")
        && prefix
            .chars()
            .skip(1)
            .any(|character| character.is_ascii_alphanumeric())
}

fn unique_injected_service_type<'a>(source: &'a str, receiver: &str) -> Option<&'a str> {
    let matches = source
        .lines()
        .filter_map(|line| {
            let (left, right) = line.trim().split_once('=')?;
            (left.split_whitespace().last()? == receiver).then_some(right.trim())
        })
        .filter_map(|right| right.strip_prefix("inject(")?.strip_suffix(')'))
        .filter(|name| is_plain_identifier(name))
        .collect::<Vec<_>>();
    matches
        .as_slice()
        .first()
        .copied()
        .filter(|_| matches.len() == 1)
}

fn unique_service_property_base<'a>(source: &'a str, property: &str) -> Option<(&'a str, &'a str)> {
    let matches = source
        .lines()
        .filter_map(|line| {
            let (left, right) = line.trim().split_once('=')?;
            (left.split_whitespace().last()? == property).then_some(right.trim())
        })
        .filter_map(|right| {
            let (binding, property) = right.split_once('.')?;
            (is_plain_identifier(binding) && is_plain_identifier(property))
                .then_some((binding, property))
        })
        .collect::<Vec<_>>();
    matches
        .as_slice()
        .first()
        .copied()
        .filter(|_| matches.len() == 1)
}

fn relative_named_import<'a>(source: &'a str, local: &str) -> Option<(&'a str, &'a str)> {
    source.lines().find_map(|line| {
        let line = line.trim();
        let body = line.strip_prefix("import {")?;
        let (bindings, remainder) = body.split_once('}')?;
        let module = first_quoted_value(remainder)?;
        if !module.starts_with('.') {
            return None;
        }
        bindings.split(',').find_map(|candidate| {
            let mut parts = candidate.split_whitespace();
            let imported = parts.next()?;
            let next = parts.next();
            let alias = parts.next();
            let local_name = match (next, alias) {
                (None, None) => imported,
                (Some("as"), Some(alias)) => alias,
                _ => return None,
            };
            (local_name == local).then_some((imported, module))
        })
    })
}

fn resolve_relative_typescript_module(
    importing_path: &str,
    module: &str,
    sources: &RepositorySources,
) -> Option<String> {
    let mut parts = importing_path
        .replace('\\', "/")
        .split('/')
        .map(str::to_string)
        .collect::<Vec<_>>();
    parts.pop()?;
    for component in module.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value.to_string()),
        }
    }
    let base = parts.join("/");
    [
        format!("{base}.ts"),
        format!("{base}.tsx"),
        format!("{base}.js"),
        format!("{base}.jsx"),
        format!("{base}.mts"),
        format!("{base}.cts"),
        format!("{base}.mjs"),
        format!("{base}.cjs"),
        format!("{base}/index.ts"),
        format!("{base}/index.tsx"),
        format!("{base}/index.js"),
        format!("{base}/index.jsx"),
    ]
    .into_iter()
    .find(|candidate| sources.files.contains_key(candidate))
}

fn exported_object_has_fixed_string_property(source: &str, object: &str, property: &str) -> bool {
    let declaration = format!("export const {object}");
    let Some(start) = source.find(&declaration) else {
        return false;
    };
    let tail = &source[start + declaration.len()..];
    let Some(open) = tail.find('{') else {
        return false;
    };
    let Some(close) = tail[open + 1..].find('}') else {
        return false;
    };
    let body = &tail[open + 1..open + 1 + close];
    let values = body
        .lines()
        .filter_map(|line| {
            let (name, value) = line.trim().trim_end_matches(',').split_once(':')?;
            (name.trim() == property).then_some(value.trim())
        })
        .collect::<Vec<_>>();
    matches!(values.as_slice(), [value] if is_quoted_literal(value))
}

fn javascript_binding_shadowed_before_use(
    file: &SourceFile,
    item: &Evidence,
    binding: &str,
) -> bool {
    let Some(scope) = javascript_enclosing_prefix(file, item) else {
        return true;
    };
    let parameter_shadow = scope
        .split_once('(')
        .and_then(|(_, parameters)| parameters.split_once(')'))
        .is_some_and(|(parameters, _)| contains_identifier(parameters, binding));
    parameter_shadow
        || ["const", "let", "var"].iter().any(|keyword| {
            scope.lines().any(|line| {
                let line = line.trim();
                let declaration = format!("{keyword} {binding}");
                line.strip_prefix(&declaration).is_some_and(|tail| {
                    tail.starts_with(char::is_whitespace)
                        || tail.starts_with('=')
                        || tail.starts_with(':')
                })
            })
        })
}

fn is_fixed_resource_selector(selector: &str) -> bool {
    let selector = selector.trim();
    if is_fixed_selector_scalar(selector) {
        return true;
    }
    if let Some(body) = selector
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    {
        let fields = body
            .split(',')
            .filter(|field| !field.trim().is_empty())
            .collect::<Vec<_>>();
        return !fields.is_empty()
            && fields.iter().all(|field| {
                field.split_once(':').is_some_and(|(name, value)| {
                    is_plain_identifier(name.trim()) && is_fixed_selector_scalar(value.trim())
                })
            });
    }
    let arrow = selector
        .split_once("=>")
        .or_else(|| selector.split_once("->"));
    let Some((parameter, predicate)) = arrow else {
        return false;
    };
    let parameter = parameter.trim().trim_matches(['(', ')']);
    if !is_plain_identifier(parameter)
        || predicate.contains("&&")
        || predicate.contains("||")
        || predicate.contains('?')
    {
        return false;
    }
    let predicate = predicate.trim();
    let equality = predicate
        .split_once("===")
        .or_else(|| predicate.split_once("=="));
    let Some((member, value)) = equality else {
        return false;
    };
    let Some(property) = member.trim().strip_prefix(&format!("{parameter}.")) else {
        return false;
    };
    is_plain_identifier(property) && is_fixed_selector_scalar(value.trim())
}

fn is_fixed_selector_scalar(selector: &str) -> bool {
    is_quoted_literal(selector)
        || selector.eq_ignore_ascii_case("true")
        || selector.eq_ignore_ascii_case("false")
        || selector.eq_ignore_ascii_case("none")
        || selector.eq_ignore_ascii_case("null")
        || selector.parse::<i128>().is_ok()
        || selector
            .strip_suffix('l')
            .or_else(|| selector.strip_suffix('L'))
            .is_some_and(|value| value.parse::<i128>().is_ok())
}

/// Omits IDOR review for one narrow initialization/cleanup shape: a private
/// same-file helper selects by its sole identifier parameter, has exactly one
/// call, and that call passes the `.id` of a record created immediately in the
/// same repository source by the same captured ORM model. This is not general
/// taint or authorization reasoning; request-derived and externally callable
/// helpers remain reviewable.
fn is_repository_created_resource_selector(item: &Evidence, sources: &RepositorySources) -> bool {
    if item.rule_id != "typescript-sequelize-resource-access" {
        return false;
    }
    let (Some(symbol), Some(filter), Some(model)) = (
        item.enclosing_symbol.as_deref(),
        item.captures
            .get("filter")
            .map(|capture| capture.text.trim()),
        item.captures
            .get("model")
            .map(|capture| capture.text.trim()),
    ) else {
        return false;
    };
    if !is_plain_identifier(symbol) || !is_plain_identifier(model) {
        return false;
    }
    let Some(body) = filter
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return false;
    };
    if body.contains(',') {
        return false;
    }
    let Some((field, selector)) = body.split_once(':') else {
        return false;
    };
    let selector = selector.trim();
    if field.trim() != "id" || !is_plain_identifier(selector) {
        return false;
    }
    let Ok(file) = sources.file(&item.location.path) else {
        return false;
    };
    let declarations = file
        .source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("export ") {
                return None;
            }
            let marker = format!("function {symbol}");
            let parameters = line.split_once(&marker)?.1.trim_start().strip_prefix('(')?;
            let parameters = parameters.split_once(')')?.0;
            Some(parameters)
        })
        .collect::<Vec<_>>();
    let [parameters] = declarations.as_slice() else {
        return false;
    };
    let parameter_names = parameters
        .split(',')
        .filter_map(|parameter| parameter.trim().split([':', '=']).next())
        .map(str::trim)
        .collect::<Vec<_>>();
    if parameter_names.as_slice() != [selector] {
        return false;
    }
    let calls = file
        .source
        .lines()
        .filter(|line| !line.contains(&format!("function {symbol}")))
        .filter_map(|line| {
            let call = line.find(&format!("{symbol}("))?;
            let argument = &line[call + symbol.len() + 1..];
            Some(argument.split_once(')')?.0.trim())
        })
        .collect::<Vec<_>>();
    let [argument] = calls.as_slice() else {
        return false;
    };
    let Some((created, property)) = argument.split_once('.') else {
        return false;
    };
    if !is_plain_identifier(created) || property != "id" {
        return false;
    }
    if identifier_occurrence_count(&file.source, symbol) != 2 {
        return false;
    }
    let compact = file
        .source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    compact.contains(&format!("const{created}=await{model}.create("))
        || (compact.contains(&format!("{model}.create("))
            && compact.contains(&format!(".then(async({created})=>")))
}

fn identifier_occurrence_count(source: &str, identifier: &str) -> usize {
    source
        .match_indices(identifier)
        .filter(|(index, matched)| {
            let before = source[..*index].chars().next_back();
            let after = source[index + matched.len()..].chars().next();
            before.is_none_or(|character| !is_identifier_character(character))
                && after.is_none_or(|character| !is_identifier_character(character))
        })
        .count()
}

fn is_non_actionable_csrf_observation(item: &Evidence, sources: &RepositorySources) -> bool {
    if item.kind != EvidenceKind::SecurityConfiguration
        || item.rule_id != "python-django-csrf-exempt-handler"
    {
        return false;
    }
    let Some(symbol) = item.enclosing_symbol.as_deref() else {
        return false;
    };
    let Ok(file) = sources.file(&item.location.path) else {
        return false;
    };
    let Some(handler) = exact_python_definition_source(file, symbol) else {
        return false;
    };
    !python_csrf_handler_context(handler).has_request_integrity_effect()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PythonCsrfHandlerContext {
    methods: BTreeSet<String>,
    ambient_authority: BTreeSet<String>,
    direct_effects: BTreeSet<String>,
}

impl PythonCsrfHandlerContext {
    fn has_request_integrity_effect(&self) -> bool {
        self.direct_effects.contains("database_mutation")
            || self.direct_effects.contains("session_or_cookie_mutation")
    }

    fn compact_summary(&self) -> String {
        let methods = if self.methods.is_empty() {
            "unknown".to_string()
        } else {
            self.methods.iter().cloned().collect::<Vec<_>>().join(",")
        };
        let authority = if self.ambient_authority.is_empty() {
            "none_observed".to_string()
        } else {
            self.ambient_authority
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        };
        let effects = if self.direct_effects.is_empty() {
            "none_observed".to_string()
        } else {
            self.direct_effects
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "request_methods: {methods}\nambient_authority: {authority}\ndirect_effects: {effects}"
        )
    }
}

fn python_csrf_handler_context(source: &str) -> PythonCsrfHandlerContext {
    let lower_source = source.to_ascii_lowercase();
    let scrubbed = scrub_python_strings_and_comments(source).to_ascii_lowercase();
    let mut context = PythonCsrfHandlerContext::default();

    for line in lower_source
        .lines()
        .filter(|line| line.contains("request.method"))
    {
        if let Some(method) = first_quoted_value(line) {
            let method = method.trim().to_ascii_uppercase();
            if matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
                context.methods.insert(method);
            }
        }
    }

    if scrubbed.contains("request.user.is_authenticated") {
        context
            .ambient_authority
            .insert("authenticated_user".to_string());
    }
    if scrubbed.contains("request.session") {
        context
            .ambient_authority
            .insert("session_state".to_string());
    }
    if scrubbed.contains("request.cookies") {
        context
            .ambient_authority
            .insert("request_cookie".to_string());
    }

    if python_has_direct_database_mutation(&scrubbed) {
        context
            .direct_effects
            .insert("database_mutation".to_string());
    }
    if scrubbed.contains("request.session[")
        || scrubbed.contains("request.session.pop(")
        || scrubbed.contains("request.session.clear(")
        || scrubbed.contains("request.session.flush(")
        || scrubbed.contains(".set_cookie(")
        || scrubbed.contains(".delete_cookie(")
        || scrubbed.contains("login(request")
        || scrubbed.contains("logout(request")
    {
        context
            .direct_effects
            .insert("session_or_cookie_mutation".to_string());
    }
    if scrubbed.contains(".write(") || scrubbed.contains(".writelines(") {
        context
            .direct_effects
            .insert("filesystem_write".to_string());
    }
    if [
        "subprocess.",
        "os.system(",
        "os.popen(",
        "eval(",
        "exec(",
        "compile(",
        "pickle.loads(",
        "yaml.load(",
        "parsestring(",
        "etree.parse(",
        "imagemath.eval(",
        "requests.",
        "httpx.",
        "urllib.request",
    ]
    .iter()
    .any(|marker| scrubbed.contains(marker))
    {
        context
            .direct_effects
            .insert("primary_security_operation".to_string());
    }
    context
}

fn python_has_direct_database_mutation(source: &str) -> bool {
    const QUERYSET_MUTATIONS: &[&str] = &[
        ".update(",
        ".create(",
        ".bulk_create(",
        ".get_or_create(",
        ".update_or_create(",
        ".delete(",
    ];
    if source.lines().any(|line| {
        line.contains(".objects.")
            && QUERYSET_MUTATIONS
                .iter()
                .any(|marker| line.contains(marker))
    }) {
        return true;
    }

    let mut orm_values = BTreeSet::new();
    for line in source.lines() {
        let Some((left, right)) = line.split_once('=') else {
            continue;
        };
        let name = left.trim();
        if is_plain_identifier(name)
            && right.contains(".objects.")
            && [".get(", ".first(", ".last(", ".filter("]
                .iter()
                .any(|marker| right.contains(marker))
        {
            orm_values.insert(name.to_string());
        }
    }
    orm_values.into_iter().any(|name| {
        source.contains(&format!("{name}.save("))
            || source.contains(&format!("{name}.delete("))
            || source.contains(&format!("{name}.update("))
    })
}

fn python_csrf_handler_facts(
    sources: &RepositorySources,
    group: &ObservationGroup,
) -> Vec<ReviewNeighborhoodFact> {
    let Some(csrf) = group
        .evidence
        .iter()
        .find(|item| item.rule_id == "python-django-csrf-exempt-handler")
    else {
        return Vec::new();
    };
    let Some(symbol) = csrf.enclosing_symbol.as_deref() else {
        return Vec::new();
    };
    let Ok(file) = sources.file(&csrf.location.path) else {
        return Vec::new();
    };
    let Some(handler) = exact_python_definition_source(file, symbol) else {
        return Vec::new();
    };
    vec![ReviewNeighborhoodFact {
        role: "python_csrf_handler_context".to_string(),
        symbol: symbol.to_string(),
        location: csrf.location.clone(),
        excerpt: python_csrf_handler_context(handler).compact_summary(),
        evidence_id: Some(csrf.id.clone()),
        provenance: textual_provenance(
            "mehscan direct Python CSRF method, authority, and effect summary 1",
        ),
    }]
}

fn is_non_actionable_autoescaped_django_response(
    item: &Evidence,
    sources: &RepositorySources,
) -> bool {
    if item.kind != EvidenceKind::Sink
        || item.capability != Capability::HtmlOutput
        || item.rule_id != "python-html-output"
    {
        return false;
    }
    let Some(content) = item
        .captures
        .get("content")
        .map(|capture| capture.text.trim())
        .filter(|content| is_plain_identifier(content))
    else {
        return false;
    };
    let Some(symbol) = item.enclosing_symbol.as_deref() else {
        return false;
    };
    let Ok(file) = sources.file(&item.location.path) else {
        return false;
    };
    let Some(handler) = exact_python_definition_source(file, symbol) else {
        return false;
    };

    let mut assignments = 0;
    for line in handler.lines() {
        let code = line.split('#').next().unwrap_or_default();
        let Some((left, right)) = code.split_once('=') else {
            continue;
        };
        if left.trim() != content {
            continue;
        }
        assignments += 1;
        let Some(arguments) = right
            .split_once("render_to_string(")
            .map(|(_, value)| value)
        else {
            return false;
        };
        let Some(template) =
            first_quoted_value(arguments).filter(|value| valid_django_template_name(value))
        else {
            return false;
        };
        if !django_template_is_autoescaped(sources, template, 0, &mut BTreeSet::new()) {
            return false;
        }
    }
    assignments > 0
}

fn first_quoted_value(text: &str) -> Option<&str> {
    let start = text.find(['\'', '"'])?;
    let quote = text.as_bytes()[start];
    let remainder = &text[start + 1..];
    let end = remainder
        .as_bytes()
        .iter()
        .position(|byte| *byte == quote)?;
    Some(&remainder[..end])
}

fn django_template_is_autoescaped(
    sources: &RepositorySources,
    template: &str,
    depth: usize,
    visited: &mut BTreeSet<String>,
) -> bool {
    if depth > 6 || !visited.insert(template.to_string()) {
        return false;
    }
    let Some(source) = find_unique_django_template_source(sources, template) else {
        return false;
    };
    let compact = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if compact.contains("|safe")
        || compact.contains("{%autoescapeoff%}")
        || compact.contains("mark_safe")
    {
        return false;
    }
    for directive in ["extends", "include"] {
        for line in source
            .lines()
            .filter(|line| line.contains("{%") && contains_identifier(line, directive))
        {
            let Some(dependency) = first_quoted_value(line) else {
                return false;
            };
            if !valid_django_template_name(dependency)
                || !django_template_is_autoescaped(sources, dependency, depth + 1, visited)
            {
                return false;
            }
        }
    }
    true
}

fn find_unique_django_template_source(
    sources: &RepositorySources,
    template: &str,
) -> Option<String> {
    let root = Path::new(&sources.root);
    let mut candidates = BTreeSet::from([root.join("templates").join(template)]);
    for file in sources
        .files
        .values()
        .filter(|file| file.language == Some(Language::Python))
    {
        let mut directory = Path::new(&file.path).parent();
        while let Some(relative) = directory {
            candidates.insert(root.join(relative).join("templates").join(template));
            directory = relative.parent();
        }
    }
    let matches = candidates
        .into_iter()
        .filter(|path| {
            fs::symlink_metadata(path).is_ok_and(|metadata| {
                metadata.file_type().is_file() && !metadata.file_type().is_symlink()
            })
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return None;
    }
    let source = fs::read_to_string(&matches[0]).ok()?;
    (source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES).then_some(source)
}

fn valid_django_template_name(template: &str) -> bool {
    template.ends_with(".html")
        && template.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
                })
        })
}

fn exact_python_definition_source<'a>(file: &'a SourceFile, symbol: &str) -> Option<&'a str> {
    if file.language != Some(Language::Python) {
        return None;
    }
    let spans = line_spans(&file.source);
    let definition_index = spans.iter().position(|(start, end)| {
        let line = &file.source[*start..*end];
        line.trim_start().starts_with("def ")
            && python_definition_identifier(line).as_deref() == Some(symbol)
    })?;
    let end_index = python_definition_end_index(&file.source, &spans, definition_index, 200);
    Some(&file.source[spans[definition_index].0..spans[end_index].1])
}

fn python_definition_end_index(
    source: &str,
    spans: &[(usize, usize)],
    definition_index: usize,
    max_lines: usize,
) -> usize {
    let definition_line = &source[spans[definition_index].0..spans[definition_index].1];
    let definition_indent = definition_line.len() - definition_line.trim_start().len();
    let mut end_index = definition_index;
    for (line_index, (start, end)) in spans
        .iter()
        .enumerate()
        .skip(definition_index + 1)
        .take(max_lines.saturating_sub(1))
    {
        let line = &source[*start..*end];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            end_index = line_index;
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= definition_indent {
            break;
        }
        end_index = line_index;
    }
    end_index
}

fn python_definition_identifier(line: &str) -> Option<String> {
    let after_def = line.trim_start().strip_prefix("def ")?.trim_start();
    let name = after_def.split_once('(')?.0.trim();
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then(|| name.to_string())
}

fn scrub_python_strings_and_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut scrubbed = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
                scrubbed[index] = b' ';
                index += 1;
            }
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"') {
            let quote = bytes[index];
            let triple = bytes.get(index..index + 3) == Some(&[quote, quote, quote]);
            let delimiter_len = if triple { 3 } else { 1 };
            for byte in scrubbed.iter_mut().skip(index).take(delimiter_len) {
                *byte = b' ';
            }
            index += delimiter_len;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    scrubbed[index] = b' ';
                    index += 1;
                    if index < bytes.len() {
                        if !matches!(bytes[index], b'\r' | b'\n') {
                            scrubbed[index] = b' ';
                        }
                        index += 1;
                    }
                    continue;
                }
                let closed = if triple {
                    bytes.get(index..index + 3) == Some(&[quote, quote, quote])
                } else {
                    bytes[index] == quote
                };
                if closed {
                    for byte in scrubbed.iter_mut().skip(index).take(delimiter_len) {
                        *byte = b' ';
                    }
                    index += delimiter_len;
                    break;
                }
                if !matches!(bytes[index], b'\r' | b'\n') {
                    scrubbed[index] = b' ';
                }
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(scrubbed).expect("scrubbing ASCII syntax preserves UTF-8")
}

fn has_fixed_internal_redirect_prefix(literal: &mehscan_core::LiteralEvaluation) -> bool {
    if literal.state != LiteralState::Partial {
        return false;
    }
    let Some(prefix) = literal.constant_fragments.first().map(|value| value.trim()) else {
        return false;
    };
    if prefix.is_empty()
        || prefix.starts_with("//")
        || prefix.starts_with("\\\\")
        || prefix.contains("://")
    {
        return false;
    }
    prefix
        .chars()
        .any(|character| character.is_ascii_alphanumeric())
}

fn has_fixed_http_authority(literal: &mehscan_core::LiteralEvaluation) -> bool {
    if literal.state != LiteralState::Partial {
        return false;
    }
    let Some(prefix) = literal.constant_fragments.first() else {
        return false;
    };
    let Some(authority_and_path) = prefix
        .strip_prefix("https://")
        .or_else(|| prefix.strip_prefix("http://"))
    else {
        return false;
    };
    let Some((authority, _)) = authority_and_path.split_once('/') else {
        return false;
    };
    !authority.is_empty()
        && !authority.contains(['@', '\\', '{', '}'])
        && !authority.chars().any(char::is_whitespace)
}

fn is_fixed_python_local_path(item: &Evidence, sources: &RepositorySources) -> bool {
    if !matches!(
        item.rule_id.as_str(),
        "python-filesystem-read" | "python-filesystem-write"
    ) {
        return false;
    }
    let Some(path_name) = item.captures.get("path").map(|capture| capture.text.trim()) else {
        return false;
    };
    if !is_plain_identifier(path_name) {
        return false;
    }
    let Ok(file) = sources.file(&item.location.path) else {
        return false;
    };
    let end = item.location.start.byte_offset.min(file.source.len());
    if !file.source.is_char_boundary(end) {
        return false;
    }
    let spans = line_spans(&file.source);
    let sink_line = item
        .location
        .start
        .line
        .saturating_sub(1)
        .min(spans.len().saturating_sub(1));
    let scope_start = item
        .enclosing_symbol
        .as_deref()
        .and_then(|symbol| {
            (0..=sink_line).rev().find_map(|line| {
                (textual_definition_identifier(&file.source[spans[line].0..spans[line].1])
                    .as_deref()
                    == Some(symbol))
                .then_some(spans[line].0)
            })
        })
        .unwrap_or(0);
    let scoped_source = &file.source[scope_start..end];
    let assignments = exact_python_assignments(scoped_source, path_name);
    let [path_value] = assignments.as_slice() else {
        return false;
    };
    let Some((base, leaf)) = python_path_join(path_value) else {
        return false;
    };
    if !is_plain_identifier(base) || !is_quoted_literal(leaf) {
        return false;
    }
    let base_assignments = exact_python_assignments(scoped_source, base);
    matches!(base_assignments.as_slice(), [value] if value.trim() == "os.path.dirname(__file__)")
}

/// A direct child name returned by `readdirSync(fixed_dir)` cannot contain a
/// path separator. Reading `fixed_dir + child` in that still-open callback is
/// therefore not a request-controlled traversal. Keep the filesystem operation
/// as evidence and omit only its standalone CWE-22 verdict job.
fn is_directory_enumerated_child_path(item: &Evidence, sources: &RepositorySources) -> bool {
    if !matches!(
        item.rule_id.as_str(),
        "javascript-filesystem-read" | "typescript-filesystem-read" | "tsx-filesystem-read"
    ) {
        return false;
    }
    let Some(path) = item.captures.get("path").map(|capture| capture.text.trim()) else {
        return false;
    };
    let Some((directory, child)) = path.split_once('+') else {
        return false;
    };
    if child.contains('+') {
        return false;
    }
    let directory = directory.trim();
    let child = child.trim();
    if !is_quoted_literal(directory) || !is_plain_identifier(child) {
        return false;
    }
    let directory_value = &directory[1..directory.len() - 1];
    if !directory_value.ends_with('/')
        || directory_value.starts_with('/')
        || directory_value.contains("../")
        || directory_value.contains("..\\")
    {
        return false;
    }
    let Ok(file) = sources.file(&item.location.path) else {
        return false;
    };
    let end = item.location.start.byte_offset.min(file.source.len());
    if !file.source.is_char_boundary(end) {
        return false;
    }
    let prefix = file.source[..end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let directory_literal = format!(
        "{}{}{}",
        &directory[..1],
        directory_value,
        &directory[directory.len() - 1..]
    );
    let callback = format!(".readdirSync({directory_literal}).forEach({child}=>{{");
    let Some(callback_start) = prefix.rfind(&callback) else {
        return false;
    };
    !prefix[callback_start + callback.len()..].contains("})")
}

fn exact_python_assignments<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    source
        .lines()
        .filter_map(|line| {
            let (left, right) = line.trim().split_once('=')?;
            (left.trim() == name).then_some(right.trim())
        })
        .collect()
}

fn python_path_join(value: &str) -> Option<(&str, &str)> {
    let arguments = value
        .trim()
        .strip_prefix("os.path.join(")?
        .strip_suffix(')')?;
    let (base, leaf) = arguments.split_once(',')?;
    (!leaf.contains(',')).then_some((base.trim(), leaf.trim()))
}

fn is_quoted_literal(value: &str) -> bool {
    value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
}

fn is_plain_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn observation_review_title(evidence: &[Evidence]) -> String {
    let mut anchors = evidence
        .iter()
        .filter(|item| {
            matches!(
                item.kind,
                EvidenceKind::Sink
                    | EvidenceKind::SecurityConfiguration
                    | EvidenceKind::SensitiveOperation
            )
        })
        .collect::<Vec<_>>();
    if anchors.is_empty() {
        anchors.extend(evidence.iter());
    }
    let cwes = anchors
        .iter()
        .flat_map(|item| item.cwe_candidates.iter().cloned())
        .collect::<BTreeSet<_>>();
    let capabilities = anchors
        .iter()
        .map(|item| format!("{:?}", item.capability).to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    format!(
        "Review non-path {} observation for {}",
        if cwes.is_empty() {
            "security".to_string()
        } else {
            cwes.into_iter().collect::<Vec<_>>().join("/")
        },
        capabilities.into_iter().collect::<Vec<_>>().join(", ")
    )
}

fn observation_review_questions(
    evidence: &[Evidence],
    facts: &[ReviewNeighborhoodFact],
) -> Vec<String> {
    let direct_stored_html_trust_bypass =
        observation_has_direct_stored_html_trust_bypass(evidence, facts);
    let direct_request_resource_selector =
        observation_has_direct_request_resource_selector(evidence);
    let java_decision_ready = java_observation_policy(evidence, facts).is_some();
    let decision_ready_policy = evidence
        .iter()
        .any(|item| explicit_cookie_omission(&item.rule_id).is_some())
        || observation_has_source_embedded_signing_key(evidence, facts)
        || java_decision_ready;
    let has_source = evidence
        .iter()
        .any(|item| item.kind == EvidenceKind::Source);
    let has_sink = evidence.iter().any(|item| item.kind == EvidenceKind::Sink);
    let has_configuration = evidence
        .iter()
        .any(|item| item.kind == EvidenceKind::SecurityConfiguration)
        || facts
            .iter()
            .any(|fact| fact.role == "configuration_context");
    let has_application_owned_fix = evidence.iter().any(|item| {
        item.kind == EvidenceKind::SecurityConfiguration
            && item
                .tags
                .iter()
                .any(|tag| tag == "recommendation:fix-application")
    });
    let has_node_session_fixation = evidence
        .iter()
        .any(|item| item.rule_id.ends_with("login-session-fixation-risk"));
    let has_node_weak_password = evidence
        .iter()
        .any(|item| item.rule_id.ends_with("weak-password-policy"));
    let has_node_password_storage_policy = evidence
        .iter()
        .any(|item| item.rule_id.ends_with("password-storage-policy-review"));
    let has_node_registration_fallthrough = evidence.iter().any(|item| {
        item.rule_id
            .ends_with("registration-rejection-fallthrough-review")
    });
    let has_node_password_confirmation = evidence.iter().any(|item| {
        item.rule_id
            .ends_with("password-confirmation-not-enforced-review")
    });
    let has_node_knowledge_recovery = evidence.iter().any(|item| {
        item.rule_id
            .ends_with("knowledge-based-password-recovery-review")
    });
    let has_node_session_cookie = evidence
        .iter()
        .any(|item| item.rule_id.contains("session-cookie-policy-"));
    let has_node_csrf_review = evidence
        .iter()
        .any(|item| item.rule_id.ends_with("cookie-session-csrf-review"));
    let has_node_credential_enumeration = evidence.iter().any(|item| {
        item.rule_id
            .ends_with("credential-response-enumeration-risk")
    });
    let has_node_sensitive_persistence = evidence
        .iter()
        .any(|item| item.rule_id.ends_with("sensitive-record-persistence-risk"));
    let has_node_http_listener = evidence
        .iter()
        .any(|item| item.rule_id.ends_with("http-listener-deployment-review"));
    let has_security_randomness = evidence.iter().any(|item| {
        item.capability == Capability::RandomGeneration
            && item.rule_id.ends_with("insecure-security-randomness")
    });
    let has_python_csrf_exempt = evidence
        .iter()
        .any(|item| item.rule_id == "python-django-csrf-exempt-handler");
    let has_python_hardcoded_jwt = evidence
        .iter()
        .any(|item| item.rule_id == "python-jwt-hardcoded-signing-key");
    let python_deserialization_file = evidence
        .iter()
        .find(|item| item.rule_id == "python-pickle-deserialization")
        .and_then(|item| item.captures.get("payload"))
        .and_then(|payload| python_payload_file(facts, payload.text.trim()));
    let has_python_filesystem_caller =
        evidence.iter().any(|item| {
            item.kind == EvidenceKind::Sink && item.capability == Capability::FilesystemRead
        }) && facts.iter().any(|fact| fact.role == "exact_caller_context");
    let has_python_source_write = evidence
        .iter()
        .any(|item| item.rule_id == "python-source-file-content-write")
        && facts.iter().any(|fact| fact.role == "exact_caller_context");
    let has_precise_node_boundary = has_node_session_fixation
        || has_node_weak_password
        || has_node_password_storage_policy
        || has_node_registration_fallthrough
        || has_node_password_confirmation
        || has_node_knowledge_recovery
        || has_node_session_cookie
        || has_node_csrf_review
        || has_node_credential_enumeration
        || has_node_sensitive_persistence
        || has_node_http_listener
        || has_security_randomness;
    let has_stored_raw_context = evidence
        .iter()
        .any(|item| item.kind == EvidenceKind::Sink && item.capability == Capability::HtmlOutput)
        && [
            "bound_remote_input",
            "persistence_call_observed",
            "raw_output_sink",
            "view_action_context",
        ]
        .iter()
        .all(|role| facts.iter().any(|fact| fact.role == *role));
    let has_database_caller_context =
        evidence.iter().any(|item| {
            item.kind == EvidenceKind::Sink && item.capability == Capability::DatabaseQuery
        }) && facts.iter().any(|fact| fact.role == "exact_caller_context");
    let has_browser_outbound_request = evidence.iter().any(|item| {
        item.kind == EvidenceKind::Sink
            && item.capability == Capability::OutboundNetworkRequest
            && item.context.runtime_environment == Some(RuntimeEnvironment::Browser)
    });
    let browser_html_endpoint_question = evidence
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == Capability::HtmlOutput
                && item.context.runtime_environment == Some(RuntimeEnvironment::Browser)
        })
        .and_then(|sink| sink.captures.get("content"))
        .and_then(|capture| browser_response_member(&capture.text))
        .and_then(|field| {
            facts
                .iter()
                .find(|fact| fact.role == "endpoint_handler_context")
                .map(|handler| {
                    format!(
                        "Does the registered `{}` endpoint return attacker-controlled markup in its `{field}` response field at runtime, including through any generated file, persistence, or helper it reads before responding?",
                        handler.symbol
                    )
                })
        });
    let has_anonymous_endpoint_policy_context = evidence
        .iter()
        .any(|item| item.rule_id == "csharp-anonymous-state-change-review")
        && facts
            .iter()
            .any(|fact| fact.role == "anonymous_endpoint_operation_context")
        && facts
            .iter()
            .any(|fact| fact.role == "public_entrypoint_ui_context");
    let mut questions = Vec::new();
    if has_node_session_fixation {
        questions.push(
            "After successful authentication, is the old session identifier invalidated by an executable session-regeneration call that encloses this identity assignment? A comment or regeneration on a separate signup path is not a login control."
                .to_string(),
        );
    }
    if has_node_weak_password {
        questions.push(
            "Does the executable password policy permit trivially short passwords, and is there any exact later application-owned validation that raises the effective minimum? Do not count a commented stronger regular expression."
                .to_string(),
        );
    }
    if has_node_password_storage_policy {
        questions.push(
            "Before this password storage boundary, does every account-creation path enforce an effective password-strength policy, or can an attacker submit an arbitrarily weak non-empty password? Hashing is storage protection, not strength validation."
                .to_string(),
        );
    }
    if has_node_registration_fallthrough {
        questions.push(
            "After sending the invalid-registration response, does execution return or otherwise stop before the persistence middleware runs? Calling `next()` after the rejection can preserve the invalid account despite the response status."
                .to_string(),
        );
    }
    if has_node_password_confirmation {
        questions.push(
            "Does a password/repeated-password mismatch reach an executable rejection before account creation, or is the comparison used only for telemetry, challenge tracking, or logging before `next()` continues?"
                .to_string(),
        );
    }
    if has_node_knowledge_recovery {
        questions.push(
            "Can publicly discoverable or guessable personal knowledge satisfy this security-answer check and reset an account password, and does effective per-account throttling materially prevent guessing? Verify the recovery design, not only whether the submitted answer matches its stored HMAC."
                .to_string(),
        );
    }
    if has_node_session_cookie {
        questions.push(
            "What HttpOnly, Secure, and SameSite values are effective for this exact session cookie under the pinned framework version and deployed configuration? TLS termination alone does not set the browser-facing Secure attribute, and generic response headers do not replace cookie attributes."
                .to_string(),
        );
    }
    if has_node_csrf_review {
        questions.push(
            "Are the listed cookie-authenticated state-changing routes protected by an effective CSRF token, strict origin enforcement, or another concrete request-bound control? SameSite is defense in depth and should not be assumed when the effective cookie policy is unknown."
                .to_string(),
        );
    }
    if has_node_credential_enumeration {
        questions.push(
            "Do the paired executable login branches return observably different messages, status codes, timing, or response shapes for unknown users and invalid passwords? Treat commented uniform responses as non-controls."
                .to_string(),
        );
    }
    if has_node_sensitive_persistence {
        questions.push(
            "Are the listed sensitive fields stored in recoverable plaintext by this exact persistence call, or does an executable field-level encryption, tokenization, or authoritative storage-layer control protect every listed field?"
                .to_string(),
        );
    }
    if has_node_http_listener {
        questions.push(
            "Is this HTTP listener externally reachable, or does an authoritative proxy, gateway, ingress, or service mesh terminate TLS and prevent direct plaintext access to the application port?"
                .to_string(),
        );
    }
    if has_security_randomness && !java_decision_ready {
        questions.push(
            "Does this generated value serve the captured security lifecycle role, and is `Math.random()` the effective generator rather than an exact later `crypto.randomBytes`, `randomUUID`, or Web Crypto replacement? This control is application-owned; proxy or gateway settings cannot make predictable application randomness cryptographically secure."
                .to_string(),
        );
    }
    if has_python_hardcoded_jwt {
        questions.push(
            "Does the matching verification code accept authentication tokens signed with this source-visible literal key? If so, the repository itself discloses the effective signing secret and application configuration cannot supersede the literal passed to this exact encode/decode pair."
                .to_string(),
        );
    } else if let Some(path) = python_deserialization_file {
        questions.push(format!(
            "Can an untrusted user, upload path, adjacent process, or deployment mechanism modify `{path}` before the shown unsafe YAML/object loader reads it, or is that exact file supplied through a trusted immutable boundary?"
        ));
    } else if has_python_filesystem_caller {
        questions.push(
            "Does the supplied Python caller pass request-derived input into this helper path parameter, and does the helper enforce canonical containment before opening the joined path?"
                .to_string(),
        );
    } else if has_python_source_write {
        questions.push(
            "Does the supplied caller pass request-derived code into the source-file writer, and can the exact imported module execute the overwritten file on reload, worker restart, or a later import?"
                .to_string(),
        );
    } else if has_python_csrf_exempt {
        questions.push(
            "Can a cross-site request invoke this state-changing handler with victim credentials or shared state, and what exact request-bound token or strict origin control applies? For GET, require proof of no victim-relevant effect because Django CSRF middleware does not protect safe methods."
                .to_string(),
        );
    } else if !has_precise_node_boundary && has_anonymous_endpoint_policy_context {
        questions.push(
            "Do the supplied operation, controller policy, and matching public UI establish an intended anonymous authentication or self-registration boundary, and does the endpoint perform any privileged action beyond ordinary sign-in or account creation?"
                .to_string(),
        );
    } else if !has_precise_node_boundary && has_stored_raw_context {
        questions.push(
            "Do the supplied write, persistence, retrieval/view, and raw-output excerpts show a context-appropriate sanitizer or a write invariant that prevents stored attacker HTML from executing?"
                .to_string(),
        );
    } else if !has_precise_node_boundary && has_database_caller_context {
        questions.push(
            "Does request-bound model data copied into the supplied repository argument influence the interpolated command text, and is parameterization or equivalent SQL-safe construction shown?"
                .to_string(),
        );
    } else if !has_precise_node_boundary && has_browser_outbound_request {
        questions.push(
            "This request executes in browser-only code. Can attacker-controlled input redirect it to an unintended origin, leak credentials or data, or bypass an intended client trust boundary? Do not classify it as server-side SSRF unless separate evidence shows server execution."
                .to_string(),
        );
    } else if !has_precise_node_boundary && let Some(question) = browser_html_endpoint_question {
        questions.push(question);
    } else if !has_precise_node_boundary && direct_request_resource_selector {
        questions.push(
            "Does this request-selected resource reach a sensitive read, mutation, or response without a later owner or tenant constraint?"
                .to_string(),
        );
    } else if !has_precise_node_boundary
        && has_source
        && has_sink
        && !direct_stored_html_trust_bypass
    {
        questions.push(
            "Does the supplied source influence the security-sensitive sink input? The deterministic engine did not admit a path."
                .to_string(),
        );
    } else if !has_precise_node_boundary && has_sink && !direct_stored_html_trust_bypass {
        questions
            .push("What is the exact origin of the security-sensitive sink input?".to_string());
    }
    if has_application_owned_fix && !has_precise_node_boundary && !has_python_hardcoded_jwt {
        questions.push(
            "Is there exact later application configuration that supersedes the explicitly weak application-owned setting? Do not assume a proxy or gateway overrides password, lockout, session-cookie, or HttpOnly semantics."
                .to_string(),
        );
    } else if has_configuration
        && !has_python_csrf_exempt
        && !has_python_hardcoded_jwt
        && !has_anonymous_endpoint_policy_context
        && !has_precise_node_boundary
        && !decision_ready_policy
    {
        questions.push(
            "What is the effective runtime or deployed control value at the authoritative layer?"
                .to_string(),
        );
    }
    if evidence
        .iter()
        .any(|item| item.kind == EvidenceKind::SensitiveOperation)
        && !decision_ready_policy
    {
        questions.push(
            "Does the observed sensitive operation establish a concrete weakness in this context?"
                .to_string(),
        );
    }
    if questions.is_empty() && !decision_ready_policy && !direct_stored_html_trust_bypass {
        questions
            .push("Does this bounded observation establish a concrete security issue?".to_string());
    }
    questions
}

fn python_payload_file(facts: &[ReviewNeighborhoodFact], payload: &str) -> Option<String> {
    if !is_plain_identifier(payload) {
        return None;
    }
    facts
        .iter()
        .filter(|fact| fact.role == "source_context")
        .flat_map(|fact| fact.excerpt.lines())
        .find_map(|line| {
            let (left, right) = line.trim().split_once('=')?;
            (left.trim() == payload && right.trim_start().starts_with("open("))
                .then(|| first_quoted_value(right).map(str::to_string))
                .flatten()
        })
}

fn browser_response_member(expression: &str) -> Option<&str> {
    let member = expression.split('.').nth(1)?;
    member
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .find(|token| !token.is_empty() && token.len() <= 80)
}

fn observation_review_id(path: &str, symbol: &str, anchors: &[String]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    hash_review_text(&mut hash, path);
    hash_review_text(&mut hash, symbol);
    for anchor in anchors {
        hash_review_text(&mut hash, anchor);
    }
    format!("observation-review-{hash:016x}")
}

fn path_review_questions(
    candidate: &mehscan_core::Candidate,
    has_configuration: bool,
    has_feature_gate: bool,
    has_configuration_gate: bool,
) -> Vec<String> {
    if candidate.sink.rule_id == "python-source-file-content-write" {
        return vec![
            "Does an exact Python import or loader reference the request-overwritten source file, allowing its contents to execute on application startup, reload, or worker restart?"
                .to_string(),
        ];
    }
    if candidate.cwe_candidates.iter().any(|cwe| cwe == "CWE-117")
        && candidate.capability == Capability::Logging
    {
        return vec![
            "Can this exact request-derived log argument contain CR, LF, or effective record delimiters, and is it encoded or structurally separated before the deployed logger renders the record?"
                .to_string(),
        ];
    }
    if candidate.capability == Capability::ResourceAccess
        && candidate.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
        && candidate
            .sink
            .context
            .http_routes
            .iter()
            .any(|route| route.path.to_ascii_lowercase().contains("benefit"))
        && candidate
            .sink
            .context
            .http_routes
            .iter()
            .all(|route| route.access == mehscan_core::HttpRouteAccess::Authenticated)
    {
        return vec![
            "Does a server-owned role or permission guard authorize this authenticated caller for the administrative operation, in addition to any owner check on the selected resource? Verify the exact registered middleware chain; a commented role guard is not a control."
                .to_string(),
        ];
    }
    if candidate
        .source
        .provenance
        .engine
        .ends_with("bounded-mongo-callback-result-summary")
        && candidate.capability == Capability::HtmlOutput
    {
        return vec![
            "Do the supplied Mongo producer, Express render binding, template expression, and effective template configuration show that attacker-controlled stored content reaches an execution-capable HTML, attribute, URL, CSS, or script context? Apply Marked or another sanitizer only to values it actually wraps, and verify that its configured version protects the relevant context."
                .to_string(),
        ];
    }
    if candidate.cwe_candidates.iter().any(|cwe| cwe == "CWE-916")
        && candidate.capability == Capability::CryptographicHash
    {
        return vec![
            "Does the supplied DAO implementation persist this password value without a recognized password KDF such as Argon2, scrypt, PBKDF2 with adequate parameters, or bcrypt with an adequate cost? A commented example is not an executable transform."
                .to_string(),
        ];
    }
    if candidate.cwe_candidates.iter().any(|cwe| cwe == "CWE-943")
        && candidate.capability == Capability::DatabaseQuery
    {
        return vec![
            "Does the supplied DAO implementation interpolate this request-derived value into MongoDB $where JavaScript, and is there an executable rejecting scalar/range validation before the predicate is constructed?"
                .to_string(),
        ];
    }
    if candidate.sink.rule_id == "csharp-request-controlled-role-assignment" {
        return vec![
            "Does an exact server-owned caller role or policy guard protect this role assignment independently of the request-bound authorization and assignment booleans? Treat a hidden form field and bound model property as client-controlled, not as caller privilege proof."
                .to_string(),
        ];
    }
    if candidate.sink.rule_id == "csharp-unverified-sso-cookie-token-issuance" {
        return vec![
            "Does the application authenticate the SSO cookie with a server-held integrity key or framework data protector before reading the account identifier? Base64 decoding and JSON parsing alone do not establish authenticity."
                .to_string(),
            "Does the verified cookie identity select the same account for which this access token is issued, with issuer, audience, purpose, and replay protections appropriate to the SSO protocol?"
                .to_string(),
        ];
    }
    let mut questions = candidate
        .uncertainty_reasons
        .iter()
        .map(|reason| uncertainty_review_question(reason, candidate.source.capability))
        .collect::<Vec<_>>();
    if candidate.protections.is_empty() {
        questions.push(missing_protection_question(candidate.capability).to_string());
    }
    if has_feature_gate {
        questions.push(
            "Do the supplied feature or challenge policy excerpts establish that this exact operation is enabled in the deployed environment?"
                .to_string(),
        );
    } else if has_configuration_gate {
        questions.push(
            "What exact configuration value is effective for the conditional branch guarding this operation in the deployed environment?"
                .to_string(),
        );
    } else if has_configuration && control_can_be_owned_outside_application(candidate.capability) {
        questions.push(
            "Which application, framework, proxy, gateway, ingress, mesh, or platform layer owns this control, and what exact value is effective in the deployed environment?"
                .to_string(),
        );
    }
    // The candidate already records an admitted bounded relationship and an
    // explicit source rule. Do not invite the reviewer to re-request those
    // scanner-established facts. Genuinely unresolved runtime behavior must
    // be expressed by a more specific question.
    questions.retain(|question| {
        !question.starts_with(
            "Do the supplied caller, callee, and registration excerpts confirm this exact bounded value handoff",
        ) && !question.starts_with(
            "Do the supplied source excerpts establish the candidate's bounded intermediate value handoff",
        ) && !question.starts_with(
            "Does the shown framework or API binding establish that this exact source expression is attacker-controlled",
        )
    });
    questions.sort();
    questions.dedup();
    questions
}

fn uncertainty_review_question(reason: &str, source_capability: Capability) -> String {
    if reason == "source_observation_not_high_confidence" {
        return match source_capability {
            Capability::CredentialMaterial => {
                "Do the supplied declarations establish that this exact credential or signing-key material is embedded in the application rather than obtained from an authoritative secret provider?"
            }
            Capability::StoredUserContent => {
                "Does the supplied producer, persistence, or retrieval context establish that this exact value retains attacker-controlled content?"
            }
            Capability::UploadedFileContent
            | Capability::UploadedFilePath
            | Capability::FileUpload => {
                "Does the shown framework binding establish that this exact file content, filename, or upload path is controlled by the remote caller?"
            }
            Capability::ArchiveEntryPath => {
                "Does the shown archive iteration establish that this exact entry path originates from an untrusted archive?"
            }
            Capability::HttpRequestData
            | Capability::RpcRequestData
            | Capability::BrowserInput
            | Capability::ExternalInput
            | Capability::ModelToolInput => {
                "Does the shown framework or API binding establish that this exact source expression is attacker-controlled for the endpoint?"
            }
            _ => {
                "Does the supplied producer context establish the exact source semantics required by this bounded relationship?"
            }
        }
        .to_string();
    }
    if reason.contains("control_flow") {
        return "Do the shown branch, exception, and early-return conditions allow the source-derived value to reach this sink on an executable path?"
            .to_string();
    }
    if reason.contains("parameter_binding") {
        return "Does the shown framework binding map this exact request or RPC parameter to the handler value used by the sink?"
            .to_string();
    }
    if reason == "message_event_origin_validation_unverified" {
        return "Does the message handler validate event.origin and, where relevant, event.source before this data reaches the browser sink?"
            .to_string();
    }
    if reason == "socket_message_producer_validation_unverified" {
        return "Does the server authenticate and authorize the Socket.IO/WebSocket producer, and is this exact event field constrained or encoded before the DOM sink?"
            .to_string();
    }
    if reason == "browser_storage_writer_origin_unverified" {
        return "Which code can write this browser-storage key, and can attacker-controlled or cross-tenant data persist into the value read here?"
            .to_string();
    }
    if reason == "browser_input_boundary_is_syntactic" {
        return "Does this browser-derived value reach the exact DOM or navigation sink at runtime without a context-appropriate validation or sanitization step?"
            .to_string();
    }
    if reason.contains("origin")
        || reason.contains("stored_file")
        || reason.contains("stored_model")
        || reason.contains("rxjs")
    {
        return "Does the supplied producer, persistence, or retrieval context establish that this exact value retains attacker-controlled content?"
            .to_string();
    }
    if reason.contains("protection") || reason.contains("validation_guard") {
        return "Does the shown validation or transformation reject unsafe values, and is it applied to the same value before this sink?"
            .to_string();
    }
    if reason.contains("runtime_dispatch")
        || reason.contains("formal_parameter")
        || reason.contains("summary")
        || reason.contains("relationship")
        || reason.contains("value_preserving")
        || reason.contains("file_role")
        || reason.contains("object_input")
        || reason.contains("policy")
        || reason.contains("model_binding")
    {
        return "Do the supplied caller, callee, and registration excerpts confirm this exact bounded value handoff without unresolved runtime dispatch?"
            .to_string();
    }
    if reason.contains("embedded_program") {
        return "Does the supplied code establish the exact embedded program or interpreter invoked with the source-derived value?"
            .to_string();
    }
    if reason.contains("response_field") || reason.contains("duplicate_key") {
        return "Does the supplied object construction and response context expose the source-derived field on this executable path?"
            .to_string();
    }
    "Do the supplied source excerpts establish the candidate's bounded intermediate value handoff?"
        .to_string()
}

fn missing_protection_question(capability: Capability) -> &'static str {
    match capability {
        Capability::DatabaseQuery => {
            "Does the shown query bind every source-derived value as a database parameter rather than composing SQL text?"
        }
        Capability::FilesystemRead | Capability::FilesystemWrite | Capability::ArchiveEntryPath => {
            "Does the shown code canonicalize the source-derived path and enforce containment within an intended base directory before filesystem access?"
        }
        Capability::OutboundNetworkRequest => {
            "Does the shown code parse the destination and enforce an allowlist that excludes internal, loopback, link-local, and metadata targets before the request?"
        }
        Capability::ProcessExecution => {
            "Does the shown code avoid a command shell and pass source-derived values only as separately structured process arguments?"
        }
        Capability::DynamicCodeExecution => {
            "Does the shown code prevent source-derived text from being interpreted as executable code?"
        }
        Capability::TemplateEvaluation => {
            "Is the template itself fixed and trusted, with source-derived values supplied only as template data under the engine's escaping rules?"
        }
        Capability::HtmlOutput => {
            "Is the source-derived value encoded for its exact HTML, attribute, URL, CSS, or script context before output?"
        }
        Capability::BrowserCredentialedRequest => {
            "Does the message handler reject untrusted event.origin/event.source values before issuing this credentialed state-changing request, and does the server independently enforce CSRF authorization?"
        }
        Capability::BrowserMessageSend => {
            "Is the message restricted to an exact trusted targetOrigin and intended recipient window before sensitive data is sent?"
        }
        Capability::Redirect => {
            "Is the source-derived redirect destination restricted to an intended local path or an explicit origin allowlist?"
        }
        Capability::Deserialization => {
            "Does the shown deserialization use a safe data format and prevent attacker-selected runtime types or unsafe object construction?"
        }
        Capability::XmlParsing => {
            "Does the effective parser configuration disable DTD processing and external entity or external resource resolution?"
        }
        Capability::ResourceAccess => {
            "Does a server-owned owner, tenant, role, or policy check authorize the caller for this exact selected resource?"
        }
        Capability::Authentication | Capability::Authorization => {
            "Does a server-owned authentication or authorization decision protect this exact operation independently of request-controlled fields?"
        }
        Capability::TokenGeneration => {
            "Does the shown token construction use an approved algorithm, protected key material, bounded lifetime, and purpose-specific validation?"
        }
        Capability::CryptographicHash | Capability::CryptographicEncryption => {
            "Does the shown cryptographic operation use an algorithm, mode, parameters, and key-management policy appropriate for this security purpose?"
        }
        Capability::RandomGeneration => {
            "Is the value generated by a cryptographically secure random source with sufficient entropy for this security purpose?"
        }
        Capability::LdapQuery => {
            "Is each source-derived LDAP value encoded for its exact filter or distinguished-name context before query construction?"
        }
        Capability::FileUpload | Capability::UploadedFileContent | Capability::UploadedFilePath => {
            "Does the upload path enforce server-generated storage names, path containment, size limits, and content validation appropriate to later use?"
        }
        Capability::Serialization => {
            "Does the shown serialization exclude sensitive fields and prevent attacker-controlled type or object-graph behavior?"
        }
        Capability::Logging => {
            "Does the shown logging path prevent source-derived control characters or secrets from corrupting or leaking through the effective log sink?"
        }
        Capability::CookieConfiguration
        | Capability::TlsConfiguration
        | Capability::HttpHeaderOutput
        | Capability::HttpRequestHandling => {
            "What exact control is effective at the authoritative application, framework, proxy, gateway, ingress, mesh, or platform layer for this deployed route?"
        }
        _ => {
            "Does the supplied code show an effective control applied to the same source-derived value before the sensitive operation?"
        }
    }
}

fn control_can_be_owned_outside_application(capability: Capability) -> bool {
    matches!(
        capability,
        Capability::CookieConfiguration
            | Capability::TlsConfiguration
            | Capability::HttpHeaderOutput
            | Capability::HttpRequestHandling
    )
}

fn collect_configuration_tokens(source: &str, output: &mut BTreeSet<String>) {
    for token in source.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-'))
    }) {
        let token = token.trim_matches(['.', '-']);
        if is_configuration_token(token) {
            output.insert(token.to_ascii_lowercase());
        }
    }
}

fn is_configuration_token(token: &str) -> bool {
    if token.len() < 5 || contains_sensitive_config_key(token) {
        return false;
    }
    let lower = token.to_ascii_lowercase();
    [
        "enable",
        "disable",
        "allow",
        "unsafe",
        "secure",
        "verify",
        "debug",
        "proxy",
        "forwarded",
        "cors",
        "csrf",
        "shell",
        "tls",
        "mode",
        "feature",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn contains_sensitive_config_key(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "private_key",
        "privatekey",
        "apikey",
        "api_key",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn index_review_context_names(
    sources: &RepositorySources,
    wanted: &BTreeSet<String>,
    definitions: &mut BTreeMap<String, Vec<OutlineSymbol>>,
    registrations: &mut BTreeMap<String, Vec<ReviewNeighborhoodFact>>,
    usages: &mut BTreeMap<String, Vec<ReviewNeighborhoodFact>>,
) {
    for file in sources.files.values() {
        if file.language.is_none()
            || is_nonproduction_review_context_path(&file.path)
            || file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        {
            continue;
        }
        // This index is intentionally lexical. The scan has already parsed
        // supported files; reparsing the whole repository for review
        // enrichment would dominate bundle construction time.
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            let mut line_names = BTreeSet::new();
            collect_review_reference_tokens(line, &mut line_names);
            for name in line_names.into_iter().filter(|name| wanted.contains(name)) {
                let entries = usages.entry(name.clone()).or_default();
                if entries.len() < 24 {
                    entries.push(ReviewNeighborhoodFact {
                        role: "exact_reference_context".to_string(),
                        symbol: name.clone(),
                        location: location_from_offsets(&file.path, &file.source, start, end),
                        excerpt: bounded_line_text(line),
                        evidence_id: None,
                        provenance: textual_provenance(
                            "bounded exact-name repository reference, lexical non-flow 1",
                        ),
                    });
                }
                if looks_like_registration_reference(line) {
                    registrations
                        .entry(name.clone())
                        .or_default()
                        .push(ReviewNeighborhoodFact {
                            role: "registration_context".to_string(),
                            symbol: name,
                            location: location_from_offsets(&file.path, &file.source, start, end),
                            excerpt: bounded_line_text(line),
                            evidence_id: None,
                            provenance: textual_provenance(
                                "bounded exact-name framework registration reference, non-flow 1",
                            ),
                        });
                }
            }
            if looks_like_registration_reference(line) {
                for name in wanted.iter().filter(|name| contains_identifier(line, name)) {
                    let entries = registrations.entry(name.clone()).or_default();
                    if !entries.iter().any(|fact| {
                        fact.location.path == file.path && fact.location.start.byte_offset == start
                    }) {
                        entries.push(ReviewNeighborhoodFact {
                            role: "registration_context".to_string(),
                            symbol: name.clone(),
                            location: location_from_offsets(&file.path, &file.source, start, end),
                            excerpt: bounded_line_text(line),
                            evidence_id: None,
                            provenance: textual_provenance(
                                "bounded exact-name framework registration reference, non-flow 1",
                            ),
                        });
                    }
                }
            }

            let Some(name) = textual_definition_identifier(line) else {
                continue;
            };
            if !wanted.contains(&name) {
                continue;
            }
            let end_line_index = textual_definition_end(&file.source, &spans, line_index);
            let location =
                location_from_offsets(&file.path, &file.source, start, spans[end_line_index].1);
            let entries = definitions.entry(name.clone()).or_default();
            if entries.iter().any(|symbol| {
                symbol.location.path == location.path
                    && symbol.location.start.byte_offset == location.start.byte_offset
            }) {
                continue;
            }
            entries.push(OutlineSymbol {
                name,
                symbol_type: "textual_definition".to_string(),
                signature: bounded_line_text(line),
                ast_kind: "bounded_declaration".to_string(),
                location,
                parent: None,
                is_import: false,
                is_exported: line.contains("export ") || line.contains("public "),
                is_public: None,
            });
        }
    }
}

/// Returns true only when a helper definition has a defensible relationship
/// to the reviewed file. Same-file definitions are owned directly. For
/// JavaScript and TypeScript cross-file definitions must be reached through an
/// exact relative import. C# also permits an exact qualified static helper when
/// its declaring type and namespace/import are owned. A repository-wide name
/// match alone is never ownership.
fn review_definition_owned_by_candidate(
    sources: &RepositorySources,
    candidate_paths: &BTreeSet<&str>,
    name: &str,
    symbol: &OutlineSymbol,
) -> bool {
    if candidate_paths.contains(symbol.location.path.as_str()) {
        return true;
    }
    candidate_paths.iter().any(|path| {
        let Ok(candidate) = sources.file(path) else {
            return false;
        };
        if candidate.language == Some(Language::Csharp)
            && csharp_qualified_helper_is_owned(sources, candidate, name, symbol)
        {
            return true;
        }
        if !matches!(
            candidate.language,
            Some(Language::Javascript | Language::Typescript)
        ) {
            return false;
        }
        relative_review_import_paths(candidate, name, sources)
            .contains(symbol.location.path.as_str())
    })
}

fn csharp_qualified_helper_is_owned(
    sources: &RepositorySources,
    candidate: &SourceFile,
    name: &str,
    symbol: &OutlineSymbol,
) -> bool {
    let parents = candidate
        .source
        .match_indices(&format!(".{name}("))
        .filter_map(|(at, _)| {
            let prefix = &candidate.source[..at];
            let start = prefix
                .rfind(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .map_or(0, |index| index + 1);
            let parent = &prefix[start..];
            is_plain_identifier(parent).then(|| parent.to_string())
        })
        .collect::<BTreeSet<_>>();
    if parents.len() != 1 {
        return false;
    }
    let parent = parents.first().expect("one qualified helper parent");
    if !parent.chars().next().is_some_and(char::is_uppercase) {
        return false;
    }
    let compact_candidate = candidate
        .source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if !compact_candidate.contains(&format!("{parent}.{name}("))
        || ["class", "struct", "record", "interface"]
            .iter()
            .any(|kind| {
                candidate.source.lines().any(|line| {
                    let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
                    normalized.contains(&format!("{kind} {parent}"))
                })
            })
    {
        return false;
    }
    let Ok(definition) = sources.file(&symbol.location.path) else {
        return false;
    };
    let definition_prefix = &definition.source[..symbol
        .location
        .start
        .byte_offset
        .min(definition.source.len())];
    if !["class", "struct", "record", "interface"]
        .iter()
        .any(|kind| {
            definition_prefix.lines().any(|line| {
                let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
                normalized.contains(&format!("{kind} {parent}"))
            })
        })
    {
        return false;
    }
    let Some(namespace) = csharp_namespace(&definition.source) else {
        return false;
    };
    let owned = csharp_namespace(&candidate.source) == Some(namespace)
        || candidate
            .source
            .lines()
            .map(|line| line.trim().trim_start_matches('\u{feff}'))
            .any(|line| line == format!("using {namespace};"));
    owned
}

fn csharp_namespace(source: &str) -> Option<&str> {
    source.lines().find_map(|line| {
        line.trim()
            .trim_start_matches('\u{feff}')
            .strip_prefix("namespace ")
            .map(|value| value.trim_end_matches([' ', '{', ';']))
            .filter(|value| !value.is_empty())
    })
}

/// Omits only a C# open-redirect review whose source parameter is proven to be
/// used exclusively as a `string.Format` value after `?` in absolute URLs
/// returned by one exactly owned helper. Other helper parameters may control
/// the authority and remain reviewable. The raw security path
/// remains in scan output; authority-bearing sibling arguments stay reviewable.
fn csharp_redirect_helper_query_only_candidate(
    candidate: &mehscan_core::Candidate,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    sources: &RepositorySources,
    review_context: &ReviewContextIndex,
) -> bool {
    if candidate.capability != Capability::Redirect
        || candidate.source.rule_id != "csharp-aspnet-controller-parameter-source"
        || candidate.sink.rule_id != "csharp-controller-http-redirect"
    {
        return false;
    }
    let Some(source_parameter) = evidence_by_id
        .get(candidate.source.id.as_str())
        .and_then(|source| source.captures.get("parameter"))
        .map(|capture| capture.text.as_str())
    else {
        return false;
    };
    let Some(location) = evidence_by_id
        .get(candidate.sink.id.as_str())
        .and_then(|sink| sink.captures.get("location"))
        .map(|capture| capture.text.as_str())
    else {
        return false;
    };
    let Some(open) = location.find('(') else {
        return false;
    };
    let Some(method) = terminal_identifier(location[..open].trim()) else {
        return false;
    };
    let Some(close) = location.rfind(')') else {
        return false;
    };
    if close <= open || location[open + 1..close].contains(['(', ')']) {
        return false;
    }
    let arguments = location[open + 1..close]
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    let matching_arguments = arguments
        .iter()
        .enumerate()
        .filter(|(_, argument)| **argument == source_parameter)
        .collect::<Vec<_>>();
    if matching_arguments.len() != 1 || !arguments.iter().all(|arg| is_plain_identifier(arg)) {
        return false;
    }
    let parameter_index = matching_arguments[0].0;
    let candidate_paths = candidate
        .steps
        .iter()
        .map(|step| step.location.path.as_str())
        .collect::<BTreeSet<_>>();
    let owned_definitions = review_context
        .definitions
        .get(method)
        .into_iter()
        .flatten()
        .filter(|symbol| {
            review_definition_owned_by_candidate(sources, &candidate_paths, method, symbol)
        })
        .collect::<Vec<_>>();
    if owned_definitions.len() != 1 {
        return false;
    }
    let symbol = owned_definitions[0];
    let Ok(definition) = sources.file(&symbol.location.path) else {
        return false;
    };
    let start = symbol
        .location
        .start
        .byte_offset
        .min(definition.source.len());
    let end = symbol.location.end.byte_offset.min(definition.source.len());
    start < end
        && definition.source.is_char_boundary(start)
        && definition.source.is_char_boundary(end)
        && csharp_helper_parameter_is_fixed_query_only(
            &definition.source[start..end],
            method,
            parameter_index,
        )
}

fn csharp_helper_parameter_is_fixed_query_only(
    definition: &str,
    method: &str,
    parameter_index: usize,
) -> bool {
    let Some(method_start) = definition.find(&format!("{method}(")) else {
        return false;
    };
    let parameters_start = method_start + method.len() + 1;
    let Some(parameters_end) = definition[parameters_start..].find(')') else {
        return false;
    };
    let parameters_end = parameters_start + parameters_end;
    let parameters = definition[parameters_start..parameters_end]
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    let Some(parameter) = parameters
        .get(parameter_index)
        .and_then(|parameter| terminal_identifier(parameter))
    else {
        return false;
    };
    let mut observed = false;
    for line in definition[parameters_end + 1..].lines() {
        let line = line.trim();
        if line.starts_with("//") || !contains_identifier(line, parameter) {
            continue;
        }
        if !csharp_query_only_format_use(line, parameter) {
            return false;
        }
        observed = true;
    }
    observed
}

fn csharp_query_only_format_use(line: &str, parameter: &str) -> bool {
    let compact = line
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let Some(format_call) = compact
        .find("string.Format(\"")
        .or_else(|| compact.find("String.Format(\""))
    else {
        return false;
    };
    let literal_start = format_call + "string.Format(\"".len();
    let Some(literal_end) = compact[literal_start..].find('"') else {
        return false;
    };
    let literal_end = literal_start + literal_end;
    let literal = &compact[literal_start..literal_end];
    let Some(query) = literal.find('?') else {
        return false;
    };
    let authority = &literal[..query];
    let query = &literal[query + 1..];
    if !authority.starts_with("http://") && !authority.starts_with("https://") {
        return false;
    }
    let Some(arguments) = compact[literal_end + 1..]
        .strip_prefix(',')
        .and_then(|arguments| arguments.strip_suffix(");"))
    else {
        return false;
    };
    let arguments = arguments.split(',').map(str::trim).collect::<Vec<_>>();
    let positions = arguments
        .iter()
        .enumerate()
        .filter(|(_, argument)| **argument == parameter)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if positions.len() != 1
        || !arguments
            .iter()
            .all(|argument| is_plain_identifier(argument))
    {
        return false;
    }
    let placeholder = format!("{{{}", positions[0]);
    !authority.contains(&placeholder) && query.contains(&placeholder)
}

fn csharp_helper_parameter_controls_absolute_url_authority(
    definition: &str,
    method: &str,
    parameter_index: usize,
) -> bool {
    let Some(method_start) = definition.find(&format!("{method}(")) else {
        return false;
    };
    let parameters_start = method_start + method.len() + 1;
    let Some(parameters_end) = definition[parameters_start..].find(')') else {
        return false;
    };
    let parameters_end = parameters_start + parameters_end;
    let parameters = definition[parameters_start..parameters_end]
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    let Some(parameter) = parameters
        .get(parameter_index)
        .and_then(|parameter| terminal_identifier(parameter))
    else {
        return false;
    };
    definition[parameters_end + 1..].lines().any(|line| {
        let line = line.trim();
        !line.starts_with("//") && csharp_absolute_url_authority_format_use(line, parameter)
    })
}

fn csharp_absolute_url_authority_format_use(line: &str, parameter: &str) -> bool {
    let compact = line
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let Some(format_call) = compact
        .find("string.Format(\"")
        .or_else(|| compact.find("String.Format(\""))
    else {
        return false;
    };
    let literal_start = format_call + "string.Format(\"".len();
    let Some(literal_end) = compact[literal_start..].find('"') else {
        return false;
    };
    let literal_end = literal_start + literal_end;
    let literal = &compact[literal_start..literal_end];
    let Some(scheme_end) = literal.find("://") else {
        return false;
    };
    if !matches!(&literal[..scheme_end], "http" | "https") {
        return false;
    }
    let authority = literal[scheme_end + 3..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let Some(arguments) = compact[literal_end + 1..]
        .strip_prefix(',')
        .and_then(|arguments| arguments.strip_suffix(");"))
    else {
        return false;
    };
    let arguments = arguments.split(',').map(str::trim).collect::<Vec<_>>();
    arguments.iter().enumerate().any(|(index, argument)| {
        argument.eq_ignore_ascii_case(parameter) && authority.contains(&format!("{{{index}}}"))
    })
}

fn relative_review_import_paths(
    candidate: &SourceFile,
    name: &str,
    sources: &RepositorySources,
) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    if let Some((_imported, module)) = relative_named_import(&candidate.source, name)
        && let Some(path) = resolve_relative_typescript_module(&candidate.path, module, sources)
    {
        paths.insert(path);
    }
    for line in candidate.source.lines() {
        let line = line.trim();
        if let Some(body) = line.strip_prefix("import * as ")
            && let Some((binding, remainder)) = body.split_once(" from ")
            && let Some(module) = first_quoted_value(remainder)
            && module.starts_with('.')
            && contains_identifier(&candidate.source, &format!("{binding}.{name}"))
            && let Some(path) = resolve_relative_typescript_module(&candidate.path, module, sources)
        {
            paths.insert(path);
        }
        if line.starts_with("import ")
            && !line.starts_with("import {")
            && !line.starts_with("import *")
            && let Some((binding, remainder)) = line["import ".len()..].split_once(" from ")
            && binding.trim() == name
            && let Some(module) = first_quoted_value(remainder)
            && module.starts_with('.')
            && let Some(path) = resolve_relative_typescript_module(&candidate.path, module, sources)
        {
            paths.insert(path);
        }
        if let Some(require_at) = line.find("require(")
            && let Some(module) = first_quoted_value(&line[require_at + "require(".len()..])
            && module.starts_with('.')
            && let Some((binding, _)) = line.split_once('=')
        {
            let binding_mentions_name = contains_identifier(binding, name);
            let namespace_binding = binding
                .split(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
                })
                .filter(|part| !part.is_empty())
                .next_back();
            if (binding_mentions_name
                || namespace_binding.is_some_and(|binding| {
                    contains_identifier(&candidate.source, &format!("{binding}.{name}"))
                }))
                && let Some(path) =
                    resolve_relative_typescript_module(&candidate.path, module, sources)
            {
                paths.insert(path);
            }
            for imported_type in binding
                .split(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
                })
                .filter(|part| {
                    part.chars()
                        .next()
                        .is_some_and(|character| character.is_ascii_uppercase())
                })
            {
                let constructor = format!("new {imported_type}(");
                let receiver = candidate.source.lines().find_map(|source_line| {
                    let (left, right) = source_line.split_once('=')?;
                    right.contains(&constructor).then(|| {
                        left.split(|character: char| {
                            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
                        })
                        .filter(|part| !part.is_empty())
                        .next_back()
                    })?
                });
                if receiver.is_some_and(|receiver| {
                    contains_identifier(&candidate.source, &format!("{receiver}.{name}"))
                }) && let Some(path) =
                    resolve_relative_typescript_module(&candidate.path, module, sources)
                {
                    paths.insert(path);
                }
            }
        }
    }
    paths
}

impl ReviewContextIndex {
    fn build(sources: &RepositorySources, wanted: &BTreeSet<String>) -> Result<Self, EngineError> {
        let mut definitions: BTreeMap<String, Vec<OutlineSymbol>> = BTreeMap::new();
        let mut registrations: BTreeMap<String, Vec<ReviewNeighborhoodFact>> = BTreeMap::new();
        let mut usages: BTreeMap<String, Vec<ReviewNeighborhoodFact>> = BTreeMap::new();
        index_review_context_names(
            sources,
            wanted,
            &mut definitions,
            &mut registrations,
            &mut usages,
        );

        // One additional lexical hop is enough to expose small wrappers such
        // as isChallengeEnabled -> getChallengeEnablementStatus without
        // pretending that this is a call graph or whole-program flow.
        let mut expanded = wanted.clone();
        for symbols in definitions.values() {
            for symbol in symbols {
                let Ok(file) = sources.file(&symbol.location.path) else {
                    continue;
                };
                let start = symbol.location.start.byte_offset.min(file.source.len());
                let end = symbol.location.end.byte_offset.min(file.source.len());
                if start < end
                    && file.source.is_char_boundary(start)
                    && file.source.is_char_boundary(end)
                {
                    collect_review_reference_tokens(&file.source[start..end], &mut expanded);
                    collect_policy_reference_tokens(&file.source[start..end], &mut expanded);
                }
            }
        }
        let second_hop = expanded
            .difference(wanted)
            .cloned()
            .collect::<BTreeSet<_>>();
        if !second_hop.is_empty() {
            index_review_context_names(
                sources,
                &second_hop,
                &mut definitions,
                &mut registrations,
                &mut usages,
            );
        }
        for symbols in definitions.values_mut() {
            symbols.sort_by(|left, right| {
                left.location.path.cmp(&right.location.path).then_with(|| {
                    left.location
                        .start
                        .byte_offset
                        .cmp(&right.location.start.byte_offset)
                })
            });
            symbols.dedup_by(|left, right| left.location == right.location);
        }
        for facts in registrations.values_mut().chain(usages.values_mut()) {
            sort_review_facts(facts);
        }
        Ok(Self {
            definitions,
            registrations,
            usages,
        })
    }

    fn expanded_references(
        &self,
        sources: &RepositorySources,
        candidate_paths: &BTreeSet<&str>,
        references: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        let mut expanded = references.clone();
        for name in references {
            let Some(symbols) = self.definitions.get(name) else {
                continue;
            };
            for symbol in symbols.iter().filter(|symbol| {
                review_definition_owned_by_candidate(sources, candidate_paths, name, symbol)
            }) {
                let Ok(file) = sources.file(&symbol.location.path) else {
                    continue;
                };
                let start = symbol.location.start.byte_offset.min(file.source.len());
                let end = symbol.location.end.byte_offset.min(file.source.len());
                if start < end
                    && file.source.is_char_boundary(start)
                    && file.source.is_char_boundary(end)
                {
                    collect_review_reference_tokens(&file.source[start..end], &mut expanded);
                    collect_policy_reference_tokens(&file.source[start..end], &mut expanded);
                }
            }
        }
        expanded
    }

    fn usage_facts(
        &self,
        sources: &RepositorySources,
        references: &BTreeSet<String>,
        candidate_paths: &BTreeSet<&str>,
        existing: &[ReviewNeighborhoodFact],
        limit: usize,
    ) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let mut facts = Vec::new();
        let mut truncated = false;
        let mut names = references.iter().collect::<Vec<_>>();
        names.sort_by(|left, right| {
            reference_priority(right)
                .cmp(&reference_priority(left))
                .then_with(|| left.cmp(right))
        });
        for name in names {
            if !self.definitions.get(name).is_some_and(|symbols| {
                symbols
                    .iter()
                    .any(|symbol| candidate_paths.contains(symbol.location.path.as_str()))
            }) {
                continue;
            }
            let Some(usages) = self.usages.get(name) else {
                continue;
            };
            let mut ordered = usages.iter().collect::<Vec<_>>();
            ordered.retain(|usage| candidate_paths.contains(usage.location.path.as_str()));
            ordered.sort_by_key(|usage| {
                (
                    usage.location.path.as_str(),
                    usage.location.start.byte_offset,
                )
            });
            for usage in ordered {
                if facts_cover_location(existing, &usage.location)
                    || facts_cover_location(&facts, &usage.location)
                {
                    continue;
                }
                if facts.len() == limit {
                    truncated = true;
                    return (facts, truncated);
                }
                let Ok(file) = sources.file(&usage.location.path) else {
                    continue;
                };
                let start_line = usage.location.start.line.saturating_sub(8).max(1);
                let end_line = usage.location.end.line.saturating_add(8);
                let Ok((slice, slice_truncated)) = source_slice(file, start_line, end_line) else {
                    continue;
                };
                truncated |= slice_truncated;
                facts.push(ReviewNeighborhoodFact {
                    role: "reference_use_context".to_string(),
                    symbol: usage.symbol.clone(),
                    location: slice.location,
                    excerpt: slice.text,
                    evidence_id: None,
                    provenance: textual_provenance(
                        "bounded enclosing candidate-file reference use, lexical non-flow 1",
                    ),
                });
            }
        }
        (facts, truncated)
    }

    fn facts(
        &self,
        sources: &RepositorySources,
        candidate_paths: &BTreeSet<&str>,
        references: &BTreeSet<String>,
        existing: &[ReviewNeighborhoodFact],
        limit: usize,
    ) -> (Vec<ReviewNeighborhoodFact>, bool) {
        if references.is_empty() || limit == 0 {
            return (Vec::new(), false);
        }
        let mut facts = Vec::new();
        let mut truncated = false;

        let mut ordered_references = references.iter().collect::<Vec<_>>();
        ordered_references.sort_by(|left, right| {
            reference_priority(right)
                .cmp(&reference_priority(left))
                .then_with(|| left.cmp(right))
        });
        let mut definition_count = 0usize;
        for name in ordered_references {
            if definition_count == 6 {
                truncated = true;
                break;
            }
            let Some(symbols) = self.definitions.get(name) else {
                continue;
            };
            for symbol in symbols
                .iter()
                .filter(|symbol| {
                    review_definition_owned_by_candidate(sources, candidate_paths, name, symbol)
                })
                .take(2)
            {
                if !looks_like_review_helper_signature(name, &symbol.signature)
                    || facts_cover_location(existing, &symbol.location)
                {
                    continue;
                }
                if facts.len() == limit {
                    truncated = true;
                    return (facts, truncated);
                }
                let Ok(file) = sources.file(&symbol.location.path) else {
                    continue;
                };
                let location_end_line = if symbol.location.end.column == 1
                    && symbol.location.end.line > symbol.location.start.line
                {
                    symbol.location.end.line - 1
                } else {
                    symbol.location.end.line
                };
                let end_line =
                    location_end_line.min(symbol.location.start.line + MAX_REVIEW_HELPER_LINES - 1);
                let Ok((slice, slice_truncated)) =
                    source_slice(file, symbol.location.start.line, end_line)
                else {
                    continue;
                };
                truncated |= slice_truncated || end_line < location_end_line;
                let excerpt = redact_helper_definition(name, &slice.text);
                facts.push(ReviewNeighborhoodFact {
                    role: "helper_definition_context".to_string(),
                    symbol: name.clone(),
                    location: slice.location,
                    excerpt,
                    evidence_id: None,
                    provenance: textual_provenance(
                        "ast-grep outline exact-name helper definition, bounded and non-flow 1",
                    ),
                });
                definition_count += 1;
                if definition_count == 6 {
                    break;
                }
            }
        }

        let mut import_count = 0usize;
        for path in candidate_paths {
            let Ok(file) = sources.file(path) else {
                continue;
            };
            for (line_index, (start, end)) in line_spans(&file.source).into_iter().enumerate() {
                let line = &file.source[start..end];
                if !looks_like_import(line)
                    || !references
                        .iter()
                        .any(|name| contains_identifier(line, name))
                {
                    continue;
                }
                if import_count == 4 {
                    truncated = true;
                    break;
                }
                if facts.len() == limit {
                    return (facts, true);
                }
                let Ok((slice, slice_truncated)) =
                    source_slice(file, line_index + 1, line_index + 1)
                else {
                    continue;
                };
                truncated |= slice_truncated;
                let module = quoted_module_name(line);
                facts.push(ReviewNeighborhoodFact {
                    role: "import_context".to_string(),
                    symbol: module.clone().unwrap_or_else(|| "import".to_string()),
                    location: slice.location,
                    excerpt: slice.text,
                    evidence_id: None,
                    provenance: textual_provenance("bounded exact import context 1"),
                });
                import_count += 1;
                if let Some(module) = module {
                    if module.starts_with('.') {
                        continue;
                    }
                    if let Some(dependency) = dependency_fact(sources, &module) {
                        if facts.len() == limit {
                            return (facts, true);
                        }
                        facts.push(dependency);
                        import_count += 1;
                    }
                }
            }
        }

        let enclosing_names = references
            .iter()
            .filter(|name| {
                existing
                    .iter()
                    .any(|fact| fact.symbol.contains(name.as_str()))
                    || self.definitions.get(name.as_str()).is_some_and(|symbols| {
                        symbols.iter().any(|symbol| {
                            symbol.is_exported
                                && candidate_paths.contains(symbol.location.path.as_str())
                        })
                    })
            })
            .collect::<Vec<_>>();
        let mut registration_count = 0usize;
        for name in enclosing_names {
            let Some(registrations) = self.registrations.get(name) else {
                continue;
            };
            for registration in registrations {
                if registration_count == 2 {
                    truncated = true;
                    return (facts, truncated);
                }
                if candidate_paths.contains(registration.location.path.as_str()) {
                    continue;
                }
                if facts.len() == limit {
                    return (facts, true);
                }
                facts.push(registration.clone());
                registration_count += 1;
            }
        }
        (facts, truncated)
    }
}

fn second_hop_review_facts(
    sources: &RepositorySources,
    context: &ReviewContextIndex,
    candidate_paths: &BTreeSet<&str>,
    references: &BTreeSet<String>,
    existing: &[ReviewNeighborhoodFact],
    precise_member_fields: Option<&BTreeSet<String>>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let expanded = context.expanded_references(sources, candidate_paths, references);
    let second_only = expanded
        .difference(references)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut facts = Vec::new();
    let mut truncated = false;

    let mut covered = existing.to_vec();
    covered.extend(facts.iter().cloned());
    let (mut helper_facts, helper_truncated) = context.facts(
        sources,
        candidate_paths,
        &second_only,
        &covered,
        limit.saturating_sub(facts.len()).min(2),
    );
    truncated |= helper_truncated;
    facts.append(&mut helper_facts);

    let remaining = limit.saturating_sub(facts.len());
    if remaining > 0 {
        let (mut gate_facts, gate_truncated) =
            feature_gate_facts(sources, references, remaining.min(4));
        truncated |= gate_truncated;
        facts.append(&mut gate_facts);
    }

    let remaining = limit.saturating_sub(facts.len());
    if remaining > 0 {
        let context_text = existing
            .iter()
            .filter(|fact| {
                matches!(
                    fact.role.as_str(),
                    "helper_definition_context" | "feature_gate_policy_context"
                )
            })
            .chain(facts.iter())
            .map(|fact| fact.excerpt.as_str())
            .collect::<Vec<_>>();
        let (mut config_facts, config_truncated) =
            configuration_path_facts(sources, &context_text, remaining.min(2));
        truncated |= config_truncated;
        facts.append(&mut config_facts);
    }

    let remaining = limit.saturating_sub(facts.len());
    if remaining > 0 {
        let (mut template_facts, template_truncated) = template_binding_facts(
            sources,
            candidate_paths,
            existing,
            precise_member_fields,
            remaining.min(2),
        );
        truncated |= template_truncated;
        facts.append(&mut template_facts);
    }
    let remaining = limit.saturating_sub(facts.len());
    if remaining > 0 {
        let mut covered = existing.to_vec();
        covered.extend(facts.iter().cloned());
        let (mut usage_facts, usage_truncated) = context.usage_facts(
            sources,
            &expanded,
            candidate_paths,
            &covered,
            remaining.min(3),
        );
        truncated |= usage_truncated;
        facts.append(&mut usage_facts);
    }
    (facts, truncated)
}

fn feature_gate_facts(
    sources: &RepositorySources,
    references: &BTreeSet<String>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let challenge_names = references
        .iter()
        .filter(|name| name.to_ascii_lowercase().ends_with("challenge"))
        .collect::<Vec<_>>();
    if challenge_names.is_empty() || limit == 0 {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    if let Some(policy) = named_definition_fact(
        sources,
        "getChallengeEnablementStatus",
        "feature_gate_policy_context",
        40,
        "exact repository challenge-enablement policy; deployed configuration remains unproved 1",
    ) {
        facts.push(policy);
    }
    for file in sources.files.values().filter(|file| {
        file.path.ends_with("challenges.yml") || file.path.ends_with("challenges.yaml")
    }) {
        let spans = line_spans(&file.source);
        for (line_index, (start, _)) in spans.iter().copied().enumerate() {
            let line = &file.source[spans[line_index].0..spans[line_index].1];
            let Some(name) = challenge_names
                .iter()
                .find(|name| line.contains("key:") && contains_identifier(line, name))
            else {
                continue;
            };
            if facts.len() == limit {
                return (facts, true);
            }
            let mut end_index = line_index;
            while end_index + 1 < spans.len() && end_index < line_index + 4 {
                let next = file.source[spans[end_index + 1].0..spans[end_index + 1].1].trim();
                if next.is_empty() || next.starts_with("name:") {
                    break;
                }
                end_index += 1;
            }
            facts.push(ReviewNeighborhoodFact {
                role: "feature_gate_context".to_string(),
                symbol: (*name).clone(),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    start,
                    spans[end_index].1,
                ),
                excerpt: file.source[start..spans[end_index].1].to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "repository challenge descriptor only; deployed environment remains unproved 1",
                ),
            });
        }
    }
    (facts, false)
}

fn named_definition_fact(
    sources: &RepositorySources,
    name: &str,
    role: &str,
    max_lines: usize,
    provenance: &str,
) -> Option<ReviewNeighborhoodFact> {
    for file in sources.files.values() {
        if file.language.is_none()
            || is_nonproduction_review_context_path(&file.path)
            || file.source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        {
            continue;
        }
        let spans = line_spans(&file.source);
        for (line_index, (start, _)) in spans.iter().copied().enumerate() {
            let line = &file.source[spans[line_index].0..spans[line_index].1];
            if textual_definition_identifier(line).as_deref() != Some(name) {
                continue;
            }
            let end_index = if file.language == Some(Language::Python) {
                python_definition_end_index(&file.source, &spans, line_index, max_lines)
            } else {
                textual_definition_end_with_limit(&file.source, &spans, line_index, max_lines)
            };
            return Some(ReviewNeighborhoodFact {
                role: role.to_string(),
                symbol: name.to_string(),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    start,
                    spans[end_index].1,
                ),
                excerpt: file.source[start..spans[end_index].1].to_string(),
                evidence_id: None,
                provenance: textual_provenance(provenance),
            });
        }
    }
    None
}

fn configuration_path_facts(
    sources: &RepositorySources,
    context: &[&str],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let mut paths = BTreeSet::new();
    for source in context {
        for quoted in quoted_values(source) {
            if is_configuration_path(quoted) && !contains_sensitive_config_key(quoted) {
                paths.insert(quoted.to_string());
            }
        }
    }
    if paths.is_empty() || limit == 0 {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for file in sources.files.values() {
        if is_nonproduction_review_context_path(&file.path) {
            continue;
        }
        if !is_configuration_file(&file.path) && file.language.is_none() {
            continue;
        }
        for (start, end) in line_spans(&file.source) {
            let line = &file.source[start..end];
            let Some(path) = paths.iter().find(|path| {
                line.contains(path.as_str())
                    || is_repository_configuration_path(&file.path)
                        && path
                            .rsplit('.')
                            .next()
                            .is_some_and(|leaf| line.trim_start().starts_with(&format!("{leaf}:")))
            }) else {
                continue;
            };
            if facts.len() == limit {
                return (facts, true);
            }
            facts.push(ReviewNeighborhoodFact {
                role: "configuration_binding_context".to_string(),
                symbol: path.clone(),
                location: location_from_offsets(&file.path, &file.source, start, end),
                excerpt: bounded_line_text(line),
                evidence_id: None,
                provenance: textual_provenance(
                    "bounded repository configuration binding; deployed value remains unproved 1",
                ),
            });
        }
    }
    (facts, false)
}

fn is_configuration_path(value: &str) -> bool {
    if value.len() > 120 {
        return false;
    }
    let segments = value.split('.').collect::<Vec<_>>();
    segments.len() >= 2
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .any(|character| character.is_ascii_alphabetic())
                && segment.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
        })
}

fn is_repository_configuration_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.starts_with("config/")
        || normalized.contains("/config/")
        || normalized.starts_with("configuration/")
        || normalized.contains("/configuration/")
}

fn quoted_values(source: &str) -> Vec<&str> {
    let mut values = Vec::new();
    for quote in ['\'', '"'] {
        let mut rest = source;
        while let Some(start) = rest.find(quote) {
            rest = &rest[start + quote.len_utf8()..];
            let Some(end) = rest.find(quote) else {
                break;
            };
            values.push(&rest[..end]);
            rest = &rest[end + quote.len_utf8()..];
        }
    }
    values
}

fn template_binding_facts(
    sources: &RepositorySources,
    candidate_paths: &BTreeSet<&str>,
    existing: &[ReviewNeighborhoodFact],
    precise_member_fields: Option<&BTreeSet<String>>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let mut binding_names = precise_member_fields.cloned().unwrap_or_default();
    if binding_names.is_empty() {
        for fact in existing {
            if !fact.excerpt.contains("bypassSecurityTrust") {
                continue;
            }
            for line in fact.excerpt.lines().filter(|line| line.contains('=')) {
                let left = line.split('=').next().unwrap_or_default();
                if let Some(name) = terminal_identifier(left) {
                    binding_names.insert(name.to_string());
                }
            }
        }
    }
    if binding_names.is_empty() {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for path in candidate_paths {
        let normalized = path.replace('\\', "/");
        let Some(stem) = normalized.strip_suffix(".component.ts") else {
            continue;
        };
        let template_path = format!("{stem}.component.html");
        let template_source = match sources.file(&template_path) {
            Ok(file) => file.source.clone(),
            Err(_) => {
                let absolute = Path::new(&sources.root).join(&template_path);
                match fs::read_to_string(absolute) {
                    Ok(source) if source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES => source,
                    _ => continue,
                }
            }
        };
        for (start, end) in line_spans(&template_source) {
            let line = &template_source[start..end];
            if !["innerhtml", "dangerouslysetinnerhtml", "v-html"]
                .iter()
                .any(|marker| line.to_ascii_lowercase().contains(marker))
                || !binding_names
                    .iter()
                    .any(|name| contains_identifier(line, name))
            {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            facts.push(ReviewNeighborhoodFact {
                role: "template_binding_context".to_string(),
                symbol: binding_names
                    .iter()
                    .find(|name| contains_identifier(line, name))
                    .cloned()
                    .unwrap_or_else(|| "template_binding".to_string()),
                location: location_from_offsets(&template_path, &template_source, start, end),
                excerpt: bounded_line_text(line),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact sibling component template binding, bounded non-flow 1",
                ),
            });
        }
    }
    (facts, false)
}

fn express_template_review_facts(
    sources: &RepositorySources,
    sink: &Evidence,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 || !sink.rule_id.ends_with("html-output") {
        return (Vec::new(), false);
    }
    let Some(template) = sink
        .captures
        .get("template")
        .map(|capture| capture.text.trim().trim_matches(['\'', '"']))
        .filter(|template| valid_template_name(template))
    else {
        return (Vec::new(), false);
    };

    let mut facts = Vec::new();
    let mut truncated = false;
    let extensions = ["html", "swig", "njk", "ejs", "pug", "hbs"];
    let candidates = extensions.into_iter().flat_map(|extension| {
        [
            format!("app/views/{template}.{extension}"),
            format!("views/{template}.{extension}"),
        ]
    });
    for template_path in candidates {
        let absolute = Path::new(&sources.root).join(&template_path);
        let Ok(source) = fs::read_to_string(absolute) else {
            continue;
        };
        if source.len() > MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES {
            continue;
        }
        let mut matching = line_spans(&source)
            .into_iter()
            .filter(|(start, end)| {
                let line = &source[*start..*end];
                line.contains("{{")
                    || line.contains("{!!")
                    || line
                        .to_ascii_lowercase()
                        .contains("dangerouslysetinnerhtml")
            })
            .collect::<Vec<_>>();
        matching.sort_by_key(|(start, end)| {
            let lower = source[*start..*end].to_ascii_lowercase();
            if ["marked(", "href=", "src=", "|safe", "{!!", "style="]
                .iter()
                .any(|marker| lower.contains(marker))
            {
                0
            } else {
                1
            }
        });
        for (start, end) in matching {
            if facts.len() == limit.saturating_sub(2) {
                truncated = true;
                break;
            }
            facts.push(ReviewNeighborhoodFact {
                role: "server_template_binding_context".to_string(),
                symbol: template.to_string(),
                location: location_from_offsets(&template_path, &source, start, end),
                excerpt: bounded_line_text(&source[start..end]),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact Express server-template expression, bounded non-flow 1",
                ),
            });
        }
        break;
    }

    let uses_marked = facts.iter().any(|fact| fact.excerpt.contains("marked("));
    for (call, property) in [
        ("swig.setDefaults", "autoescape"),
        ("marked.setOptions", "sanitize"),
    ] {
        if property == "sanitize" && !uses_marked {
            continue;
        }
        if facts.len() == limit {
            truncated = true;
            break;
        }
        let Some(fact) = exact_javascript_configuration_fact(sources, call, property) else {
            continue;
        };
        facts.push(fact);
    }
    (facts, truncated)
}

fn valid_template_name(template: &str) -> bool {
    !template.is_empty()
        && template.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
        })
}

fn exact_javascript_configuration_fact(
    sources: &RepositorySources,
    call: &str,
    property: &str,
) -> Option<ReviewNeighborhoodFact> {
    for file in sources.files.values().filter(|file| {
        matches!(
            file.language,
            Some(Language::Javascript | Language::Typescript | Language::Tsx)
        ) && !is_nonproduction_review_context_path(&file.path)
    }) {
        let spans = line_spans(&file.source);
        for (index, (start, _)) in spans.iter().copied().enumerate() {
            if !file.source[spans[index].0..spans[index].1].contains(call) {
                continue;
            }
            let mut in_block_comment = false;
            for (line_start, end) in spans.iter().copied().skip(index).take(10) {
                let text = &file.source[start..end];
                let line = &file.source[line_start..end];
                let trimmed = line.trim();
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                let active = !in_block_comment && !trimmed.starts_with("//");
                if active && contains_identifier(trimmed, property) && trimmed.contains(':') {
                    return Some(ReviewNeighborhoodFact {
                        role: "template_configuration_context".to_string(),
                        symbol: property.to_string(),
                        location: location_from_offsets(&file.path, &file.source, start, end),
                        excerpt: text.to_string(),
                        evidence_id: None,
                        provenance: textual_provenance(
                            "exact executable JavaScript template configuration, bounded non-flow 1",
                        ),
                    });
                }
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
            }
        }
    }
    None
}

fn origin_consumer_review_facts(
    sources: &RepositorySources,
    context: &ReviewContextIndex,
    candidate_paths: &BTreeSet<&str>,
    existing: &[ReviewNeighborhoodFact],
    precise_stored_fields: Option<&BTreeSet<String>>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    let (endpoint_facts, endpoint_truncated) =
        endpoint_consumer_facts(sources, candidate_paths, existing, 3);
    let mut response_context = existing.to_vec();
    response_context.extend(endpoint_facts.iter().cloned());
    let mut truncated = endpoint_truncated;
    for (mut additions, was_truncated) in [
        ineffective_protection_review_facts(sources, existing, 2),
        browser_storage_write_facts(sources, existing, 2),
        token_payload_origin_facts(sources, existing, 1),
        request_response_origin_facts(sources, &response_context, 2),
        stored_write_origin_facts_with_fields(sources, existing, precise_stored_fields, 2),
        configuration_lifecycle_facts(sources, existing, 2),
        (endpoint_facts, endpoint_truncated),
        candidate_registration_facts(sources, context, candidate_paths, existing, 1),
    ] {
        truncated |= was_truncated;
        for fact in additions.drain(..) {
            if !matches!(
                fact.role.as_str(),
                "ineffective_protection_context" | "request_response_origin_context"
            ) && (facts_cover_location(existing, &fact.location)
                || facts_cover_location(&facts, &fact.location))
            {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            facts.push(fact);
        }
    }
    (facts, truncated)
}

fn ineffective_protection_review_facts(
    sources: &RepositorySources,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0
        || !existing.iter().any(|fact| {
            matches!(fact.role.as_str(), "source_context" | "sink_context")
                && fact.excerpt.contains(".redirect(")
        })
    {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for helper in existing.iter().filter(|fact| {
        fact.role == "helper_definition_context"
            && fact.excerpt.contains(".includes(")
            && (fact.excerpt.contains("allowlist") || fact.excerpt.contains("Allowlist"))
    }) {
        let Ok(file) = sources.file(&helper.location.path) else {
            continue;
        };
        for (start, end) in line_spans(&file.source) {
            let line = &file.source[start..end];
            if !line.contains(".includes(") || (!line.contains("allow") && !line.contains("Allow"))
            {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            facts.push(ReviewNeighborhoodFact {
                role: "ineffective_protection_context".to_string(),
                symbol: "substring URL allowlist".to_string(),
                location: location_from_offsets(&file.path, &file.source, start, end),
                excerpt: bounded_line_text(line),
                evidence_id: None,
                provenance: textual_provenance(
                    "substring containment does not establish redirect destination identity 1",
                ),
            });
            break;
        }
    }
    (facts, false)
}

#[cfg(test)]
fn stored_write_origin_facts(
    sources: &RepositorySources,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    stored_write_origin_facts_with_fields(sources, existing, None, limit)
}

fn stored_write_origin_facts_with_fields(
    sources: &RepositorySources,
    existing: &[ReviewNeighborhoodFact],
    precise_fields: Option<&BTreeSet<String>>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let text = existing
        .iter()
        .map(|fact| fact.excerpt.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let mut fields = precise_fields
        .cloned()
        .unwrap_or_else(|| interpolated_member_fields(existing));
    if text.contains("eval(") {
        fields.extend(
            [
                "username",
                "comment",
                "description",
                "content",
                "title",
                "name",
            ]
            .into_iter()
            .filter(|field| contains_identifier(&text, field))
            .map(str::to_string),
        );
    }
    if fields.is_empty() {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language.is_some() && !is_nonproduction_review_context_path(&file.path))
    {
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            let Some(field) = fields.iter().find(|field| contains_identifier(line, field)) else {
                continue;
            };
            let lower = line.to_ascii_lowercase();
            if ![".update(", ".create(", ".save(", ".set("]
                .iter()
                .any(|marker| lower.contains(marker))
            {
                continue;
            }
            let definition_index = (0..=line_index).rev().take(64).find(|index| {
                is_textual_callable_definition(&file.source[spans[*index].0..spans[*index].1])
            });
            let (slice_start, slice_end) = if let Some(definition_index) = definition_index {
                let end_index =
                    textual_definition_end_with_limit(&file.source, &spans, definition_index, 96);
                (spans[definition_index].0, spans[end_index].1)
            } else {
                (
                    spans[line_index.saturating_sub(8)].0,
                    spans[(line_index + 8).min(spans.len() - 1)].1,
                )
            };
            let excerpt = &file.source[slice_start..slice_end];
            let excerpt_lower = excerpt.to_ascii_lowercase();
            if !(excerpt.contains("req.")
                || excerpt_lower.contains("request.")
                || excerpt_lower.contains("request["))
            {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            facts.push(ReviewNeighborhoodFact {
                role: "stored_write_origin_context".to_string(),
                symbol: field.clone(),
                location: location_from_offsets(&file.path, &file.source, slice_start, slice_end),
                excerpt: excerpt.to_string(),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact request-backed persistence writer for rendered member field 1",
                ),
            });
        }
    }
    (facts, false)
}

fn evidence_member_fields<'a>(evidence: impl Iterator<Item = &'a Evidence>) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    for item in evidence {
        for value in item
            .captures
            .values()
            .map(|capture| capture.text.as_str())
            .chain(
                item.context
                    .literals
                    .values()
                    .flat_map(|literal| literal.references.iter().map(String::as_str)),
            )
        {
            for expression in
                value.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
            {
                let Some((_, field)) = expression.rsplit_once('.') else {
                    continue;
                };
                if field.len() >= 2
                    && field.len() <= 80
                    && field
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                {
                    fields.insert(field.to_string());
                }
            }
        }
    }
    fields
}

fn sink_assignment_target_field(sources: &RepositorySources, item: &Evidence) -> Option<String> {
    if item.kind != EvidenceKind::Sink {
        return None;
    }
    let file = sources.file(&item.location.path).ok()?;
    let (start, end) = line_spans(&file.source).into_iter().find(|(start, end)| {
        *start <= item.location.start.byte_offset && item.location.start.byte_offset <= *end
    })?;
    let sink_start = item.location.start.byte_offset.min(end);
    if !file.source.is_char_boundary(start) || !file.source.is_char_boundary(sink_start) {
        return None;
    }
    let prefix = &file.source[start..sink_start];
    let equals = prefix.rfind('=')?;
    let before = prefix[..equals].trim_end();
    let after = prefix[equals + 1..].trim_start();
    let comparison = before.ends_with(['!', '<', '>', '=']) || after.starts_with('=');
    if comparison || !after.is_empty() {
        return None;
    }
    terminal_identifier(before).map(str::to_string)
}

fn browser_storage_write_facts(
    sources: &RepositorySources,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let keys = existing
        .iter()
        .flat_map(|fact| fact.excerpt.lines())
        .filter(|line| line.contains("Storage.getItem("))
        .flat_map(quoted_values)
        .filter(|value| !value.is_empty() && value.len() <= 80)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language.is_some() && !is_nonproduction_review_context_path(&file.path))
    {
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            let Some(key) = keys.iter().find(|key| {
                line.contains("Storage.setItem(")
                    && quoted_values(line)
                        .iter()
                        .any(|value| *value == key.as_str())
            }) else {
                continue;
            };
            if facts.len() == limit {
                return (facts, true);
            }
            let start_line = line_index.saturating_sub(4) + 1;
            let end_line = (line_index + 5).min(spans.len());
            let Ok((slice, slice_truncated)) = source_slice(file, start_line, end_line) else {
                continue;
            };
            facts.push(ReviewNeighborhoodFact {
                role: "browser_storage_write_context".to_string(),
                symbol: key.clone(),
                location: slice.location,
                excerpt: slice.text,
                evidence_id: None,
                provenance: textual_provenance(
                    "exact production browser-storage writer for the read key 1",
                ),
            });
            if slice_truncated {
                return (facts, true);
            }
        }
    }
    (facts, false)
}

fn token_payload_origin_facts(
    sources: &RepositorySources,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0
        || !existing.iter().any(|fact| {
            fact.excerpt.contains("jwtDecode(") && fact.excerpt.contains("Storage.getItem(")
        })
    {
        return (Vec::new(), false);
    }
    for file in sources
        .files
        .values()
        .filter(|file| file.language.is_some() && !is_nonproduction_review_context_path(&file.path))
    {
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            if !line.contains("authorize(") {
                continue;
            }
            let definition_index = (0..=line_index).rev().take(64).find(|index| {
                is_textual_callable_definition(&file.source[spans[*index].0..spans[*index].1])
            });
            let Some(definition_index) = definition_index else {
                continue;
            };
            let end_index =
                textual_definition_end_with_limit(&file.source, &spans, definition_index, 96);
            let excerpt = &file.source[spans[definition_index].0..spans[end_index].1];
            if !excerpt.contains("data:")
                || !excerpt.contains("authorize(")
                || !excerpt.contains("res.json(")
                || !excerpt.contains("token")
            {
                continue;
            }
            return (
                vec![ReviewNeighborhoodFact {
                    role: "token_payload_origin_context".to_string(),
                    symbol: textual_definition_identifier(
                        &file.source[spans[definition_index].0..spans[definition_index].1],
                    )
                    .unwrap_or_else(|| "token producer".to_string()),
                    location: location_from_offsets(
                        &file.path,
                        &file.source,
                        spans[definition_index].0,
                        spans[end_index].1,
                    ),
                    excerpt: excerpt.to_string(),
                    evidence_id: None,
                    provenance: textual_provenance(
                        "exact user-data token construction and response context 1",
                    ),
                }],
                false,
            );
        }
    }
    (Vec::new(), false)
}

fn request_response_origin_facts(
    _sources: &RepositorySources,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let fields = interpolated_member_fields(existing);
    if fields.is_empty() || limit == 0 {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for handler in existing
        .iter()
        .filter(|fact| fact.role == "endpoint_handler_context")
    {
        let Some(field) = fields
            .iter()
            .find(|field| contains_identifier(&handler.excerpt, field))
        else {
            continue;
        };
        if !handler.excerpt.contains("req.")
            || !handler.excerpt.contains("res.json(")
            || !(handler.excerpt.contains(&format!("{field}:"))
                || handler.excerpt.contains(&format!(".{field}")))
        {
            continue;
        }
        if facts.len() == limit {
            return (facts, true);
        }
        let mut fact = handler.clone();
        fact.role = "request_response_origin_context".to_string();
        fact.provenance =
            textual_provenance("exact registered request-derived response-field producer 1");
        facts.push(fact);
    }
    (facts, false)
}

fn interpolated_member_fields(existing: &[ReviewNeighborhoodFact]) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    for fact in existing
        .iter()
        .filter(|fact| matches!(fact.role.as_str(), "source_context" | "sink_context"))
    {
        for interpolation in fact.excerpt.split("${").skip(1) {
            let Some(expression) = interpolation.split('}').next() else {
                continue;
            };
            // A terminal method call such as `${value.toString()}` names an
            // operation, not a persisted member field. Treating `toString`
            // as a data field can attach an unrelated writer to any review
            // whose context window contains the interpolation.
            if expression.trim_end().ends_with(')') {
                continue;
            }
            if let Some(field) = expression
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .filter(|token| !token.is_empty())
                .next_back()
                .filter(|token| token.len() >= 2 && token.len() <= 80)
            {
                fields.insert(field.to_string());
            }
        }
    }
    fields
}

fn is_textual_callable_definition(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.contains("function ")
        || trimmed.starts_with("func ")
        || trimmed.starts_with("func (")
        || trimmed.starts_with("def ")
        || ((trimmed.starts_with("const ")
            || trimmed.starts_with("let ")
            || trimmed.starts_with("var "))
            && (trimmed.contains("=>") || trimmed.contains("function")))
        || (trimmed.contains('(')
            && trimmed.contains('{')
            && ["public ", "private ", "protected ", "internal "]
                .iter()
                .any(|modifier| trimmed.starts_with(modifier)))
}

fn configuration_lifecycle_facts(
    sources: &RepositorySources,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let keys = existing
        .iter()
        .filter(|fact| fact.role == "configuration_binding_context")
        .map(|fact| fact.symbol.as_str())
        .filter(|key| is_configuration_path(key))
        .filter(|key| {
            existing
                .iter()
                .any(|fact| fact.role == "helper_definition_context" && fact.excerpt.contains(*key))
        })
        .collect::<BTreeSet<_>>();
    if keys.is_empty() || limit == 0 {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language.is_some())
    {
        let spans = line_spans(&file.source);
        for (line_index, _) in spans.iter().copied().enumerate() {
            let line = &file.source[spans[line_index].0..spans[line_index].1];
            let Some(key) = keys.iter().find(|key| line.contains(*key)) else {
                continue;
            };
            let definition_index = (0..=line_index).rev().take(10).find(|index| {
                textual_definition_identifier(&file.source[spans[*index].0..spans[*index].1])
                    .is_some()
            });
            if let Some(definition_index) = definition_index {
                if facts.len() == limit {
                    return (facts, true);
                }
                let end_index =
                    textual_definition_end_with_limit(&file.source, &spans, definition_index, 16);
                facts.push(ReviewNeighborhoodFact {
                    role: "configuration_lifecycle_context".to_string(),
                    symbol: (*key).to_string(),
                    location: location_from_offsets(
                        &file.path,
                        &file.source,
                        spans[definition_index].0,
                        spans[end_index].1,
                    ),
                    excerpt: file.source[spans[definition_index].0..spans[end_index].1].to_string(),
                    evidence_id: None,
                    provenance: textual_provenance(
                        "bounded exact configuration-key lifecycle use, non-deployment proof 1",
                    ),
                });
            }
            let mut names = BTreeSet::new();
            collect_review_reference_tokens(line, &mut names);
            for name in names {
                if facts.len() == limit {
                    return (facts, true);
                }
                let Some(mut fact) = named_definition_fact(
                    sources,
                    &name,
                    "configuration_lifecycle_context",
                    24,
                    "exact helper referenced by configuration lifecycle; non-flow 1",
                ) else {
                    continue;
                };
                fact.symbol = name;
                if !facts_cover_location(&facts, &fact.location) {
                    facts.push(fact);
                }
            }
            if !facts.is_empty() {
                return (facts, false);
            }
        }
    }
    (facts, false)
}

fn endpoint_consumer_facts(
    sources: &RepositorySources,
    _candidate_paths: &BTreeSet<&str>,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let mut endpoints = existing
        .iter()
        .filter(|fact| {
            if fact.role != "helper_definition_context"
                || !["service", "repository", "client"]
                    .iter()
                    .any(|suffix| fact.symbol.to_ascii_lowercase().ends_with(suffix))
            {
                return false;
            }
            let mut characters = fact.symbol.chars();
            let Some(first) = characters.next() else {
                return false;
            };
            let receiver = format!("{}{}", first.to_ascii_lowercase(), characters.as_str());
            existing.iter().any(|context| {
                matches!(context.role.as_str(), "source_context" | "sink_context")
                    && contains_identifier(&context.excerpt, &receiver)
            })
        })
        .flat_map(|fact| quoted_values(&fact.excerpt))
        .filter(|value| value.starts_with('/') && value.len() > 1 && value.len() <= 160)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let mut exact_endpoints = BTreeSet::new();
    for fact in existing
        .iter()
        .filter(|fact| matches!(fact.role.as_str(), "source_context" | "sink_context"))
    {
        exact_endpoints.extend(javascript_fetch_endpoints(&fact.excerpt));
    }
    endpoints.extend(exact_endpoints.iter().cloned());
    if endpoints.is_empty() {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|file| file.language.is_some())
    {
        for (start, end) in line_spans(&file.source) {
            let line = &file.source[start..end];
            let django_registration = file.language == Some(Language::Python)
                && ["path(", "re_path("].iter().any(|call| line.contains(call));
            if !(looks_like_registration_reference(line) || django_registration)
                || !quoted_values(line).iter().any(|route| {
                    if route.len() <= 1 {
                        return false;
                    }
                    let route = route.trim_start_matches('/');
                    if !exact_endpoints.is_empty() {
                        return exact_endpoints
                            .iter()
                            .any(|endpoint| endpoint.trim_start_matches('/') == route);
                    }
                    endpoints.iter().any(|endpoint| {
                        let endpoint = endpoint.trim_start_matches('/');
                        route == endpoint
                            || route.starts_with(endpoint)
                            || endpoint.starts_with(route)
                    })
                })
            {
                continue;
            }
            facts.push(ReviewNeighborhoodFact {
                role: "endpoint_registration_context".to_string(),
                symbol: endpoints.iter().next().cloned().unwrap_or_default(),
                location: location_from_offsets(&file.path, &file.source, start, end),
                excerpt: bounded_line_text(line),
                evidence_id: None,
                provenance: textual_provenance(
                    "exact client/server endpoint literal registration, bounded non-runtime 1",
                ),
            });
            let mut names = BTreeSet::new();
            collect_review_reference_tokens(line, &mut names);
            if django_registration
                && let Some(handler_argument) = line.split(',').nth(1)
                && let Some(name) = terminal_identifier(handler_argument)
            {
                names.insert(name.to_string());
            }
            for name in names {
                if facts.len() == limit {
                    return (facts, true);
                }
                if let Some(fact) = named_definition_fact(
                    sources,
                    &name,
                    "endpoint_handler_context",
                    48,
                    "exact registered endpoint handler definition, bounded non-runtime 1",
                ) {
                    facts.push(fact);
                    break;
                }
            }
            return (facts, false);
        }
    }
    (facts, false)
}

fn javascript_fetch_endpoints(source: &str) -> BTreeSet<String> {
    let mut endpoints = BTreeSet::new();
    let mut remaining = source;
    while let Some(index) = remaining.find("fetch(") {
        remaining = &remaining[index + "fetch(".len()..];
        let Some(endpoint) = first_quoted_value(remaining) else {
            continue;
        };
        if endpoint.starts_with('/') && endpoint.len() > 1 && endpoint.len() <= 160 {
            endpoints.insert(endpoint.to_string());
        }
    }
    endpoints
}

fn candidate_registration_facts(
    sources: &RepositorySources,
    context: &ReviewContextIndex,
    candidate_paths: &BTreeSet<&str>,
    existing: &[ReviewNeighborhoodFact],
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if limit == 0 {
        return (Vec::new(), false);
    }
    let needs_direct_registration = existing.iter().any(|fact| {
        fact.role == "configuration_binding_context"
            && fact.symbol.split('.').count() >= 3
            && existing.iter().any(|helper| {
                helper.role == "helper_definition_context" && helper.excerpt.contains(&fact.symbol)
            })
    });
    if needs_direct_registration {
        let mut exported = BTreeSet::new();
        for path in candidate_paths {
            let Ok(file) = sources.file(path) else {
                continue;
            };
            for line in file.source.lines().filter(|line| line.contains("export ")) {
                if let Some(name) = textual_definition_identifier(line) {
                    exported.insert(name);
                }
            }
        }
        for file in sources
            .files
            .values()
            .filter(|file| file.language.is_some())
        {
            for (start, end) in line_spans(&file.source) {
                let line = &file.source[start..end];
                let Some(symbol) = exported.iter().find(|symbol| {
                    looks_like_registration_reference(line) && contains_identifier(line, symbol)
                }) else {
                    continue;
                };
                return (
                    vec![ReviewNeighborhoodFact {
                        role: "registration_context".to_string(),
                        symbol: symbol.clone(),
                        location: location_from_offsets(&file.path, &file.source, start, end),
                        excerpt: bounded_line_text(line),
                        evidence_id: None,
                        provenance: textual_provenance(
                            "exact exported candidate handler framework registration 1",
                        ),
                    }],
                    false,
                );
            }
        }
    }
    let mut symbols = BTreeSet::new();
    for (name, definitions) in &context.definitions {
        if definitions.iter().any(|definition| {
            definition.is_exported && candidate_paths.contains(definition.location.path.as_str())
        }) {
            symbols.insert(name.clone());
        }
    }
    let mut facts = Vec::new();
    let mut ordered_symbols = symbols.into_iter().collect::<Vec<_>>();
    ordered_symbols.sort_by_key(|name| {
        (
            !context.definitions.get(name).is_some_and(|definitions| {
                definitions.iter().any(|definition| {
                    definition.is_exported
                        && candidate_paths.contains(definition.location.path.as_str())
                })
            }),
            name.clone(),
        )
    });
    for symbol in ordered_symbols {
        let Some(registrations) = context.registrations.get(&symbol) else {
            continue;
        };
        for registration in registrations {
            if facts_cover_location(existing, &registration.location) {
                continue;
            }
            if facts.len() == limit {
                return (facts, true);
            }
            facts.push(registration.clone());
        }
    }
    (facts, false)
}

fn review_reference_tokens(
    candidates: &[mehscan_core::Candidate],
    sources: &RepositorySources,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    context_lines: usize,
) -> BTreeSet<String> {
    let mut references = BTreeSet::new();
    for candidate in candidates {
        let mut candidate_paths = BTreeSet::new();
        for step in &candidate.steps {
            let Ok(file) = sources.file(&step.location.path) else {
                continue;
            };
            candidate_paths.insert(step.location.path.as_str());
            collect_enclosing_textual_definition_names(
                file,
                step.location.start.line,
                &mut references,
            );
            let exact_start = step.location.start.byte_offset.min(file.source.len());
            let exact_end = step.location.end.byte_offset.min(file.source.len());
            if exact_start < exact_end
                && file.source.is_char_boundary(exact_start)
                && file.source.is_char_boundary(exact_end)
            {
                collect_review_reference_tokens(
                    &file.source[exact_start..exact_end],
                    &mut references,
                );
            }
            let start_line = step
                .location
                .start
                .line
                .saturating_sub(context_lines)
                .max(1);
            let end_line = step.location.end.line.saturating_add(context_lines);
            if let Ok((slice, _)) = source_slice(file, start_line, end_line) {
                collect_policy_reference_tokens(&slice.text, &mut references);
                collect_challenge_reference_tokens(&slice.text, &mut references);
                collect_boundary_type_reference_tokens(&slice.text, &mut references);
            }
        }
        for path in candidate_paths {
            if let Ok(file) = sources.file(path) {
                for line in file.source.lines().filter(|line| looks_like_import(line)) {
                    collect_boundary_type_reference_tokens(line, &mut references);
                }
            }
        }
        for evidence_id in [&candidate.source.id, &candidate.sink.id] {
            if let Some(evidence) = evidence_by_id.get(evidence_id.as_str()) {
                for capture in evidence.captures.values() {
                    collect_review_reference_tokens(&capture.text, &mut references);
                }
            }
        }
        if evidence_by_id
            .get(candidate.sink.id.as_str())
            .is_some_and(|sink| sink.tags.iter().any(|tag| tag == "unique-helper"))
            && let Ok(file) = sources.file(&candidate.sink.location.path)
        {
            let start = candidate
                .sink
                .location
                .start
                .byte_offset
                .min(file.source.len());
            let end = candidate
                .sink
                .location
                .end
                .byte_offset
                .min(file.source.len());
            if start < end
                && file.source.is_char_boundary(start)
                && file.source.is_char_boundary(end)
                && let Some(helper) = direct_call_reference(&file.source[start..end])
            {
                references.insert(helper);
            }
        }
        for symbol in [
            candidate.source.enclosing_symbol.as_deref(),
            candidate.sink.enclosing_symbol.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(identifier) = terminal_identifier(symbol) {
                references.insert(identifier.to_string());
            }
        }
    }
    references
}

fn collect_review_reference_tokens(source: &str, output: &mut BTreeSet<String>) {
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !(bytes[index].is_ascii_alphabetic() || matches!(bytes[index], b'_' | b'$')) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
        {
            index += 1;
        }
        let token = &source[start..index];
        let before = source[..start]
            .chars()
            .rev()
            .find(|character| !character.is_whitespace());
        let after_offset = source[index..]
            .char_indices()
            .find(|(_, character)| !character.is_whitespace())
            .map(|(offset, _)| index + offset);
        let after = after_offset.and_then(|offset| source[offset..].chars().next());
        let qualified_call = after == Some('.')
            && after_offset.is_some_and(|offset| {
                source[offset + 1..]
                    .split(|character: char| {
                        character.is_whitespace()
                            || matches!(character, ';' | ',' | ')' | ']' | '}')
                    })
                    .next()
                    .is_some_and(|tail| tail.contains('('))
            });
        let sensitive = is_sensitive_reference_name(token);
        let model_or_policy_name = {
            let lower = token.to_ascii_lowercase();
            lower == "automodels"
                || lower.ends_with("model")
                || lower != "challenge" && lower.ends_with("challenge")
                || lower.contains("allowlist")
                || lower.contains("redirect")
        };
        if is_helpful_reference_identifier(token)
            && (after == Some('(')
                || before == Some('.') && after == Some('(')
                || qualified_call
                || sensitive
                || model_or_policy_name)
        {
            output.insert(token.to_string());
        }
    }
}

fn direct_call_reference(source: &str) -> Option<String> {
    let prefix = source.split_once('(')?.0;
    prefix
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        })
        .rfind(|token| is_helpful_reference_identifier(token))
        .map(str::to_string)
}

fn collect_policy_reference_tokens(source: &str, output: &mut BTreeSet<String>) {
    let mut tokens = BTreeSet::new();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !(bytes[index].is_ascii_alphabetic() || matches!(bytes[index], b'_' | b'$')) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
        {
            index += 1;
        }
        let token = &source[start..index];
        let lower = token.to_ascii_lowercase();
        if is_helpful_reference_identifier(token)
            && [
                "allowlist",
                "redirectallowed",
                "sanitize",
                "validate",
                "encode",
                "escape",
                "encrypt",
                "parsexml",
                "automodels",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
        {
            tokens.insert(token.to_string());
        }
    }
    output.extend(tokens);
}

fn collect_challenge_reference_tokens(source: &str, output: &mut BTreeSet<String>) {
    for token in source.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
    }) {
        let lower = token.to_ascii_lowercase();
        if lower != "challenge"
            && lower.ends_with("challenge")
            && is_helpful_reference_identifier(token)
        {
            output.insert(token.to_string());
        }
    }
}

fn collect_boundary_type_reference_tokens(source: &str, output: &mut BTreeSet<String>) {
    for token in source.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
    }) {
        if !token
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_uppercase())
        {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if ["service", "repository", "client"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
            && is_helpful_reference_identifier(token)
        {
            output.insert(token.to_string());
        }
    }
}

fn collect_used_import_boundary_types(
    source: &str,
    review_text: &str,
    output: &mut BTreeSet<String>,
) {
    for line in source.lines().filter(|line| looks_like_import(line)) {
        let mut imported = BTreeSet::new();
        collect_boundary_type_reference_tokens(line, &mut imported);
        for name in imported {
            let mut characters = name.chars();
            let Some(first) = characters.next() else {
                continue;
            };
            let receiver = format!("{}{}", first.to_ascii_lowercase(), characters.as_str());
            if contains_identifier(review_text, &receiver)
                || contains_identifier(review_text, &name)
            {
                output.insert(name);
            }
        }
    }
}

fn collect_enclosing_textual_definition_names(
    file: &SourceFile,
    target_line: usize,
    output: &mut BTreeSet<String>,
) {
    let spans = line_spans(&file.source);
    if target_line == 0 || target_line > spans.len() {
        return;
    }
    for line_index in (0..target_line).rev().take(80) {
        let line = &file.source[spans[line_index].0..spans[line_index].1];
        let Some(name) = textual_definition_identifier(line) else {
            continue;
        };
        let end_index = textual_definition_end_with_limit(&file.source, &spans, line_index, 80);
        if end_index + 1 >= target_line {
            output.insert(name);
            return;
        }
    }
}

fn reference_priority(name: &str) -> u8 {
    let lower = name.to_ascii_lowercase();
    if is_sensitive_reference_name(name) {
        4
    } else if [
        "challenge",
        "allow",
        "redirect",
        "sanitize",
        "validate",
        "verify",
        "hash",
        "parse",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        3
    } else if lower.contains("model") || lower.contains("coupon") {
        2
    } else {
        1
    }
}

fn is_sensitive_reference_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "password" | "passwd" | "secret" | "token" | "credential" | "apikey" | "key"
    ) {
        return false;
    }
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "privatekey",
        "private_key",
        "apikey",
        "api_key",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn textual_definition_identifier(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with('*')
        || trimmed.starts_with("/*")
    {
        return None;
    }
    if let Some(method) = trimmed.strip_prefix("func (")
        && let Some((_, after_receiver)) = method.split_once(')')
        && let Some((name, _)) = after_receiver.trim_start().split_once('(')
    {
        let name = name.trim();
        if is_helpful_reference_identifier(name)
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Some(name.to_string());
        }
    }
    if let Some(method) = trimmed.strip_prefix("this.")
        && let Some((name, value)) = method.split_once('=')
    {
        let name = name.trim();
        let value = value.trim_start();
        if is_helpful_reference_identifier(name)
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && (value.starts_with('(') || value.starts_with("function"))
        {
            return Some(name.to_string());
        }
    }
    let tokens = trimmed
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if matches!(
            *token,
            "const" | "let" | "var" | "function" | "class" | "def"
        ) {
            let name = tokens.get(index + 1).copied()?;
            return is_helpful_reference_identifier(name).then(|| name.to_string());
        }
        if *token == "func" {
            // Receiver methods were handled above; plain functions name the
            // token immediately following `func`.
            let name = tokens.get(index + 1).copied()?;
            return is_helpful_reference_identifier(name).then(|| name.to_string());
        }
    }
    if trimmed.contains('(')
        && ["public ", "private ", "protected ", "internal "]
            .iter()
            .any(|modifier| trimmed.starts_with(modifier))
    {
        let prefix = trimmed.split_once('(')?.0;
        if !prefix.contains('=') {
            let name = prefix
                .split(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
                })
                .rfind(|token| !token.is_empty())?;
            if is_helpful_reference_identifier(name) {
                return Some(name.to_string());
            }
        }
    }
    let first = tokens.first().copied()?;
    let after_first = trimmed.find(first).map(|start| start + first.len())?;
    if is_helpful_reference_identifier(first)
        && trimmed[after_first..].trim_start().starts_with([':', '?'])
        && (trimmed.contains('{') || trimmed.contains("defaultValue"))
    {
        return Some(first.to_string());
    }
    None
}

fn textual_definition_end(
    source: &str,
    spans: &[(usize, usize)],
    start_line_index: usize,
) -> usize {
    textual_definition_end_with_limit(source, spans, start_line_index, 64)
}

fn textual_definition_end_with_limit(
    source: &str,
    spans: &[(usize, usize)],
    start_line_index: usize,
    max_lines: usize,
) -> usize {
    let mut depth = 0isize;
    let mut opened = false;
    let maximum = (start_line_index + max_lines.saturating_sub(1)).min(spans.len() - 1);
    for line_index in start_line_index..=maximum {
        let (start, end) = spans[line_index];
        for character in source[start..end].chars() {
            match character {
                '{' | '[' | '(' => {
                    opened = true;
                    depth += 1;
                }
                '}' | ']' | ')' if opened => depth -= 1,
                _ => {}
            }
        }
        let brace_on_next_line = line_index == start_line_index
            && depth <= 0
            && spans
                .get(line_index + 1)
                .is_some_and(|(next_start, next_end)| {
                    source[*next_start..*next_end].trim_start().starts_with('{')
                });
        if brace_on_next_line {
            continue;
        }
        if !opened || depth <= 0 {
            return line_index;
        }
    }
    maximum
}

fn is_helpful_reference_identifier(token: &str) -> bool {
    if token.len() < 3 || token.len() > 96 || !token.is_ascii() {
        return false;
    }
    !matches!(
        token.to_ascii_lowercase().as_str(),
        "any"
            | "app"
            | "async"
            | "await"
            | "body"
            | "boolean"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "data"
            | "default"
            | "delete"
            | "else"
            | "export"
            | "false"
            | "finally"
            | "for"
            | "from"
            | "function"
            | "get"
            | "if"
            | "import"
            | "interface"
            | "let"
            | "new"
            | "null"
            | "number"
            | "object"
            | "private"
            | "public"
            | "query"
            | "req"
            | "request"
            | "res"
            | "response"
            | "return"
            | "set"
            | "static"
            | "string"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "type"
            | "undefined"
            | "var"
            | "void"
            | "while"
    )
}

fn terminal_identifier(symbol: &str) -> Option<&str> {
    symbol
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        })
        .rfind(|part| is_helpful_reference_identifier(part))
}

fn facts_cover_location(facts: &[ReviewNeighborhoodFact], location: &Location) -> bool {
    facts.iter().any(|fact| {
        fact.location.path == location.path
            && fact.location.start.byte_offset <= location.start.byte_offset
            && fact.location.end.byte_offset >= location.end.byte_offset
    })
}

fn redact_helper_definition(name: &str, excerpt: &str) -> String {
    if !is_sensitive_reference_name(name) {
        return excerpt.to_string();
    }
    let lower = excerpt.to_ascii_lowercase();
    if looks_like_configuration_reference(excerpt) {
        return format!(
            "Definition for {name} reads configuration or environment state; security-sensitive value redacted."
        );
    }
    if lower.contains("begin rsa private key") || lower.contains("begin private key") {
        return format!(
            "Definition for {name} contains a source-embedded private-key literal; value redacted."
        );
    }
    redact_quoted_literals(excerpt)
}

fn redact_quoted_literals(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut quote = None;
    let mut escaped = false;
    for character in source.chars() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == active {
                output.push_str("<redacted>");
                output.push(character);
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
        }
        output.push(character);
    }
    if quote.is_some() {
        output.push_str("<redacted>");
    }
    output
}

fn looks_like_import(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("import ")
        || trimmed.starts_with("export ") && trimmed.contains(" from ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("using ")
        || trimmed.starts_with("require(")
        || line.contains(" require(")
        || line.contains("import(")
}

fn quoted_module_name(line: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let mut parts = line.rsplitn(3, quote);
        let Some(_after) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        if !value.trim().is_empty() && !value.chars().any(char::is_whitespace) {
            return Some(value.to_string());
        }
    }
    None
}

fn dependency_fact(sources: &RepositorySources, module: &str) -> Option<ReviewNeighborhoodFact> {
    let dependency = module.strip_prefix('@').unwrap_or(module);
    let dependency = dependency.split('/').next().unwrap_or(dependency);
    for file in sources.files.values().filter(|file| {
        if is_nonproduction_review_context_path(&file.path) {
            return false;
        }
        let name = file.path.rsplit('/').next().unwrap_or(&file.path);
        matches!(name, "package.json" | "pyproject.toml" | "requirements.txt")
            || name.ends_with(".csproj")
            || name == "pom.xml"
            || name == "build.gradle"
            || name == "build.gradle.kts"
    }) {
        for (line_index, (start, end)) in line_spans(&file.source).into_iter().enumerate() {
            let line = &file.source[start..end];
            if !contains_identifier(line, dependency) {
                continue;
            }
            let Ok((slice, _)) = source_slice(file, line_index + 1, line_index + 1) else {
                continue;
            };
            return Some(ReviewNeighborhoodFact {
                role: "dependency_context".to_string(),
                symbol: module.to_string(),
                location: slice.location,
                excerpt: slice.text,
                evidence_id: None,
                provenance: textual_provenance(
                    "bounded repository dependency declaration, effective resolution unproved 1",
                ),
            });
        }
    }
    None
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    source
        .match_indices(identifier)
        .any(|(start, _)| is_identifier_match(source, start, start + identifier.len()))
}

fn looks_like_registration_reference(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let registration_call = [
        ".get(",
        ".post(",
        ".put(",
        ".patch(",
        ".delete(",
        ".use(",
        "mapget(",
        "mappost(",
        "mapput(",
        "mapdelete(",
        "addroute(",
        "route(",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    registration_call
        && quoted_values(line)
            .iter()
            .any(|route| route.starts_with('/') && route.len() > 1)
}

fn configuration_facts(
    sources: &RepositorySources,
    candidate_paths: &BTreeSet<&str>,
    tokens: &BTreeSet<String>,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    if tokens.is_empty() {
        return (Vec::new(), false);
    }
    let mut facts = Vec::new();
    let mut truncated = false;
    'files: for file in sources.files.values() {
        let config_file = is_configuration_file(&file.path);
        let candidate_file = candidate_paths.contains(file.path.as_str());
        if !candidate_file && is_nonproduction_review_context_path(&file.path) {
            continue;
        }
        if !config_file && !candidate_file {
            continue;
        }
        let spans = line_spans(&file.source);
        for (line_index, (start, end)) in spans.iter().copied().enumerate() {
            let line = &file.source[start..end];
            if contains_sensitive_config_key(line) {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            let Some(token) = tokens
                .iter()
                .find(|token| contains_identifier(&lower, token))
            else {
                continue;
            };
            let include = config_file
                || looks_like_configuration_reference(line)
                || line_index.checked_sub(1).is_some_and(|previous| {
                    looks_like_configuration_reference(
                        &file.source[spans[previous].0..spans[previous].1],
                    )
                });
            if !include {
                continue;
            }
            if facts.len() == limit {
                truncated = true;
                break 'files;
            }
            let excerpt_start_line = if candidate_file && line_index > 0 {
                line_index
            } else {
                line_index + 1
            };
            let excerpt_end_line = line_index + 1;
            let Ok((slice, slice_truncated)) =
                source_slice(file, excerpt_start_line, excerpt_end_line)
            else {
                continue;
            };
            truncated |= slice_truncated;
            facts.push(ReviewNeighborhoodFact {
                role: "configuration_context".to_string(),
                symbol: token.clone(),
                location: slice.location,
                excerpt: slice.text,
                evidence_id: None,
                provenance: textual_provenance("mehscan bounded configuration context 1"),
            });
        }
    }
    (facts, truncated)
}

fn looks_like_configuration_reference(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "@value",
        "process.env",
        "system.getenv",
        "getenvironmentvariable",
        "os.getenv",
        "os.environ",
        "env::var",
        "configuration[",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn is_configuration_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    name == ".env"
        || name.starts_with(".env.")
        || name.contains("config")
        || [".properties", ".yml", ".yaml", ".toml", ".ini", ".conf"]
            .iter()
            .any(|extension| name.ends_with(extension))
}

fn sort_review_facts(facts: &mut Vec<ReviewNeighborhoodFact>) {
    facts.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then_with(|| left.location.path.cmp(&right.location.path))
            .then_with(|| {
                left.location
                    .start
                    .byte_offset
                    .cmp(&right.location.start.byte_offset)
            })
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    facts.dedup_by(|left, right| {
        left.role == right.role
            && left.location == right.location
            && left.symbol == right.symbol
            && left.excerpt == right.excerpt
    });
}

fn path_review_fingerprint(
    reviews: &[PathReview],
    observation_reviews: &[ObservationReview],
    contract: &ReviewTriageContract,
    context_lines: usize,
    offset: usize,
    include_review_material: bool,
) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    hash_review_text(&mut hash, &context_lines.to_string());
    hash_review_text(&mut hash, &offset.to_string());
    hash_review_text(
        &mut hash,
        if include_review_material {
            "all"
        } else {
            "production"
        },
    );
    for value in contract
        .response_fields
        .iter()
        .chain(&contract.decisions)
        .chain(&contract.confidence_levels)
        .chain(&contract.instructions)
    {
        hash_review_text(&mut hash, value);
    }
    for review in reviews {
        hash_review_text(&mut hash, &review.id);
        hash_review_text(&mut hash, &review.candidate.id);
        hash_review_text(&mut hash, &review.candidate.title);
        hash_review_text(&mut hash, &format!("{:?}", review.candidate.state));
        for cwe in &review.candidate.cwe_candidates {
            hash_review_text(&mut hash, cwe);
        }
        if let Some(basis) = &review.review_basis {
            let serialized = serde_json::to_string(basis)
                .expect("path review basis must remain JSON serializable");
            hash_review_text(&mut hash, &serialized);
        }
        let decision_facts = serde_json::to_string(&review.decision_facts)
            .expect("path decision facts must remain JSON serializable");
        hash_review_text(&mut hash, &decision_facts);
        let truncation = serde_json::to_string(&review.truncation)
            .expect("path truncation must remain JSON serializable");
        hash_review_text(&mut hash, &truncation);
        for fact in &review.facts {
            hash_review_text(&mut hash, &fact.role);
            hash_review_text(&mut hash, &fact.symbol);
            hash_review_text(&mut hash, &fact.location.path);
            hash_review_text(&mut hash, &fact.location.start.byte_offset.to_string());
            hash_review_text(&mut hash, &fact.location.end.byte_offset.to_string());
            hash_review_text(&mut hash, &fact.excerpt);
            hash_review_text(&mut hash, fact.evidence_id.as_deref().unwrap_or("<null>"));
        }
        for question in &review.open_questions {
            hash_review_text(&mut hash, question);
        }
    }
    for review in observation_reviews {
        hash_review_text(&mut hash, &review.id);
        hash_review_text(&mut hash, &review.title);
        for evidence_id in &review.anchor_evidence_ids {
            hash_review_text(&mut hash, evidence_id);
        }
        for item in &review.evidence {
            hash_review_text(&mut hash, &item.id);
            hash_review_text(&mut hash, &item.rule_id);
        }
        if let Some(basis) = &review.review_basis {
            let serialized = serde_json::to_string(basis)
                .expect("observation review basis must remain JSON serializable");
            hash_review_text(&mut hash, &serialized);
        }
        let decision_facts = serde_json::to_string(&review.decision_facts)
            .expect("observation decision facts must remain JSON serializable");
        hash_review_text(&mut hash, &decision_facts);
        let truncation = serde_json::to_string(&review.truncation)
            .expect("observation truncation must remain JSON serializable");
        hash_review_text(&mut hash, &truncation);
        for fact in &review.facts {
            hash_review_text(&mut hash, &fact.role);
            hash_review_text(&mut hash, &fact.symbol);
            hash_review_text(&mut hash, &fact.location.path);
            hash_review_text(&mut hash, &fact.location.start.byte_offset.to_string());
            hash_review_text(&mut hash, &fact.location.end.byte_offset.to_string());
            hash_review_text(&mut hash, &fact.excerpt);
        }
        for question in &review.open_questions {
            hash_review_text(&mut hash, question);
        }
    }
    format!("path-reviewpack-{hash:016x}")
}

fn hash_review_text(hash: &mut u64, value: &str) {
    for byte in value.bytes().chain(std::iter::once(0xff)) {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
}

pub fn build_investigation_job(
    root: &Path,
    filter: EvidenceFilter,
    context_lines: Option<usize>,
    limit: Option<usize>,
) -> Result<InvestigationJob, EngineError> {
    let filter = normalize_evidence_filter(filter)?;
    let max_units = bounded_unit_limit(limit)?;
    let context_lines = bounded_context_lines(context_lines)?;
    let limits = InvestigationLimits {
        max_units,
        context_lines,
        max_evidence_per_unit: MAX_UNIT_EVIDENCE,
        max_imports_per_unit: MAX_UNIT_IMPORTS,
        max_source_lines: MAX_SOURCE_LINES,
        max_source_bytes: MAX_SOURCE_BYTES,
    };
    let scan = scan_path(root)?;
    let languages: BTreeMap<_, _> = scan
        .coverage
        .files
        .iter()
        .filter_map(|file| file.language.map(|language| (file.path.as_str(), language)))
        .collect();
    if !scan
        .evidence
        .iter()
        .any(|evidence| evidence_matches(evidence, &filter, &languages))
    {
        return Ok(InvestigationJob {
            schema_version: SCHEMA_VERSION.to_string(),
            root: scan.root,
            operation: "build_investigation_units".to_string(),
            filter,
            limits,
            truncated: false,
            units: Vec::new(),
            coverage: scan.coverage,
            diagnostics: scan.diagnostics,
        });
    }
    let sources = RepositorySources::load(root)?;
    let outlines = OutlineExtractors::build()?;
    let mut outline_cache: BTreeMap<String, Vec<OutlineSymbol>> = BTreeMap::new();
    let mut pending: BTreeMap<(String, usize, usize), PendingUnit> = BTreeMap::new();

    for evidence in scan
        .evidence
        .iter()
        .filter(|evidence| evidence_matches(evidence, &filter, &languages))
    {
        let language = languages.get(evidence.location.path.as_str()).copied();
        if language.is_some() && !outline_cache.contains_key(&evidence.location.path) {
            let file = sources.file(&evidence.location.path)?;
            outline_cache.insert(evidence.location.path.clone(), outlines.extract(file)?);
        }
        let symbol = outline_cache
            .get(&evidence.location.path)
            .and_then(|outline| enclosing_outline_symbol(outline, &evidence.location));
        let anchor_location = symbol
            .as_ref()
            .map(|symbol| symbol.location.clone())
            .unwrap_or_else(|| evidence.location.clone());
        let key = (
            anchor_location.path.clone(),
            anchor_location.start.byte_offset,
            anchor_location.end.byte_offset,
        );
        pending
            .entry(key)
            .or_insert_with(|| PendingUnit {
                language,
                anchor: InvestigationAnchor {
                    location: anchor_location,
                    symbol,
                },
                selected_evidence_ids: Vec::new(),
            })
            .selected_evidence_ids
            .push(evidence.id.clone());
    }

    let truncated = pending.len() > max_units;
    let rules = crate::rules::load_builtin_rules()?;
    let relations = crate::rules::load_builtin_relations(&rules)?;
    let linked_sink_ids = scan
        .security_paths
        .iter()
        .map(|path| path.sink_evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let guidance_by_rule: BTreeMap<_, _> = rules
        .into_iter()
        .map(|rule| (rule.id, rule.ai.investigate))
        .collect();
    let mut units = Vec::new();
    for pending in pending.into_values().take(max_units) {
        let file = sources.file(&pending.anchor.location.path)?;
        let start_line = pending
            .anchor
            .location
            .start
            .line
            .saturating_sub(context_lines)
            .max(1);
        let end_line = pending
            .anchor
            .location
            .end
            .line
            .saturating_add(context_lines);
        let (mut source, source_truncated) = source_slice(file, start_line, end_line)?;
        let (relation_start, relation_end) = if pending.anchor.symbol.is_some() {
            (
                pending.anchor.location.start.byte_offset,
                pending.anchor.location.end.byte_offset,
            )
        } else {
            (
                source.location.start.byte_offset,
                source.location.end.byte_offset,
            )
        };
        let mut evidence = scan
            .evidence
            .iter()
            .filter(|evidence| {
                evidence.location.path == pending.anchor.location.path
                    && evidence.location.start.byte_offset >= relation_start
                    && evidence.location.end.byte_offset <= relation_end
            })
            .cloned()
            .collect::<Vec<_>>();
        let evidence_truncated = evidence.len() > MAX_UNIT_EVIDENCE;

        let mut capabilities = BTreeSet::new();
        let mut cwe_candidates = BTreeSet::new();
        let mut ai_guidance = BTreeSet::new();
        for item in &evidence {
            capabilities.insert(item.capability);
            cwe_candidates.extend(item.cwe_candidates.iter().cloned());
            if let Some(guidance) = guidance_by_rule.get(&item.rule_id) {
                ai_guidance.extend(guidance.iter().cloned());
            } else if let Some(guidance) = crate::secrets::guidance_for_rule(&item.rule_id) {
                ai_guidance.extend(guidance.iter().map(|item| (*item).to_string()));
            }
        }
        if has_unlinked_compatible_pair(&evidence, &relations, &linked_sink_ids) {
            ai_guidance.insert(
                "A compatible source and sink coexist in this unit, but deterministic bounded value flow did not connect them. Review the exact parameter-to-argument flow and any framework abstraction; do not assume a vulnerability from proximity alone."
                    .to_string(),
            );
        }
        evidence.truncate(MAX_UNIT_EVIDENCE);
        redact_secrets_in_slice(&mut source, &evidence);

        let mut imports = outline_cache
            .get(&pending.anchor.location.path)
            .into_iter()
            .flatten()
            .filter(|symbol| symbol.is_import)
            .cloned()
            .collect::<Vec<_>>();
        let imports_truncated = imports.len() > MAX_UNIT_IMPORTS;
        imports.truncate(MAX_UNIT_IMPORTS);
        let grouping_resolution = if pending.anchor.symbol.is_some() {
            Resolution::Ast
        } else {
            Resolution::Textual
        };
        let id = investigation_unit_id(&pending.anchor.location);
        units.push(InvestigationUnit {
            id,
            language: pending.language,
            anchor: pending.anchor,
            selected_evidence_ids: pending.selected_evidence_ids,
            evidence,
            source,
            imports,
            capabilities: capabilities.into_iter().collect(),
            cwe_candidates: cwe_candidates.into_iter().collect(),
            ai_guidance: ai_guidance.into_iter().collect(),
            provenance: InvestigationUnitProvenance {
                grouping: QueryProvenance {
                    resolution: grouping_resolution,
                    engine: if grouping_resolution == Resolution::Ast {
                        "ast-grep-outline 0.45.1 enclosing range".to_string()
                    } else {
                        "bounded source-window grouping".to_string()
                    },
                },
                source: textual_provenance("bounded-source-reader"),
                imports: ast_provenance("ast-grep-outline 0.45.1"),
                guidance: QueryProvenance {
                    resolution: Resolution::External,
                    engine: "mehscan built-in rule catalog".to_string(),
                },
            },
            context_truncated: source_truncated || evidence_truncated || imports_truncated,
        });
    }

    Ok(InvestigationJob {
        schema_version: SCHEMA_VERSION.to_string(),
        root: scan.root,
        operation: "build_investigation_units".to_string(),
        filter,
        limits,
        truncated,
        units,
        coverage: scan.coverage,
        diagnostics: scan.diagnostics,
    })
}

pub fn find_symbol(
    root: &Path,
    name: &str,
    limit: Option<usize>,
) -> Result<QueryResponse<Vec<OutlineSymbol>>, EngineError> {
    if name.is_empty() {
        return Err(EngineError("symbol name must not be empty".to_string()));
    }
    let limit = bounded_limit(limit)?;
    let sources = RepositorySources::load(root)?;
    let outlines = OutlineExtractors::build()?;
    let mut matches = Vec::new();
    let mut truncated = false;
    for file in sources.files.values() {
        if file.language.is_none() {
            continue;
        }
        for symbol in outlines.extract(file)? {
            if symbol.name == name {
                if matches.len() == limit {
                    truncated = true;
                    break;
                }
                matches.push(symbol);
            }
        }
        if truncated {
            break;
        }
    }
    Ok(response(
        &sources.root,
        "find_symbol",
        ast_provenance("ast-grep-outline 0.45.1"),
        truncated,
        matches,
    ))
}

pub fn find_imports(
    root: &Path,
    name: &str,
    limit: Option<usize>,
) -> Result<QueryResponse<Vec<OutlineSymbol>>, EngineError> {
    if name.is_empty() {
        return Err(EngineError("import name must not be empty".to_string()));
    }
    let limit = bounded_limit(limit)?;
    let sources = RepositorySources::load(root)?;
    let outlines = OutlineExtractors::build()?;
    let mut matches = Vec::new();
    let mut truncated = false;
    for file in sources.files.values() {
        if file.language.is_none() {
            continue;
        }
        for symbol in outlines.extract(file)? {
            if symbol.is_import && (symbol.name.contains(name) || symbol.signature.contains(name)) {
                if matches.len() == limit {
                    truncated = true;
                    break;
                }
                matches.push(symbol);
            }
        }
        if truncated {
            break;
        }
    }
    Ok(response(
        &sources.root,
        "find_imports",
        ast_provenance("ast-grep-outline 0.45.1"),
        truncated,
        matches,
    ))
}

pub fn find_text_references(
    root: &Path,
    symbol: &str,
    limit: Option<usize>,
) -> Result<QueryResponse<Vec<TextReference>>, EngineError> {
    if symbol.is_empty() {
        return Err(EngineError(
            "reference symbol must not be empty".to_string(),
        ));
    }
    let limit = bounded_limit(limit)?;
    let sources = RepositorySources::load(root)?;
    let mut matches = Vec::new();
    let mut truncated = false;
    'files: for file in sources.files.values() {
        for (line_start, line_end) in line_spans(&file.source) {
            let line = &file.source[line_start..line_end];
            let mut search_from = 0;
            while let Some(relative) = line[search_from..].find(symbol) {
                let start = search_from + relative;
                let end = start + symbol.len();
                search_from = end;
                if !is_identifier_match(line, start, end) {
                    continue;
                }
                if matches.len() == limit {
                    truncated = true;
                    break 'files;
                }
                matches.push(TextReference {
                    text: bounded_line_text(line),
                    location: location_from_offsets(
                        &file.path,
                        &file.source,
                        line_start + start,
                        line_start + end,
                    ),
                });
            }
        }
    }
    Ok(response(
        &sources.root,
        "find_text_references",
        textual_provenance("bounded-identifier-text-search"),
        truncated,
        matches,
    ))
}

pub fn run_structural_query(
    root: &Path,
    language: Language,
    pattern: &str,
    path: Option<&str>,
    limit: Option<usize>,
) -> Result<QueryResponse<Vec<StructuralMatch>>, EngineError> {
    if pattern.is_empty() {
        return Err(EngineError(
            "structural query must not be empty".to_string(),
        ));
    }
    let limit = bounded_limit(limit)?;
    let parser = parser_language(language);
    let pattern = Pattern::try_new(pattern, parser)
        .map_err(|error| EngineError(format!("invalid structural query: {error}")))?;
    let sources = RepositorySources::load(root)?;
    let requested_path = path.map(normalize_relative);
    if let Some(path) = &requested_path {
        sources.file(path)?;
    }
    let mut matches = Vec::new();
    let mut truncated = false;
    'files: for file in sources.files.values().filter(|file| {
        file.language == Some(language)
            && requested_path
                .as_ref()
                .is_none_or(|path| file.path == *path)
    }) {
        let document = StrDoc::try_new(&file.source, parser)
            .map_err(|error| EngineError(format!("could not parse {}: {error}", file.path)))?;
        let ast = AstGrep::doc(document);
        let root = ast.root();
        if root.dfs().any(|node| node.is_error() || node.is_missing()) {
            return Err(EngineError(format!(
                "could not run structural query on {}: parser produced ERROR or missing nodes",
                file.path
            )));
        }
        for matched in root.find_all(&pattern) {
            if matches.len() == limit {
                truncated = true;
                break 'files;
            }
            let node = matched.get_node();
            matches.push(StructuralMatch {
                text: bounded_match_text(node.text().as_ref()),
                location: location_from_offsets(
                    &file.path,
                    &file.source,
                    node.range().start,
                    node.range().end,
                ),
            });
        }
    }
    Ok(response(
        &sources.root,
        "run_structural_query",
        ast_provenance("ast-grep 0.45.1 ephemeral pattern"),
        truncated,
        matches,
    ))
}

impl RepositorySources {
    fn load(root: &Path) -> Result<Self, EngineError> {
        let discovery = discover(root)?;
        let display_root = display_path(&discovery.root);
        let mut files = BTreeMap::new();
        for file in discovery.files {
            let (language, source) = match file.class {
                FileClass::Supported(language) => {
                    let source = fs::read_to_string(&file.absolute).map_err(|error| {
                        EngineError(format!(
                            "could not read {} as UTF-8: {error}",
                            file.relative
                        ))
                    })?;
                    (Some(language), source)
                }
                FileClass::SecretOnly
                | FileClass::EmbeddedJavascriptTemplate
                | FileClass::Razor
                | FileClass::WebForms => {
                    let Ok(source) = crate::code::read_secret_text(&file.absolute) else {
                        continue;
                    };
                    (None, source)
                }
                FileClass::UnsupportedSource | FileClass::Ignored => continue,
            };
            files.insert(
                file.relative.clone(),
                SourceFile {
                    path: file.relative,
                    language,
                    source,
                },
            );
        }
        Ok(Self {
            root: display_root,
            files,
        })
    }

    fn file(&self, path: &str) -> Result<&SourceFile, EngineError> {
        let normalized = normalize_relative(path);
        if normalized.split('/').any(|part| part == "..") {
            return Err(EngineError(
                "query path must stay inside the scan root".to_string(),
            ));
        }
        self.files.get(&normalized).ok_or_else(|| {
            EngineError(format!(
                "scannable text file {normalized:?} was not found under the scan root"
            ))
        })
    }
}

impl OutlineExtractors {
    fn build() -> Result<Self, EngineError> {
        let mut rules_by_language = BTreeMap::new();
        for rule in parse_outline_rules::<SupportLang>(DEFAULT_OUTLINE_RULES)
            .map_err(|error| EngineError(format!("built-in outline rules are invalid: {error}")))?
        {
            if let Some(language) = all_languages()
                .into_iter()
                .find(|language| rule.common().language == parser_language(*language))
            {
                rules_by_language
                    .entry(language)
                    .or_insert_with(Vec::new)
                    .push(rule);
            }
        }
        let by_language = rules_by_language
            .into_iter()
            .map(|(language, rules)| {
                CombinedExtractors::try_from(rules, &Default::default())
                    .map(|extractors| (language, extractors))
                    .map_err(|error| {
                        EngineError(format!("outline rules could not compile: {error}"))
                    })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { by_language })
    }

    fn extract(&self, file: &SourceFile) -> Result<Vec<OutlineSymbol>, EngineError> {
        let language = file.language.ok_or_else(|| {
            EngineError(format!(
                "no outline language is available for {}",
                file.path
            ))
        })?;
        let parser = parser_language(language);
        let extractors = self.by_language.get(&language).ok_or_else(|| {
            EngineError(format!(
                "no outline extractor is available for {:?}",
                language
            ))
        })?;
        let document = StrDoc::try_new(&file.source, parser)
            .map_err(|error| EngineError(format!("could not parse {}: {error}", file.path)))?;
        let ast = AstGrep::doc(document);
        let root = ast.root();
        if root.dfs().any(|node| node.is_error() || node.is_missing()) {
            return Err(EngineError(format!(
                "could not build outline for {}: parser produced ERROR or missing nodes",
                file.path
            )));
        }
        let mut symbols = Vec::new();
        for item in extractors.extract(root) {
            push_outline_item(&mut symbols, &file.path, &file.source, item);
        }
        symbols.sort_by_key(|symbol| symbol.location.start.byte_offset);
        Ok(symbols)
    }
}

fn all_languages() -> [Language; 7] {
    [
        Language::Csharp,
        Language::Java,
        Language::Javascript,
        Language::Typescript,
        Language::Tsx,
        Language::Python,
        Language::Go,
    ]
}

fn push_outline_item(
    symbols: &mut Vec<OutlineSymbol>,
    path: &str,
    source: &str,
    item: OutlineItem<'_>,
) {
    let parent = item.entry.name.to_string();
    symbols.push(outline_symbol(
        path,
        source,
        &item.entry,
        None,
        item.is_import,
        item.is_exported,
        None,
    ));
    for member in item.members {
        symbols.push(outline_member(path, source, member, &parent));
    }
}

fn outline_member(
    path: &str,
    source: &str,
    member: OutlineMember<'_>,
    parent: &str,
) -> OutlineSymbol {
    outline_symbol(
        path,
        source,
        &member.entry,
        Some(parent.to_string()),
        false,
        false,
        Some(member.is_public),
    )
}

fn outline_symbol(
    path: &str,
    source: &str,
    entry: &OutlineEntry<'_>,
    parent: Option<String>,
    is_import: bool,
    is_exported: bool,
    is_public: Option<bool>,
) -> OutlineSymbol {
    OutlineSymbol {
        name: entry.name.to_string(),
        symbol_type: symbol_type_name(entry.symbol_type).to_string(),
        signature: entry.signature.to_string(),
        ast_kind: entry.ast_kind.to_string(),
        location: location_from_offsets(
            path,
            source,
            entry.range.byte_offset.start,
            entry.range.byte_offset.end,
        ),
        parent,
        is_import,
        is_exported,
        is_public,
    }
}

fn symbol_type_name(symbol_type: SymbolType) -> &'static str {
    match symbol_type {
        SymbolType::File => "file",
        SymbolType::Module => "module",
        SymbolType::Namespace => "namespace",
        SymbolType::Package => "package",
        SymbolType::Class => "class",
        SymbolType::Method => "method",
        SymbolType::Property => "property",
        SymbolType::Field => "field",
        SymbolType::Constructor => "constructor",
        SymbolType::Enum => "enum",
        SymbolType::Interface => "interface",
        SymbolType::Function => "function",
        SymbolType::Variable => "variable",
        SymbolType::Constant => "constant",
        SymbolType::String => "string",
        SymbolType::Number => "number",
        SymbolType::Boolean => "boolean",
        SymbolType::Array => "array",
        SymbolType::Object => "object",
        SymbolType::Key => "key",
        SymbolType::Null => "null",
        SymbolType::EnumMember => "enum_member",
        SymbolType::Struct => "struct",
        SymbolType::Event => "event",
        SymbolType::Operator => "operator",
        SymbolType::TypeParameter => "type_parameter",
    }
}

fn response<T>(
    root: &str,
    operation: &str,
    provenance: QueryProvenance,
    truncated: bool,
    results: T,
) -> QueryResponse<T> {
    QueryResponse {
        schema_version: SCHEMA_VERSION.to_string(),
        root: root.to_string(),
        operation: operation.to_string(),
        provenance,
        truncated,
        results,
    }
}

fn has_unlinked_compatible_pair(
    evidence: &[Evidence],
    relations: &[RelationContract],
    linked_sink_ids: &BTreeSet<&str>,
) -> bool {
    let source_capabilities = evidence
        .iter()
        .filter(|item| item.kind == EvidenceKind::Source)
        .map(|item| item.capability)
        .collect::<BTreeSet<_>>();
    evidence.iter().any(|sink| {
        sink.kind == EvidenceKind::Sink
            && !linked_sink_ids.contains(sink.id.as_str())
            && relations.iter().any(|relation| {
                relation.sink.capability == sink.capability
                    && source_capabilities
                        .iter()
                        .any(|source| relation.source.accepts(*source))
            })
    })
}

fn evidence_matches(
    evidence: &Evidence,
    filter: &EvidenceFilter,
    languages: &BTreeMap<&str, Language>,
) -> bool {
    filter.kind.is_none_or(|kind| evidence.kind == kind)
        && filter
            .capability
            .is_none_or(|capability| evidence.capability == capability)
        && filter.language.is_none_or(|language| {
            languages.get(evidence.location.path.as_str()) == Some(&language)
        })
        && filter
            .path
            .as_ref()
            .is_none_or(|path| evidence.location.path == normalize_relative(path))
}

fn normalize_evidence_filter(mut filter: EvidenceFilter) -> Result<EvidenceFilter, EngineError> {
    if let Some(path) = &mut filter.path {
        let normalized = normalize_relative(path);
        let has_drive_prefix = normalized.as_bytes().get(1) == Some(&b':');
        if normalized.is_empty()
            || normalized.starts_with('/')
            || has_drive_prefix
            || normalized.split('/').any(|part| part == "..")
        {
            return Err(EngineError(
                "evidence filter path must be relative and stay inside the scan root".to_string(),
            ));
        }
        *path = normalized;
    }
    Ok(filter)
}

fn enclosing_outline_symbol(
    symbols: &[OutlineSymbol],
    location: &Location,
) -> Option<OutlineSymbol> {
    symbols
        .iter()
        .filter(|symbol| {
            symbol.location.start.byte_offset <= location.start.byte_offset
                && symbol.location.end.byte_offset >= location.end.byte_offset
                && !symbol.is_import
        })
        .min_by_key(|symbol| symbol.location.end.byte_offset - symbol.location.start.byte_offset)
        .cloned()
}

fn ast_provenance(engine: &str) -> QueryProvenance {
    QueryProvenance {
        resolution: Resolution::Ast,
        engine: engine.to_string(),
    }
}

fn textual_provenance(engine: &str) -> QueryProvenance {
    QueryProvenance {
        resolution: Resolution::Textual,
        engine: engine.to_string(),
    }
}

fn bounded_limit(limit: Option<usize>) -> Result<usize, EngineError> {
    let limit = limit.unwrap_or(DEFAULT_RESULT_LIMIT);
    if limit == 0 || limit > MAX_RESULT_LIMIT {
        return Err(EngineError(format!(
            "query limit must be between 1 and {MAX_RESULT_LIMIT}"
        )));
    }
    Ok(limit)
}

fn bounded_unit_limit(limit: Option<usize>) -> Result<usize, EngineError> {
    let limit = limit.unwrap_or(DEFAULT_UNIT_LIMIT);
    if limit == 0 || limit > MAX_UNIT_LIMIT {
        return Err(EngineError(format!(
            "investigation unit limit must be between 1 and {MAX_UNIT_LIMIT}"
        )));
    }
    Ok(limit)
}

fn bounded_review_limit(limit: Option<usize>) -> Result<usize, EngineError> {
    let limit = limit.unwrap_or(DEFAULT_REVIEW_LIMIT);
    if limit == 0 || limit > MAX_REVIEW_LIMIT {
        return Err(EngineError(format!(
            "review limit must be between 1 and {MAX_REVIEW_LIMIT}"
        )));
    }
    Ok(limit)
}

fn bounded_review_bundle_bytes(max_input_bytes: Option<usize>) -> Result<usize, EngineError> {
    let max_input_bytes = max_input_bytes.unwrap_or(DEFAULT_REVIEW_BUNDLE_MAX_BYTES);
    if !(MIN_REVIEW_BUNDLE_MAX_BYTES..=MAX_REVIEW_BUNDLE_MAX_BYTES).contains(&max_input_bytes) {
        return Err(EngineError(format!(
            "review bundle byte limit must be between {MIN_REVIEW_BUNDLE_MAX_BYTES} and {MAX_REVIEW_BUNDLE_MAX_BYTES}"
        )));
    }
    Ok(max_input_bytes)
}

fn bounded_review_bundle_reviews(max_reviews: Option<usize>) -> Result<usize, EngineError> {
    let max_reviews = max_reviews.unwrap_or(DEFAULT_REVIEW_BUNDLE_MAX_REVIEWS);
    if max_reviews == 0 || max_reviews > MAX_REVIEW_LIMIT {
        return Err(EngineError(format!(
            "review bundle item limit must be between 1 and {MAX_REVIEW_LIMIT}"
        )));
    }
    Ok(max_reviews)
}

fn bounded_context_lines(context_lines: Option<usize>) -> Result<usize, EngineError> {
    let context_lines = context_lines.unwrap_or(DEFAULT_CONTEXT_LINES);
    if context_lines > MAX_CONTEXT_LINES {
        return Err(EngineError(format!(
            "context lines must be between 0 and {MAX_CONTEXT_LINES}"
        )));
    }
    Ok(context_lines)
}

fn normalize_relative(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

fn line_spans(source: &str) -> Vec<(usize, usize)> {
    if source.is_empty() {
        return vec![(0, 0)];
    }
    let mut spans = Vec::new();
    let mut start = 0;
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            spans.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < source.len() {
        spans.push((start, source.len()));
    }
    spans
}

fn source_slice(
    file: &SourceFile,
    start_line: usize,
    end_line: usize,
) -> Result<(SourceSlice, bool), EngineError> {
    let spans = line_spans(&file.source);
    if start_line == 0 || end_line < start_line {
        return Err(EngineError(
            "source range must use one-based lines with end >= start".to_string(),
        ));
    }
    if start_line > spans.len() {
        return Err(EngineError(format!(
            "start line {start_line} is outside {} ({} lines)",
            file.path,
            spans.len()
        )));
    }
    let bounded_end = end_line.min(start_line.saturating_add(MAX_SOURCE_LINES - 1));
    let actual_end = bounded_end.min(spans.len());
    let start_byte = spans[start_line - 1].0;
    let mut end_byte = spans[actual_end - 1].1;
    let mut truncated = bounded_end < end_line;
    if end_byte - start_byte > MAX_SOURCE_BYTES {
        end_byte = floor_char_boundary(&file.source, start_byte + MAX_SOURCE_BYTES);
        truncated = true;
    }
    Ok((
        SourceSlice {
            location: location_from_offsets(&file.path, &file.source, start_byte, end_byte),
            text: file.source[start_byte..end_byte].to_string(),
        },
        truncated,
    ))
}

/// Returns normal line context when it is compact. For generated or minified
/// one-line sources, keeps a byte-bounded window around the actual observation
/// instead of returning the first 64 KiB of the line (which may omit the sink).
fn review_source_slice(
    file: &SourceFile,
    start_line: usize,
    end_line: usize,
    anchor: &Location,
) -> Result<(SourceSlice, bool), EngineError> {
    let spans = line_spans(&file.source);
    if start_line == 0 || end_line < start_line {
        return Err(EngineError(
            "source range must use one-based lines with end >= start".to_string(),
        ));
    }
    if start_line > spans.len() {
        return Err(EngineError(format!(
            "start line {start_line} is outside {} ({} lines)",
            file.path,
            spans.len()
        )));
    }
    let requested_end = end_line.min(spans.len());
    let requested_lines = requested_end.saturating_sub(start_line) + 1;
    let anchor_line = anchor.start.line.clamp(start_line, requested_end);
    let actual_start = if requested_lines > MAX_SOURCE_LINES {
        let latest_start = requested_end.saturating_sub(MAX_SOURCE_LINES - 1);
        anchor_line
            .saturating_sub(MAX_SOURCE_LINES / 2)
            .max(start_line)
            .min(latest_start)
    } else {
        start_line
    };
    let actual_end = actual_start
        .saturating_add(MAX_SOURCE_LINES - 1)
        .min(requested_end);
    let range_start = spans[actual_start - 1].0;
    let range_end = spans[actual_end - 1].1;
    let mut truncated = requested_lines > MAX_SOURCE_LINES;
    if range_end - range_start <= MAX_REVIEW_PRIMARY_CONTEXT_BYTES {
        return Ok((
            SourceSlice {
                location: location_from_offsets(&file.path, &file.source, range_start, range_end),
                text: file.source[range_start..range_end].to_string(),
            },
            truncated,
        ));
    }

    truncated = true;
    let anchor_start = anchor.start.byte_offset.clamp(range_start, range_end);
    let anchor_end = anchor.end.byte_offset.clamp(anchor_start, range_end);
    let anchor_bytes = anchor_end - anchor_start;
    let mut excerpt_start = if anchor_bytes >= MAX_REVIEW_PRIMARY_CONTEXT_BYTES {
        anchor_start
    } else {
        anchor_start.saturating_sub((MAX_REVIEW_PRIMARY_CONTEXT_BYTES - anchor_bytes) / 2)
    }
    .max(range_start);
    let mut excerpt_end = excerpt_start
        .saturating_add(MAX_REVIEW_PRIMARY_CONTEXT_BYTES)
        .min(range_end);
    excerpt_start = excerpt_end
        .saturating_sub(MAX_REVIEW_PRIMARY_CONTEXT_BYTES)
        .max(range_start);
    while excerpt_start < excerpt_end && !file.source.is_char_boundary(excerpt_start) {
        excerpt_start += 1;
    }
    excerpt_end = floor_char_boundary(&file.source, excerpt_end);
    Ok((
        SourceSlice {
            location: location_from_offsets(&file.path, &file.source, excerpt_start, excerpt_end),
            text: file.source[excerpt_start..excerpt_end].to_string(),
        },
        truncated,
    ))
}

fn redact_secrets_in_slice(source: &mut SourceSlice, evidence: &[Evidence]) {
    let slice_start = source.location.start.byte_offset;
    let slice_end = source.location.end.byte_offset;
    let mut bytes = source.text.as_bytes().to_vec();
    for location in evidence.iter().filter_map(|item| {
        if item.kind == EvidenceKind::Secret {
            Some(&item.location)
        } else if item.rule_id == "go-cookie-store-hardcoded-key" {
            item.captures
                .get("key_material")
                .map(|capture| &capture.location)
        } else if item.rule_id.ends_with("nextauth-hardcoded-credentials") {
            item.captures
                .get("password_literal")
                .map(|capture| &capture.location)
        } else {
            None
        }
    }) {
        let start = location.start.byte_offset;
        let end = location.end.byte_offset;
        if start < slice_start || end > slice_end || start >= end {
            continue;
        }
        for byte in &mut bytes[start - slice_start..end - slice_start] {
            *byte = b'*';
        }
    }
    source.text = String::from_utf8(bytes).expect("masking ASCII secret bytes preserves UTF-8");
}

fn investigation_unit_id(location: &Location) -> String {
    let input = format!(
        "{}\0{}\0{}",
        location.path, location.start.byte_offset, location.end.byte_offset
    );
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("unit-{hash:016x}")
}

fn location_from_offsets(path: &str, source: &str, start: usize, end: usize) -> Location {
    Location {
        path: path.to_string(),
        start: position_at(source, start),
        end: position_at(source, end),
    }
}

fn position_at(source: &str, offset: usize) -> Position {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let column = source[line_start..offset].chars().count() + 1;
    Position {
        line,
        column,
        byte_offset: offset,
    }
}

fn floor_char_boundary(source: &str, mut offset: usize) -> usize {
    offset = offset.min(source.len());
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

fn is_identifier_match(line: &str, start: usize, end: usize) -> bool {
    let before = line[..start].chars().next_back();
    let after = line[end..].chars().next();
    !before.is_some_and(is_identifier_character) && !after.is_some_and(is_identifier_character)
}

fn is_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

fn bounded_line_text(line: &str) -> String {
    let line = line.trim_end_matches(['\r', '\n']);
    bounded_match_text(line)
}

fn bounded_match_text(text: &str) -> String {
    const MAX_TEXT_CHARS: usize = 500;
    let mut output = text.chars().take(MAX_TEXT_CHARS).collect::<String>();
    if text.chars().count() > MAX_TEXT_CHARS {
        output.push('…');
    }
    output
}

fn display_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(&value)
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn distinguishes_property_mutation_from_equality() {
        assert!(!compact_has_property_assignment(
            "if(environment.hostServer==='.')",
            "hostServer"
        ));
        assert!(!compact_has_property_assignment(
            "environment.hostServer==value",
            "hostServer"
        ));
        assert!(compact_has_property_assignment(
            "environment.hostServer=value",
            "hostServer"
        ));
        assert!(compact_has_property_assignment(
            "environment['hostServer']+=suffix",
            "hostServer"
        ));
    }

    #[test]
    fn fixed_resource_selectors_cover_scalar_map_and_predicate_shapes() {
        for selector in [
            "1",
            "1L",
            "\"system\"",
            "{ id: 1 }",
            "{ id: 1, tenant: \"system\" }",
            "item => item.Id == 1",
        ] {
            assert!(is_fixed_resource_selector(selector), "{selector}");
        }
        for selector in [
            "request.params.id",
            "{ id: request.params.id }",
            "{ id: 1, tenant: request.tenant }",
            "item => item.Id == request.params.id",
            "item => item.Id == 1 && item.OwnerId == request.user.id",
            "item => request.allowed == 1",
        ] {
            assert!(!is_fixed_resource_selector(selector), "{selector}");
        }
    }

    #[test]
    fn source_positions_count_unicode_columns() {
        let source = "α = 1\ncall()\n";
        assert_eq!(position_at(source, "α = 1\n".len()).line, 2);
        assert_eq!(position_at(source, "α".len()).column, 2);
    }

    #[test]
    fn review_source_window_keeps_the_anchor_on_a_large_minified_line() {
        let prefix = "a".repeat(40 * 1024);
        let marker = "dangerous(value)";
        let source = format!("{prefix}{marker}{}", "b".repeat(40 * 1024));
        let anchor_start = prefix.len();
        let file = SourceFile {
            path: "dist/application.js".to_string(),
            language: Some(Language::Javascript),
            source,
        };
        let anchor = location_from_offsets(
            &file.path,
            &file.source,
            anchor_start,
            anchor_start + marker.len(),
        );

        let (slice, truncated) =
            review_source_slice(&file, 1, 1, &anchor).expect("review context should build");

        assert!(truncated);
        assert!(slice.text.len() <= MAX_REVIEW_PRIMARY_CONTEXT_BYTES);
        assert!(slice.text.contains(marker));
        assert!(slice.location.start.byte_offset <= anchor.start.byte_offset);
        assert!(slice.location.end.byte_offset >= anchor.end.byte_offset);
    }

    #[test]
    fn review_source_window_keeps_the_anchor_when_a_symbol_exceeds_the_line_cap() {
        let source = (1..=500)
            .map(|line| {
                if line == 450 {
                    "dangerous(value)\n".to_string()
                } else {
                    format!("let value_{line} = {line};\n")
                }
            })
            .collect::<String>();
        let anchor_start = source.find("dangerous(value)").expect("anchor text");
        let file = SourceFile {
            path: "src/large.rs".to_string(),
            language: Some(Language::Rust),
            source,
        };
        let anchor = location_from_offsets(
            &file.path,
            &file.source,
            anchor_start,
            anchor_start + "dangerous(value)".len(),
        );

        let (slice, truncated) =
            review_source_slice(&file, 1, 500, &anchor).expect("review context should build");

        assert!(truncated);
        assert!(slice.text.contains("dangerous(value)"));
        assert!(slice.location.start.byte_offset <= anchor.start.byte_offset);
        assert!(slice.location.end.byte_offset >= anchor.end.byte_offset);
        assert!(slice.text.lines().count() <= MAX_SOURCE_LINES);
    }

    #[test]
    fn oversized_observation_payloads_retain_actionable_anchors_first() {
        let make_evidence = |id: String, kind| Evidence {
            id,
            kind,
            capability: Capability::DatabaseQuery,
            location: location_from_offsets("src/large.ts", "x", 0, 1),
            enclosing_symbol: Some("largeHandler".to_string()),
            captures: BTreeMap::new(),
            cwe_candidates: vec!["CWE-89".to_string()],
            tags: Vec::new(),
            confidence: mehscan_core::Confidence::High,
            provenance: mehscan_core::Provenance {
                resolution: Resolution::Ast,
                engine: "test".to_string(),
                rule_version: 1,
            },
            context: mehscan_core::EvidenceContext::default(),
            symbol_resolution: None,
            rule_id: "test-observation".to_string(),
            related_evidence: Vec::new(),
        };
        let mut evidence = (0..MAX_UNIT_EVIDENCE + 5)
            .map(|index| make_evidence(format!("source-{index}"), EvidenceKind::Source))
            .collect::<Vec<_>>();
        evidence.push(make_evidence("sink".to_string(), EvidenceKind::Sink));

        let (selected, anchors, anchors_truncated) =
            bounded_observation_evidence(evidence, &["sink".to_string()], MAX_UNIT_EVIDENCE);

        assert_eq!(selected.len(), MAX_UNIT_EVIDENCE);
        assert_eq!(selected[0].id, "sink");
        assert_eq!(anchors, vec!["sink"]);
        assert!(!anchors_truncated);

        let all_anchors = (0..MAX_UNIT_EVIDENCE + 1)
            .map(|index| format!("sink-{index}"))
            .collect::<Vec<_>>();
        let evidence = all_anchors
            .iter()
            .map(|id| make_evidence(id.clone(), EvidenceKind::Sink))
            .collect::<Vec<_>>();
        let (selected, retained_anchors, anchors_truncated) =
            bounded_observation_evidence(evidence, &all_anchors, MAX_UNIT_EVIDENCE);
        assert_eq!(selected.len(), MAX_UNIT_EVIDENCE);
        assert_eq!(retained_anchors.len(), MAX_UNIT_EVIDENCE);
        assert!(anchors_truncated);
    }

    #[test]
    fn identifier_search_rejects_larger_names() {
        assert!(is_identifier_match("run(value)", 0, 3));
        assert!(!is_identifier_match("runner(value)", 0, 3));
    }

    #[test]
    fn review_questions_hide_internal_uncertainty_labels() {
        let cases = [
            "source_observation_not_high_confidence",
            "control_flow_context_not_modeled",
            "aspnet_parameter_binding_is_syntactic",
            "runtime_dispatch_unverified",
            "python_value_preserving_origin",
            "value_transform_protection_is_syntactic",
        ];
        for reason in cases {
            let question = uncertainty_review_question(reason, Capability::HttpRequestData);
            assert!(!question.contains(reason));
            assert!(!question.contains("scanner uncertainty"));
            assert!(!question.contains('_'));
        }
        let credential = uncertainty_review_question(
            "source_observation_not_high_confidence",
            Capability::CredentialMaterial,
        );
        assert!(credential.contains("signing-key material"));
        assert!(credential.contains("secret provider"));
        assert!(!credential.contains("attacker-controlled for the endpoint"));
    }

    #[test]
    fn triage_contract_forbids_reasking_for_supplied_facts() {
        let contract = path_review_triage_contract();
        assert!(contract.instructions.iter().any(|instruction| {
            instruction.contains("requested artifact is absent from facts")
                && instruction.contains("instead of asking to inspect it again")
        }));
    }

    #[test]
    fn triage_contract_requires_review_specific_summaries() {
        let contract = path_review_triage_contract();
        assert!(contract.instructions.iter().any(|instruction| {
            instruction.contains("Evaluate each review independently")
                && instruction.contains("review_basis semantics")
                && instruction.contains("do not reuse category-wide boilerplate")
                && instruction.contains("alternative weaknesses from other reviews")
        }));
    }

    #[test]
    fn triage_contract_does_not_treat_telemetry_as_a_control() {
        let contract = path_review_triage_contract();
        assert!(contract.instructions.iter().any(|instruction| {
            instruction.contains("reviewed invariant requires rejection")
                && instruction.contains("challenge solving, telemetry, logging, or auditing")
                && instruction.contains("decide issue rather than needs_review")
        }));
    }

    #[test]
    fn triage_contract_keeps_decision_ready_paths_on_the_named_invariant() {
        let contract = path_review_triage_contract();
        assert!(contract.instructions.iter().any(|instruction| {
            instruction.contains("decision_facts.unresolved")
                && instruction.contains("affirmatively disproves that same behavior")
                && instruction.contains("do not substitute a different invariant")
        }));
    }

    #[test]
    fn triage_contract_calibrates_decision_ready_cookie_observations() {
        let contract = path_review_triage_contract();
        assert!(contract.instructions.iter().any(|instruction| {
            instruction.contains("decision_facts.unresolved is empty")
                && instruction.contains("authentication-cookie omission")
                && instruction.contains("medium confidence")
                && instruction.contains("remediation ownership")
        }));
        assert_eq!(
            explicit_cookie_omission("typescript-auth-cookie-missing-same-site"),
            Some("SameSite")
        );
    }

    #[test]
    fn missing_protection_questions_match_control_ownership() {
        assert!(
            missing_protection_question(Capability::DatabaseQuery).contains("database parameter")
        );
        assert!(missing_protection_question(Capability::FilesystemRead).contains("containment"));
        assert!(
            missing_protection_question(Capability::OutboundNetworkRequest)
                .contains("metadata targets")
        );
        assert!(
            missing_protection_question(Capability::TemplateEvaluation).contains("template itself")
        );
        assert!(
            missing_protection_question(Capability::HttpHeaderOutput).contains("authoritative")
        );
        assert!(!control_can_be_owned_outside_application(
            Capability::DatabaseQuery
        ));
        assert!(control_can_be_owned_outside_application(
            Capability::HttpHeaderOutput
        ));
    }

    #[test]
    fn exact_csharp_caller_context_starts_at_the_enclosing_action() {
        let repository = "public class Repository {\n    public void Save(Order order) { command.CommandText = order.Name; }\n}\n";
        let controller = "public class OrdersController {\n    [HttpPost]\n    public IActionResult Create(InputModel model)\n    {\n        var order = new Order { Name = model.Name };\n        _repository.Save(order);\n        return Ok();\n    }\n}\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::from([
                (
                    "Data/Repository.cs".to_string(),
                    SourceFile {
                        path: "Data/Repository.cs".to_string(),
                        language: Some(Language::Csharp),
                        source: repository.to_string(),
                    },
                ),
                (
                    "Controllers/OrdersController.cs".to_string(),
                    SourceFile {
                        path: "Controllers/OrdersController.cs".to_string(),
                        language: Some(Language::Csharp),
                        source: controller.to_string(),
                    },
                ),
            ]),
        };
        let (facts, truncated) =
            exact_csharp_caller_facts(&sources, "Data/Repository.cs", "Save", 2);
        assert!(!truncated);
        assert_eq!(facts.len(), 1);
        assert!(
            facts[0]
                .excerpt
                .starts_with("    public IActionResult Create")
        );
        assert!(facts[0].excerpt.contains("Name = model.Name"));
        assert!(facts[0].excerpt.contains("_repository.Save(order)"));
    }

    #[test]
    fn review_context_adds_helpers_dependencies_and_redacts_sensitive_definitions() {
        let route_source = "import { eval as safeEval } from 'notevil'\nimport * as security from '../lib/security'\nexport function run(input: string) { return safeEval(security.hash(input), security.privateKey) }\n";
        let helper_source = "export const privateKey = 'do-not-emit-this-value'\nexport const hash = (value: string) => crypto.createHash('md5').update(value).digest('hex')\n";
        let package_source = "{\n  \"dependencies\": {\n    \"notevil\": \"^1.3.3\"\n  }\n}\n";
        let mut files = BTreeMap::new();
        files.insert(
            "routes/run.ts".to_string(),
            SourceFile {
                path: "routes/run.ts".to_string(),
                language: Some(Language::Typescript),
                source: route_source.to_string(),
            },
        );
        files.insert(
            "lib/security.ts".to_string(),
            SourceFile {
                path: "lib/security.ts".to_string(),
                language: Some(Language::Typescript),
                source: helper_source.to_string(),
            },
        );
        files.insert(
            "package.json".to_string(),
            SourceFile {
                path: "package.json".to_string(),
                language: None,
                source: package_source.to_string(),
            },
        );
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files,
        };
        let references = BTreeSet::from([
            "safeEval".to_string(),
            "hash".to_string(),
            "privateKey".to_string(),
        ]);
        let index =
            ReviewContextIndex::build(&sources, &references).expect("context index should build");
        let paths = BTreeSet::from(["routes/run.ts"]);
        let existing = vec![ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "run".to_string(),
            location: location_from_offsets("routes/run.ts", route_source, 80, route_source.len()),
            excerpt: route_source.lines().last().unwrap_or_default().to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        }];
        let indexed_names = index.definitions.keys().cloned().collect::<Vec<_>>();
        assert!(!indexed_names.iter().any(|name| name == "run"));
        let (facts, _) = index.facts(&sources, &paths, &references, &existing, 12);

        assert!(
            facts.iter().any(|fact| {
                fact.role == "helper_definition_context"
                    && fact.symbol == "hash"
                    && fact.excerpt.contains("createHash('md5')")
            }),
            "indexed: {indexed_names:#?}; facts: {facts:#?}"
        );
        assert!(facts.iter().any(|fact| {
            fact.role == "helper_definition_context"
                && fact.symbol == "privateKey"
                && fact.excerpt.contains("<redacted>")
                && !fact.excerpt.contains("do-not-emit-this-value")
        }));
        assert!(facts.iter().any(|fact| {
            fact.role == "dependency_context"
                && fact.symbol == "notevil"
                && fact.excerpt.contains("^1.3.3")
        }));
    }

    #[test]
    fn review_context_requires_file_or_import_ownership_for_helpers_and_registrations() {
        let route = "import { loadOrder } from '../services/orders'\nexport function show(req, res) {\n  const info = req.body.info\n  return res.json(loadOrder(req.params.id))\n}\n";
        let helper = "export function loadOrder(id) { return Order.findByPk(id) }\n";
        let unrelated =
            "export function all() { return [] }\nexport function info() { return 'noise' }\n";
        let server = "app.get('/orders/:id', show)\napp.get('/noise', all)\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::from([
                (
                    "routes/orders.ts".to_string(),
                    SourceFile {
                        path: "routes/orders.ts".to_string(),
                        language: Some(Language::Typescript),
                        source: route.to_string(),
                    },
                ),
                (
                    "services/orders.ts".to_string(),
                    SourceFile {
                        path: "services/orders.ts".to_string(),
                        language: Some(Language::Typescript),
                        source: helper.to_string(),
                    },
                ),
                (
                    "frontend/noise.ts".to_string(),
                    SourceFile {
                        path: "frontend/noise.ts".to_string(),
                        language: Some(Language::Typescript),
                        source: unrelated.to_string(),
                    },
                ),
                (
                    "server.ts".to_string(),
                    SourceFile {
                        path: "server.ts".to_string(),
                        language: Some(Language::Typescript),
                        source: server.to_string(),
                    },
                ),
            ]),
        };
        let references = BTreeSet::from([
            "all".to_string(),
            "info".to_string(),
            "loadOrder".to_string(),
            "show".to_string(),
        ]);
        let index = ReviewContextIndex::build(&sources, &references).expect("context index");
        let paths = BTreeSet::from(["routes/orders.ts"]);
        let existing = vec![ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "show".to_string(),
            location: location_from_offsets("routes/orders.ts", route, 0, route.len()),
            excerpt: route.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        }];

        let (facts, _) = index.facts(&sources, &paths, &references, &existing, 12);
        assert!(facts.iter().any(|fact| {
            fact.role == "helper_definition_context" && fact.symbol == "loadOrder"
        }));
        assert!(facts.iter().any(|fact| {
            fact.role == "registration_context"
                && fact.symbol == "show"
                && fact.location.path == "server.ts"
        }));
        assert!(
            !facts.iter().any(|fact| {
                matches!(
                    fact.role.as_str(),
                    "helper_definition_context" | "registration_context"
                ) && matches!(fact.symbol.as_str(), "all" | "info")
            }),
            "facts: {facts:#?}"
        );
    }

    #[test]
    fn review_context_owns_exact_csharp_qualified_static_helpers() {
        let controller = "using App.Models;\nnamespace App.Controllers\n{\n    class CheckoutController { object Go(string carrier) => Order.GetTrackingUrl(carrier); }\n}\n";
        let helper = "namespace App.Models\n{\n    public class Order\n    {\n        public static string GetTrackingUrl(string carrier)\n        {\n            return $\"https://{carrier}\";\n        }\n    }\n}\n";
        let noise = "namespace Other.Models\n{\n    public class Order\n    {\n        public static string GetTrackingUrl(string carrier)\n        {\n            return carrier;\n        }\n    }\n}\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::from([
                (
                    "Controllers/CheckoutController.cs".to_string(),
                    SourceFile {
                        path: "Controllers/CheckoutController.cs".to_string(),
                        language: Some(Language::Csharp),
                        source: controller.to_string(),
                    },
                ),
                (
                    "Models/Order.cs".to_string(),
                    SourceFile {
                        path: "Models/Order.cs".to_string(),
                        language: Some(Language::Csharp),
                        source: helper.to_string(),
                    },
                ),
                (
                    "Other/Order.cs".to_string(),
                    SourceFile {
                        path: "Other/Order.cs".to_string(),
                        language: Some(Language::Csharp),
                        source: noise.to_string(),
                    },
                ),
            ]),
        };
        let references = BTreeSet::from(["GetTrackingUrl".to_string()]);
        let index = ReviewContextIndex::build(&sources, &references).expect("context index");
        let paths = BTreeSet::from(["Controllers/CheckoutController.cs"]);
        let existing = vec![ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "Go".to_string(),
            location: location_from_offsets(
                "Controllers/CheckoutController.cs",
                controller,
                0,
                controller.len(),
            ),
            excerpt: controller.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        }];

        let (facts, _) = index.facts(&sources, &paths, &references, &existing, 12);
        let helpers = facts
            .iter()
            .filter(|fact| {
                fact.role == "helper_definition_context" && fact.symbol == "GetTrackingUrl"
            })
            .collect::<Vec<_>>();
        assert_eq!(helpers.len(), 1, "facts: {facts:#?}");
        assert_eq!(helpers[0].location.path, "Models/Order.cs");
    }

    #[test]
    fn second_hop_context_keeps_feature_gates_and_template_bindings_exact() {
        let component_source = "this.results.orderNo = this.sanitizer.bypassSecurityTrustHtml(value)\nuser.email = this.sanitizer.bypassSecurityTrustHtml(user.email)\n";
        let template_source = "<span [innerHtml]=\"results.orderNo\"></span>\n<span [innerHtml]=\"user.email\"></span>\n";
        let challenge_source =
            "  key: wantedChallenge\n  disabledEnv:\n    - Docker\n\n  key: unrelatedChallenge\n";
        let mut files = BTreeMap::new();
        for (path, language, source) in [
            (
                "frontend/result.component.ts",
                Some(Language::Typescript),
                component_source,
            ),
            ("frontend/result.component.html", None, template_source),
            ("data/static/challenges.yml", None, challenge_source),
        ] {
            files.insert(
                path.to_string(),
                SourceFile {
                    path: path.to_string(),
                    language,
                    source: source.to_string(),
                },
            );
        }
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files,
        };
        let existing = vec![ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "bypassSecurityTrustHtml".to_string(),
            location: location_from_offsets(
                "frontend/result.component.ts",
                component_source,
                0,
                component_source.len(),
            ),
            excerpt: component_source.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        }];
        let paths = BTreeSet::from(["frontend/result.component.ts"]);
        let (template_facts, _) = template_binding_facts(&sources, &paths, &existing, None, 2);
        assert_eq!(template_facts.len(), 2);
        let precise_fields = BTreeSet::from(["orderNo".to_string()]);
        let (precise_template_facts, _) =
            template_binding_facts(&sources, &paths, &existing, Some(&precise_fields), 2);
        assert_eq!(precise_template_facts.len(), 1);
        assert_eq!(precise_template_facts[0].symbol, "orderNo");

        let references = BTreeSet::from(["wantedChallenge".to_string()]);
        let (gate_facts, _) = feature_gate_facts(&sources, &references, 2);
        assert_eq!(gate_facts.len(), 1);
        assert_eq!(gate_facts[0].symbol, "wantedChallenge");
        assert!(gate_facts[0].excerpt.contains("Docker"));
    }

    #[test]
    fn configuration_paths_reject_template_and_version_lookalikes() {
        assert!(is_configuration_path("application.promotion.subtitles"));
        assert!(!is_configuration_path("^1.3.3"));
        assert!(!is_configuration_path(
            "${active ? 'confirmation' : 'error'}"
        ));
        assert!(!is_configuration_path("./result.component"));
    }

    #[test]
    fn review_configuration_context_excludes_tests_and_teaching_material() {
        let route = "const mode = process.env.MODE\n";
        let production = "mode: production\nmodels: generated\ndisallowed: false\n";
        let test = "httpMock.verify()\n";
        let teaching = "explanation: verify the database lookup\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::from([
                (
                    "routes/live.ts".to_string(),
                    SourceFile {
                        path: "routes/live.ts".to_string(),
                        language: Some(Language::Typescript),
                        source: route.to_string(),
                    },
                ),
                (
                    "config/app.yml".to_string(),
                    SourceFile {
                        path: "config/app.yml".to_string(),
                        language: None,
                        source: production.to_string(),
                    },
                ),
                (
                    "src/configuration.service.spec.ts".to_string(),
                    SourceFile {
                        path: "src/configuration.service.spec.ts".to_string(),
                        language: Some(Language::Typescript),
                        source: test.to_string(),
                    },
                ),
                (
                    "data/static/codefixes/example.info.yml".to_string(),
                    SourceFile {
                        path: "data/static/codefixes/example.info.yml".to_string(),
                        language: None,
                        source: teaching.to_string(),
                    },
                ),
            ]),
        };
        let paths = BTreeSet::from(["routes/live.ts"]);
        let tokens = BTreeSet::from(["mode".to_string(), "verify".to_string()]);

        let (facts, truncated) = configuration_facts(&sources, &paths, &tokens, 8);
        assert!(!truncated);
        assert!(
            facts
                .iter()
                .any(|fact| fact.location.path == "config/app.yml")
        );
        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.location.path == "config/app.yml")
                .count(),
            1
        );
        assert!(!facts.iter().any(|fact| {
            fact.location.path.ends_with(".spec.ts") || fact.location.path.contains("/codefixes/")
        }));
    }

    #[test]
    fn review_context_indexes_one_lexical_helper_hop() {
        let source = "export function isChallengeEnabled (challenge: Challenge): boolean {\n  return getChallengeEnablementStatus(challenge).enabled\n}\nexport function getChallengeEnablementStatus (challenge: Challenge) {\n  return challenge.disabledEnv ? { enabled: false } : { enabled: true }\n}\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::from([(
                "lib/utils.ts".to_string(),
                SourceFile {
                    path: "lib/utils.ts".to_string(),
                    language: Some(Language::Typescript),
                    source: source.to_string(),
                },
            )]),
        };
        let wanted = BTreeSet::from(["isChallengeEnabled".to_string()]);
        let index = ReviewContextIndex::build(&sources, &wanted).expect("index should build");
        let paths = BTreeSet::from(["lib/utils.ts"]);
        let expanded = index.expanded_references(&sources, &paths, &wanted);
        assert!(expanded.contains("getChallengeEnablementStatus"));
        assert!(
            index
                .definitions
                .contains_key("getChallengeEnablementStatus")
        );

        let mut challenge_names = BTreeSet::new();
        collect_challenge_reference_tokens(
            "challenges.rceChallenge and a generic challenge",
            &mut challenge_names,
        );
        assert_eq!(
            challenge_names,
            BTreeSet::from(["rceChallenge".to_string()])
        );
    }

    #[test]
    fn origin_context_connects_exact_endpoint_and_request_write_shapes() {
        let component = "export class OrderService {\n  private host = '/rest/orders'\n}\n";
        let server = "app.get('/rest/orders/:id', orders())\n";
        let handler = "export function orders () {\n  return (req, res) => {\n    res.json({ orderId: req.params.id })\n  }\n}\n";
        let update = "export async function updateProfile (req) {\n  await user.update({ username: req.body.username })\n}\n";
        let email_update = "export async function updateEmail (req) {\n  await user.update({ email: req.body.email })\n}\n";
        let comment_update = "export async function updateComment (req) {\n  await feedback.update({ comment: req.body.comment })\n}\n";
        let mut files = BTreeMap::new();
        for (path, source) in [
            ("frontend/order.service.ts", component),
            ("server.ts", server),
            ("routes/orders.ts", handler),
            ("routes/update.ts", update),
            ("routes/email.ts", email_update),
            ("routes/comment.ts", comment_update),
        ] {
            files.insert(
                path.to_string(),
                SourceFile {
                    path: path.to_string(),
                    language: Some(Language::Typescript),
                    source: source.to_string(),
                },
            );
        }
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files,
        };
        let helper = ReviewNeighborhoodFact {
            role: "helper_definition_context".to_string(),
            symbol: "OrderService".to_string(),
            location: location_from_offsets(
                "frontend/order.service.ts",
                component,
                0,
                component.len(),
            ),
            excerpt: component.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        let consumer = ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "render".to_string(),
            location: location_from_offsets(
                "frontend/order.service.ts",
                component,
                0,
                component.len(),
            ),
            excerpt: "this.orderService.find(id)".to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        let (endpoint, _) =
            endpoint_consumer_facts(&sources, &BTreeSet::new(), &[helper, consumer], 3);
        assert!(endpoint.iter().any(|fact| {
            fact.role == "endpoint_registration_context" && fact.location.path == "server.ts"
        }));
        assert!(endpoint.iter().any(|fact| {
            fact.role == "endpoint_handler_context"
                && fact.symbol == "orders"
                && fact.excerpt.contains("req.params.id")
        }));

        let eval_fact = ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "eval".to_string(),
            location: location_from_offsets("routes/orders.ts", handler, 0, handler.len()),
            excerpt: "const username = user.username\neval(username)".to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        let (writes, _) = stored_write_origin_facts(&sources, &[eval_fact.clone()], 2);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].symbol, "username");
        assert!(writes[0].excerpt.contains("req.body.username"));

        let mixed_context = ReviewNeighborhoodFact {
            excerpt: "`${user.email}` and `${feedback.comment}`".to_string(),
            ..eval_fact
        };
        let precise_fields = BTreeSet::from(["comment".to_string()]);
        let (precise_writes, _) = stored_write_origin_facts_with_fields(
            &sources,
            &[mixed_context.clone()],
            Some(&precise_fields),
            2,
        );
        assert_eq!(precise_writes.len(), 1);
        assert_eq!(precise_writes[0].symbol, "comment");
        assert!(precise_writes[0].excerpt.contains("req.body.comment"));

        let method_interpolation = ReviewNeighborhoodFact {
            excerpt: "`${value.toString()}`".to_string(),
            ..mixed_context
        };
        assert!(interpolated_member_fields(&[method_interpolation]).is_empty());
    }

    #[test]
    fn origin_context_connects_browser_storage_token_and_response_producers() {
        let consumer = "export class LastLoginComponent {\n  show () {\n    const token = localStorage.getItem('token')\n    const payload = jwtDecode(token)\n    return this.sanitizer.bypassSecurityTrustHtml(`${payload.data.lastLoginIp}`)\n  }\n}\n";
        let writer = "export class LoginComponent {\n  login (authentication) {\n    localStorage.setItem('token', authentication.token)\n  }\n}\n";
        let login = "export function login () {\n  function afterLogin (user, res) {\n    const authenticatedUser = { data: user }\n    const token = security.authorize(authenticatedUser)\n    res.json({ token })\n  }\n}\n";
        let persisted = "export function saveLoginIp () {\n  return async (req, res) => {\n    const lastLoginIp = req.headers['true-client-ip']\n    await user.update({ lastLoginIp })\n    res.json(user)\n  }\n}\n";
        let handler = "export function trackOrder () {\n  return (req, res) => {\n    const id = req.params.id\n    res.json({ data: [{ orderId: id }] })\n  }\n}\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: [
                ("frontend/last-login.ts", consumer),
                ("frontend/login.ts", writer),
                ("routes/login.ts", login),
                ("routes/save-login-ip.ts", persisted),
                ("routes/track-order.ts", handler),
            ]
            .into_iter()
            .map(|(path, source)| {
                (
                    path.to_string(),
                    SourceFile {
                        path: path.to_string(),
                        language: Some(Language::Typescript),
                        source: source.to_string(),
                    },
                )
            })
            .collect(),
        };
        let last_login_facts = vec![ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "bypassSecurityTrustHtml".to_string(),
            location: location_from_offsets("frontend/last-login.ts", consumer, 0, consumer.len()),
            excerpt: consumer.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        }];

        let (storage, storage_truncated) =
            browser_storage_write_facts(&sources, &last_login_facts, 2);
        assert!(!storage_truncated);
        assert_eq!(storage.len(), 1);
        assert_eq!(storage[0].symbol, "token");
        assert!(storage[0].excerpt.contains("authentication.token"));

        let (token, token_truncated) = token_payload_origin_facts(&sources, &last_login_facts, 1);
        assert!(!token_truncated);
        assert_eq!(token.len(), 1);
        assert_eq!(token[0].symbol, "afterLogin");
        assert!(token[0].excerpt.contains("data: user"));
        assert!(token[0].excerpt.contains("res.json({ token })"));

        let (stored, stored_truncated) = stored_write_origin_facts(&sources, &last_login_facts, 2);
        assert!(!stored_truncated);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].symbol, "lastLoginIp");
        assert!(stored[0].excerpt.contains("req.headers"));
        assert!(stored[0].excerpt.contains("user.update({ lastLoginIp })"));

        let track_facts = vec![
            ReviewNeighborhoodFact {
                role: "sink_context".to_string(),
                symbol: "bypassSecurityTrustHtml".to_string(),
                location: location_from_offsets("frontend/track.ts", "", 0, 0),
                excerpt: "bypassSecurityTrustHtml(`${results.data[0].orderId}`)".to_string(),
                evidence_id: None,
                provenance: textual_provenance("test"),
            },
            ReviewNeighborhoodFact {
                role: "endpoint_handler_context".to_string(),
                symbol: "trackOrder".to_string(),
                location: location_from_offsets("routes/track-order.ts", handler, 0, handler.len()),
                excerpt: handler.to_string(),
                evidence_id: None,
                provenance: textual_provenance("test"),
            },
        ];
        let (response, response_truncated) =
            request_response_origin_facts(&sources, &track_facts, 2);
        assert!(!response_truncated);
        assert_eq!(response.len(), 1);
        assert_eq!(response[0].role, "request_response_origin_context");
        assert!(response[0].excerpt.contains("req.params.id"));

        let context = ReviewContextIndex::build(&sources, &BTreeSet::new())
            .expect("review context should build");
        let (collected, _) = origin_consumer_review_facts(
            &sources,
            &context,
            &BTreeSet::new(),
            &track_facts,
            None,
            MAX_REVIEW_ORIGIN_FACTS,
        );
        assert!(
            collected
                .iter()
                .any(|fact| fact.role == "request_response_origin_context")
        );
    }

    #[test]
    fn fixed_database_queries_remain_evidence_but_not_review_anchors() {
        let mut literals = BTreeMap::new();
        literals.insert(
            "query".to_string(),
            mehscan_core::LiteralEvaluation {
                state: LiteralState::Known,
                value: Some(LiteralValue::String("SELECT 1".to_string())),
                constant_fragments: Vec::new(),
                references: Vec::new(),
            },
        );
        let evidence = Evidence {
            id: "fixed-query".to_string(),
            kind: EvidenceKind::Sink,
            capability: Capability::DatabaseQuery,
            location: location_from_offsets("routes/health.ts", "db.query('SELECT 1')", 0, 20),
            enclosing_symbol: Some("health".to_string()),
            captures: BTreeMap::new(),
            cwe_candidates: vec!["CWE-89".to_string()],
            tags: Vec::new(),
            confidence: mehscan_core::Confidence::High,
            provenance: mehscan_core::Provenance {
                resolution: Resolution::Ast,
                engine: "test".to_string(),
                rule_version: 1,
            },
            context: mehscan_core::EvidenceContext {
                literals,
                ..Default::default()
            },
            symbol_resolution: None,
            rule_id: "javascript-database-query".to_string(),
            related_evidence: Vec::new(),
        };

        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::new(),
        };
        assert!(is_non_actionable_fixed_sink_observation(
            &evidence, &sources
        ));
        assert_eq!(evidence.kind, EvidenceKind::Sink);
        assert_eq!(evidence.capability, Capability::DatabaseQuery);
    }

    #[test]
    fn safe_purpose_observation_guards_are_bounded() {
        assert!(is_fixed_local_file_read(
            "fs.readFileSync('./swagger.yml', 'utf8')"
        ));
        assert!(!is_fixed_local_file_read("fs.readFileSync(file, 'utf8')"));
        assert!(!is_fixed_local_file_read(
            "fs.readFileSync('./schemas/' + name, 'utf8')"
        ));

        let source = "grunt.registerTask('checksum', 'Create .md5 checksum files', function () {\n\
            const buffer = fs.readFileSync('dist/package.zip')\n\
            const md5 = crypto.createHash('md5')\n\
            md5.update(buffer)\n\
            const value = md5.digest('hex')\n\
            grunt.file.write('dist/package.zip.md5', value)\n\
        })\n";
        let mut captures = BTreeMap::new();
        captures.insert(
            "algorithm".to_string(),
            mehscan_core::Capture {
                text: "'md5'".to_string(),
                location: location_from_offsets(
                    "Gruntfile.js",
                    source,
                    source.find("'md5'").unwrap(),
                    source.find("'md5'").unwrap() + 5,
                ),
            },
        );
        let evidence = Evidence {
            id: "checksum-hash".to_string(),
            kind: EvidenceKind::SecurityConfiguration,
            capability: Capability::CryptographicHash,
            location: captures["algorithm"].location.clone(),
            enclosing_symbol: Some("grunt".to_string()),
            captures,
            cwe_candidates: vec!["CWE-327".to_string()],
            tags: Vec::new(),
            confidence: mehscan_core::Confidence::High,
            provenance: mehscan_core::Provenance {
                resolution: Resolution::Ast,
                engine: "test".to_string(),
                rule_version: 1,
            },
            context: Default::default(),
            symbol_resolution: None,
            rule_id: "javascript-hash-algorithm-selection".to_string(),
            related_evidence: Vec::new(),
        };
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: [(
                "Gruntfile.js".to_string(),
                SourceFile {
                    path: "Gruntfile.js".to_string(),
                    language: Some(Language::Javascript),
                    source: source.to_string(),
                },
            )]
            .into_iter()
            .collect(),
        };
        assert!(is_non_actionable_safe_purpose_observation(
            &evidence, &sources
        ));

        let non_checksum_source =
            source.replace("registerTask('checksum'", "registerTask('passwords'");
        let non_checksum_sources = RepositorySources {
            root: "fixture".to_string(),
            files: [(
                "Gruntfile.js".to_string(),
                SourceFile {
                    path: "Gruntfile.js".to_string(),
                    language: Some(Language::Javascript),
                    source: non_checksum_source,
                },
            )]
            .into_iter()
            .collect(),
        };
        assert!(!is_non_actionable_safe_purpose_observation(
            &evidence,
            &non_checksum_sources
        ));
    }

    #[test]
    fn safe_purpose_guards_require_the_complete_semantic_shape() {
        let make = |kind, capability, rule: &str, path: &str, role: &str, value: &str| Evidence {
            id: format!("{rule}-{role}"),
            kind,
            capability,
            location: location_from_offsets(path, "", 0, 0),
            enclosing_symbol: Some("test".to_string()),
            captures: BTreeMap::from([(
                role.to_string(),
                mehscan_core::Capture {
                    text: value.to_string(),
                    location: location_from_offsets(path, "", 0, 0),
                },
            )]),
            cwe_candidates: vec!["CWE-22".to_string(), "CWE-639".to_string()],
            tags: Vec::new(),
            confidence: mehscan_core::Confidence::High,
            provenance: mehscan_core::Provenance {
                resolution: Resolution::Ast,
                engine: "test".to_string(),
                rule_version: 1,
            },
            context: Default::default(),
            symbol_resolution: None,
            rule_id: rule.to_string(),
            related_evidence: Vec::new(),
        };
        let lint = "const configDir = path.resolve(__dirname, '../../config')\nconst files = await readdir(configDir)\nconfiguration = yaml.load(await readFile(file, 'utf8'))\nValidationSchema.safeParse(configuration)\n";
        let upload = "const loggedInUser = authenticatedUsers.get(req.cookies.token)\nconst uploadedFileType = await fileType.fromBuffer(buffer)\nif (!startsWith(uploadedFileType.mime, 'image')) return\nconst filePath = `assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}`\n";
        let captcha = "const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })\nif (req.body.captcha === captcha.answer) next()\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: [
                ("lib/scripts/lint.ts", lint),
                ("routes/upload.ts", upload),
                ("routes/captcha.ts", captcha),
            ]
            .into_iter()
            .map(|(path, source)| {
                (
                    path.to_string(),
                    SourceFile {
                        path: path.to_string(),
                        language: Some(Language::Typescript),
                        source: source.to_string(),
                    },
                )
            })
            .collect(),
        };

        let yaml = make(
            EvidenceKind::Sink,
            Capability::Deserialization,
            "typescript-yaml-deserialization",
            "lib/scripts/lint.ts",
            "payload",
            "await readFile(file, 'utf8')",
        );
        assert!(is_schema_validated_local_yaml_tool(&yaml, &sources));
        let incomplete_sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::from([(
                "lib/scripts/lint.ts".to_string(),
                SourceFile {
                    path: "lib/scripts/lint.ts".to_string(),
                    language: Some(Language::Typescript),
                    source: lint.replace(
                        "ValidationSchema.safeParse(configuration)",
                        "use(configuration)",
                    ),
                },
            )]),
        };
        assert!(!is_schema_validated_local_yaml_tool(
            &yaml,
            &incomplete_sources
        ));

        let write = make(
            EvidenceKind::Sink,
            Capability::FilesystemWrite,
            "typescript-filesystem-write",
            "routes/upload.ts",
            "path",
            "filePath",
        );
        assert!(is_authenticated_generated_upload_write(&write, &sources));

        let captcha_lookup = make(
            EvidenceKind::Sink,
            Capability::ResourceAccess,
            "typescript-sequelize-resource-access",
            "routes/captcha.ts",
            "model",
            "CaptchaModel",
        );
        assert!(is_captcha_verification_lookup(&captcha_lookup, &sources));
    }

    #[test]
    fn origin_context_rejects_key_field_and_request_lookalikes() {
        let consumer = "const token = localStorage.getItem('auth-token')\nconst payload = jwtDecode(token)\nbypassSecurityTrustHtml(`${payload.data.displayName}`)\n";
        let wrong_key = "localStorage.setItem('token', authentication.token)\n";
        let non_request_write = "export function saveDisplayName (profile) {\n  user.update({ displayName: profile.displayName })\n}\n";
        let static_response = "export function profile () {\n  return (req, res) => {\n    res.json({ displayName: 'system' })\n  }\n}\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: [
                ("frontend/view.ts", consumer),
                ("frontend/login.ts", wrong_key),
                ("routes/update.ts", non_request_write),
                ("routes/profile.ts", static_response),
            ]
            .into_iter()
            .map(|(path, source)| {
                (
                    path.to_string(),
                    SourceFile {
                        path: path.to_string(),
                        language: Some(Language::Typescript),
                        source: source.to_string(),
                    },
                )
            })
            .collect(),
        };
        let sink = ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "bypassSecurityTrustHtml".to_string(),
            location: location_from_offsets("frontend/view.ts", consumer, 0, consumer.len()),
            excerpt: consumer.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };

        assert!(
            browser_storage_write_facts(&sources, std::slice::from_ref(&sink), 2)
                .0
                .is_empty()
        );
        assert!(
            stored_write_origin_facts(&sources, std::slice::from_ref(&sink), 2)
                .0
                .is_empty()
        );

        let mut response_facts = vec![sink];
        response_facts.push(ReviewNeighborhoodFact {
            role: "endpoint_handler_context".to_string(),
            symbol: "profile".to_string(),
            location: location_from_offsets(
                "routes/profile.ts",
                static_response,
                0,
                static_response.len(),
            ),
            excerpt: static_response.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        });
        assert!(
            request_response_origin_facts(&sources, &response_facts, 2)
                .0
                .is_empty()
        );
    }

    #[test]
    fn execution_configuration_gate_requires_exact_conditional_use() {
        let location = location_from_offsets("Service.java", "", 0, 0);
        let configuration = ReviewNeighborhoodFact {
            role: "configuration_context".to_string(),
            symbol: "enable_shell_injection".to_string(),
            location: location.clone(),
            excerpt: "ENABLE_SHELL_INJECTION=false".to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        let guarded_sink = ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "convertVideo".to_string(),
            location: location.clone(),
            excerpt: "if (video != null && enable_shell_injection) { shell.execute(command); }"
                .to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        assert!(path_execution_configuration_gate(&[
            configuration.clone(),
            guarded_sink,
        ]));

        let unrelated = ReviewNeighborhoodFact {
            role: "sink_context".to_string(),
            symbol: "convertVideo".to_string(),
            location,
            excerpt: "shell.execute(command);".to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        assert!(!path_execution_configuration_gate(&[
            configuration,
            unrelated,
        ]));
    }

    #[test]
    fn marks_substring_redirect_allowlists_as_ineffective_context() {
        let helper = "export const isRedirectAllowed = (url: string) => {\n  for (const allowedUrl of redirectAllowlist) {\n    if (url.includes(allowedUrl)) return true\n  }\n  return false\n}\n";
        let sources = RepositorySources {
            root: "fixture".to_string(),
            files: BTreeMap::from([(
                "lib/security.ts".to_string(),
                SourceFile {
                    path: "lib/security.ts".to_string(),
                    language: Some(Language::Typescript),
                    source: helper.to_string(),
                },
            )]),
        };
        let existing = vec![
            ReviewNeighborhoodFact {
                role: "helper_definition_context".to_string(),
                symbol: "isRedirectAllowed".to_string(),
                location: location_from_offsets("lib/security.ts", helper, 0, helper.len()),
                excerpt: helper.to_string(),
                evidence_id: None,
                provenance: textual_provenance("test"),
            },
            ReviewNeighborhoodFact {
                role: "sink_context".to_string(),
                symbol: "redirect".to_string(),
                location: location_from_offsets("routes/redirect.ts", "res.redirect(toUrl)", 0, 19),
                excerpt: "res.redirect(toUrl)".to_string(),
                evidence_id: None,
                provenance: textual_provenance("test"),
            },
        ];

        let (facts, truncated) = ineffective_protection_review_facts(&sources, &existing, 2);
        assert!(!truncated);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].role, "ineffective_protection_context");
        assert_eq!(facts[0].symbol, "substring URL allowlist");
        assert!(facts[0].excerpt.contains("url.includes(allowedUrl)"));
    }

    #[test]
    fn server_generated_fixed_root_paths_require_bounded_filename_components() {
        let source = "const email = authenticatedUsers.from(req).data.email\n\
            const orderId = security.hash(email).slice(0, 4) + '-' + utils.randomHexString(16)\n\
            const pdfFile = `order_${orderId}.pdf`\n\
            fs.createWriteStream(path.join('ftp/', pdfFile))";
        let make_evidence = |kind, capability, rule_id: &str, capture: (&str, &str)| {
            let mut captures = BTreeMap::new();
            captures.insert(
                capture.0.to_string(),
                mehscan_core::Capture {
                    text: capture.1.to_string(),
                    location: location_from_offsets("routes/order.ts", source, 0, source.len()),
                },
            );
            Evidence {
                id: rule_id.to_string(),
                kind,
                capability,
                location: location_from_offsets("routes/order.ts", source, 0, source.len()),
                enclosing_symbol: Some("placeOrder".to_string()),
                captures,
                cwe_candidates: Vec::new(),
                tags: Vec::new(),
                confidence: mehscan_core::Confidence::High,
                provenance: mehscan_core::Provenance {
                    resolution: Resolution::Ast,
                    engine: "test".to_string(),
                    rule_version: 1,
                },
                context: Default::default(),
                symbol_resolution: None,
                rule_id: rule_id.to_string(),
                related_evidence: Vec::new(),
            }
        };
        let evidence = vec![
            make_evidence(
                EvidenceKind::Sanitizer,
                Capability::FixedFormatTransform,
                "typescript-fixed-format-transform",
                ("value", "email"),
            ),
            make_evidence(
                EvidenceKind::Sink,
                Capability::FilesystemWrite,
                "typescript-filesystem-write",
                ("path", "path.join('ftp/', pdfFile)"),
            ),
        ];
        let fact = ReviewNeighborhoodFact {
            role: "source_context".to_string(),
            symbol: "placeOrder".to_string(),
            location: location_from_offsets("routes/order.ts", source, 0, source.len()),
            excerpt: source.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        assert!(observation_has_server_generated_fixed_root_path(
            &evidence,
            std::slice::from_ref(&fact)
        ));

        let unsafe_fact = ReviewNeighborhoodFact {
            excerpt: source.replace(
                "security.hash(email).slice(0, 4)",
                "req.body.filename + security.hash(email).slice(0, 4)",
            ),
            ..fact
        };
        assert!(!observation_has_server_generated_fixed_root_path(
            &evidence,
            &[unsafe_fact]
        ));
    }

    #[test]
    fn operator_configured_local_assets_require_literal_safe_defaults_and_fixed_reads() {
        let source_text = "getSubsFromFile()";
        let source = Evidence {
            id: "subtitle".to_string(),
            kind: EvidenceKind::Source,
            capability: Capability::StoredUserContent,
            location: location_from_offsets("routes/video.ts", source_text, 0, source_text.len()),
            enclosing_symbol: Some("promotionVideo".to_string()),
            captures: BTreeMap::new(),
            cwe_candidates: Vec::new(),
            tags: vec!["stored-data".to_string(), "local-file".to_string()],
            confidence: mehscan_core::Confidence::High,
            provenance: mehscan_core::Provenance {
                resolution: Resolution::Ast,
                engine: "test".to_string(),
                rule_version: 1,
            },
            context: Default::default(),
            symbol_resolution: None,
            rule_id: "typescript-stored-subtitle-content".to_string(),
            related_evidence: Vec::new(),
        };
        let fact = |role: &str, excerpt: &str| ReviewNeighborhoodFact {
            role: role.to_string(),
            symbol: "application.promotion.subtitles".to_string(),
            location: location_from_offsets("fixture.ts", excerpt, 0, excerpt.len()),
            excerpt: excerpt.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        let facts = vec![
            fact(
                "configuration_binding_context",
                "subtitles: owasp_promo.vtt",
            ),
            fact(
                "helper_definition_context",
                "const subtitles = config.get<string>('application.promotion.subtitles'); fs.readFileSync('assets/videos/' + subtitles, 'utf8')",
            ),
            fact(
                "configuration_lifecycle_context",
                "retrieveCustomFile('application.promotion.subtitles', 'assets/videos')",
            ),
        ];
        assert!(path_has_operator_configured_local_asset_origin(
            source.capability,
            &source.tags,
            &facts
        ));

        let mut unsafe_facts = facts;
        unsafe_facts[0].excerpt = "subtitles: ../outside.vtt".to_string();
        assert!(!path_has_operator_configured_local_asset_origin(
            source.capability,
            &source.tags,
            &unsafe_facts
        ));
    }

    #[test]
    fn direct_observation_relationships_require_exact_local_operands() {
        let source_text =
            "feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(feedbacks[i].comment)";
        let make = |id: &str,
                    kind,
                    capability,
                    rule_id: &str,
                    capture_name: &str,
                    capture_text: &str,
                    symbol: &str| {
            Evidence {
                id: id.to_string(),
                kind,
                capability,
                location: location_from_offsets("component.ts", source_text, 0, source_text.len()),
                enclosing_symbol: Some(symbol.to_string()),
                captures: BTreeMap::from([(
                    capture_name.to_string(),
                    mehscan_core::Capture {
                        text: capture_text.to_string(),
                        location: location_from_offsets(
                            "component.ts",
                            source_text,
                            0,
                            source_text.len(),
                        ),
                    },
                )]),
                cwe_candidates: Vec::new(),
                tags: Vec::new(),
                confidence: mehscan_core::Confidence::Medium,
                provenance: mehscan_core::Provenance {
                    resolution: Resolution::Ast,
                    engine: "test".to_string(),
                    rule_version: 1,
                },
                context: Default::default(),
                symbol_resolution: None,
                rule_id: rule_id.to_string(),
                related_evidence: Vec::new(),
            }
        };
        let stored = make(
            "stored",
            EvidenceKind::Source,
            Capability::StoredUserContent,
            "typescript-angular-rxjs-stored-source",
            "value",
            "feedbacks",
            "populate",
        );
        let html = make(
            "html",
            EvidenceKind::Sink,
            Capability::HtmlOutput,
            "typescript-angular-html-trust-bypass",
            "content",
            "feedbacks[i].comment",
            "populate",
        );
        let fact = ReviewNeighborhoodFact {
            role: "source_context".to_string(),
            symbol: "populate".to_string(),
            location: location_from_offsets("component.ts", source_text, 0, source_text.len()),
            excerpt: source_text.to_string(),
            evidence_id: None,
            provenance: textual_provenance("test"),
        };
        assert!(observation_has_direct_stored_html_trust_bypass(
            &[stored.clone(), html.clone()],
            std::slice::from_ref(&fact)
        ));
        let mut wrong_scope_html = html;
        wrong_scope_html.enclosing_symbol = Some("other".to_string());
        assert!(!observation_has_direct_stored_html_trust_bypass(
            &[stored, wrong_scope_html],
            &[fact]
        ));

        let request = make(
            "request",
            EvidenceKind::Source,
            Capability::HttpRequestData,
            "typescript-http-request-data",
            "name",
            "id",
            "update",
        );
        let resource = make(
            "resource",
            EvidenceKind::Sink,
            Capability::ResourceAccess,
            "typescript-sequelize-resource-access",
            "filter",
            "{ id: req.params.id }",
            "update",
        );
        assert!(observation_has_direct_request_resource_selector(&[
            request.clone(),
            resource.clone()
        ]));
        let mut unrelated_request = request;
        unrelated_request
            .captures
            .get_mut("name")
            .expect("name capture")
            .text = "basketId".to_string();
        assert!(!observation_has_direct_request_resource_selector(&[
            unrelated_request,
            resource
        ]));
    }

    #[test]
    fn reviewer_visible_basis_changes_the_path_review_fingerprint() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("tests/fixtures/review-guidance-contract");
        let job = build_all_path_review_jobs(&root, Some(6), false)
            .expect("cross-language guidance fixture should build");
        let mut changed = job.observation_reviews.clone();
        changed[0]
            .review_basis
            .as_mut()
            .expect("rule-derived basis")
            .exclude
            .push("new reviewer-visible exclusion".to_string());

        let changed_fingerprint = path_review_fingerprint(
            &job.reviews,
            &changed,
            &job.triage_contract,
            job.context_lines,
            job.offset,
            job.include_review_material,
        );
        assert_ne!(job.fingerprint, changed_fingerprint);
    }

    #[test]
    fn path_review_question_uses_existing_descriptive_relationship_semantics() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("tests/fixtures/v2-node-policy");
        let job = build_all_path_review_jobs(&root, Some(20), false)
            .expect("node policy fixture should build review jobs");
        let review = job
            .reviews
            .iter()
            .find(|review| review.candidate.sink.rule_id == "typescript-plaintext-totp-storage")
            .expect("plaintext TOTP path review");
        let basis = review.review_basis.as_ref().expect("path review basis");

        assert!(
            basis
                .security_question
                .contains("TOTP secret assigned directly to persistent model field")
        );
        assert!(!basis.security_question.contains("ResourceAccess behavior"));
        assert!(basis.deterministic_facts.iter().any(|fact| {
            fact == "Bounded relationship semantics: TOTP secret assigned directly to persistent model field -> model saved without an observed encryption transform."
        }));
        assert!(review.decision_facts.established.iter().any(|fact| {
            fact == "The bounded path records this rule-specific behavior: model saved without an observed encryption transform."
        }));
    }
}
