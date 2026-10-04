//! Optional, source-bound Roslyn navigation facts. No admission or safety changes.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mehscan_core::{
    Capability, Diagnostic, DiagnosticLevel, Location, OperandFact, OperandFactKind, ScanResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::EngineError;

const MAX_SNAPSHOT: u64 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct Context {
    projects: Vec<Project>,
}
#[derive(Debug, Deserialize)]
struct Project {
    id: String,
    sources: Vec<String>,
    references: Vec<String>,
    reference_directories: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    pub evidence_id: String,
    pub role: String,
    pub sink: Location,
    pub operand: Location,
}
#[derive(Debug, Serialize)]
struct Request<'a> {
    schema_version: &'a str,
    root: PathBuf,
    context_path: PathBuf,
    queries: Vec<Query>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    schema_version: String,
    pub backend: String,
    context_sha256: String,
    sources: Vec<FileHash>,
    references: Vec<FileHash>,
    projects: Vec<ProjectRecord>,
    pub observations: Vec<Observation>,
    pub diagnostics: Vec<serde_json::Value>,
}
#[derive(Debug, Serialize, Deserialize)]
struct FileHash {
    path: String,
    sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct ProjectRecord {
    id: String,
    target_framework: String,
    language_version: String,
    compiler_errors: usize,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Observation {
    pub evidence_id: String,
    project_id: String,
    pub facts: Vec<OperandFact>,
}

pub fn queries(scan: &ScanResult) -> Vec<Query> {
    scan.evidence
        .iter()
        .filter(|e| e.location.path.ends_with(".cs") && e.capability == Capability::DatabaseQuery)
        .filter_map(|e| {
            e.captures.get("query").map(|operand| Query {
                evidence_id: e.id.clone(),
                role: "query".into(),
                sink: e.location.clone(),
                operand: operand.location.clone(),
            })
        })
        .collect()
}

/// Launch an explicitly supplied helper once for the selected SQL operands.
pub fn collect(
    root: &Path,
    context: &Path,
    backend: &Path,
    scan: &ScanResult,
) -> Result<Snapshot, EngineError> {
    let declared: Context = serde_json::from_slice(&std::fs::read(context)?).map_err(err)?;
    for path in declared.projects.iter().flat_map(|p| &p.sources) {
        source_path(root, path)?;
    }
    let request = Request {
        schema_version: "1",
        root: root.canonicalize()?,
        context_path: context.canonicalize()?,
        queries: queries(scan),
    };
    let input = serde_json::to_vec(&request).map_err(err)?;
    if input.len() as u64 > MAX_SNAPSHOT {
        return Err(EngineError(
            "Roslyn request exceeds 8 MiB; narrow the source scope".into(),
        ));
    }
    let mut command = Command::new(backend.canonicalize()?);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let output = std::thread::spawn(move || read_bounded(stdout, MAX_SNAPSHOT));
    let errors = std::thread::spawn(move || read_bounded(stderr, 8192));
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(EngineError(
                "Roslyn helper exceeded 60 seconds; narrow the explicit context".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let bytes = output
        .join()
        .map_err(|_| EngineError("Roslyn output reader failed".into()))??;
    writer
        .join()
        .map_err(|_| EngineError("Roslyn input writer failed".into()))??;
    let error_bytes = errors
        .join()
        .map_err(|_| EngineError("Roslyn error reader failed".into()))??;
    if !status.success() {
        return Err(EngineError(format!(
            "Roslyn helper failed: {}",
            String::from_utf8_lossy(&error_bytes).trim()
        )));
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(err)?;
    validate(root, context, &snapshot)?;
    Ok(snapshot)
}

pub fn load(path: &Path) -> Result<Snapshot, EngineError> {
    serde_json::from_slice(&read_bounded(std::fs::File::open(path)?, MAX_SNAPSHOT)?).map_err(err)
}

/// Validate all source/reference inputs before attaching anything. This is shadow
/// metadata: existing identities, captures, paths, IDs and selection stay intact.
pub fn enrich(
    root: &Path,
    context: &Path,
    snapshot: &Snapshot,
    scan: &mut ScanResult,
) -> Result<(), EngineError> {
    validate(root, context, snapshot)?;
    let expected: BTreeMap<_, _> = queries(scan)
        .into_iter()
        .map(|q| (q.evidence_id.clone(), q))
        .collect();
    let projects: BTreeMap<_, _> = snapshot
        .projects
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect();
    let mut observed = BTreeMap::<&str, Vec<&Observation>>::new();
    for observation in &snapshot.observations {
        if !expected.contains_key(&observation.evidence_id)
            || !projects.contains_key(observation.project_id.as_str())
        {
            return Err(EngineError(
                "Roslyn snapshot contains an unknown operation/project; regenerate it".into(),
            ));
        }
        observed
            .entry(&observation.evidence_id)
            .or_default()
            .push(observation);
        for fact in &observation.facts {
            if !matches!(
                fact.kind,
                OperandFactKind::SemanticIdentity
                    | OperandFactKind::SemanticDefinition
                    | OperandFactKind::LocalOperandOrigin
                    | OperandFactKind::OperandBoundary
            ) || fact.remaining_checks.is_empty()
            {
                return Err(EngineError("Unsupported Roslyn navigation fact".into()));
            }
            validate_location(root, &snapshot.sources, &fact.location)?;
            if fact.kind == OperandFactKind::LocalOperandOrigin {
                let text = std::fs::read_to_string(source_path(root, &fact.location.path)?)?;
                if text.get(fact.location.start.byte_offset..fact.location.end.byte_offset)
                    != Some(fact.value.as_str())
                {
                    return Err(EngineError(
                        "Roslyn initializer text does not match source".into(),
                    ));
                }
            }
        }
    }
    for evidence in &mut scan.evidence {
        let Some(records) = observed.get(evidence.id.as_str()) else {
            continue;
        };
        if records.len() != 1 {
            scan.diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Warning,
                path: Some(evidence.location.path.clone()),
                message:
                    "Roslyn: multiple target/project contexts cover this operation; facts withheld"
                        .into(),
            });
            continue;
        }
        let record = records[0];
        let partial = projects[record.project_id.as_str()].compiler_errors > 0;
        for fact in &record.facts {
            let mut fact = fact.clone();
            if partial {
                fact.remaining_checks
                    .push("partial_semantic_context".into());
            }
            if !evidence.context.operand_facts.iter().any(|old| {
                old.kind == fact.kind
                    && old.role == fact.role
                    && old.location == fact.location
                    && old.value == fact.value
            }) {
                evidence.context.operand_facts.push(fact);
            }
        }
    }
    for project in &snapshot.projects {
        if project.compiler_errors > 0 {
            scan.diagnostics.push(Diagnostic { level: DiagnosticLevel::Warning, path: None,
                message: format!("Roslyn project {} ({}, C# {}) has {} compiler errors; affected bindings remain unresolved",
                    project.id, project.target_framework, project.language_version, project.compiler_errors) });
        }
    }
    Ok(())
}

fn validate(root: &Path, context_path: &Path, snapshot: &Snapshot) -> Result<(), EngineError> {
    let context_bytes = std::fs::read(context_path)?;
    if snapshot.schema_version != "1" || digest(&context_bytes) != snapshot.context_sha256 {
        return Err(EngineError(
            "Roslyn context is stale or has an unsupported version".into(),
        ));
    }
    let context: Context = serde_json::from_slice(&context_bytes).map_err(err)?;
    let expected_sources: BTreeSet<_> = context
        .projects
        .iter()
        .flat_map(|p| p.sources.iter())
        .map(|s| s.replace('\\', "/"))
        .collect();
    let actual_sources: BTreeSet<_> = snapshot.sources.iter().map(|s| s.path.clone()).collect();
    if expected_sources != actual_sources || actual_sources.len() != snapshot.sources.len() {
        return Err(EngineError(
            "Roslyn source scope does not match its context".into(),
        ));
    }
    let ids: BTreeSet<_> = context.projects.iter().map(|p| p.id.as_str()).collect();
    if ids.len() != context.projects.len()
        || ids.len() != snapshot.projects.len()
        || ids != snapshot.projects.iter().map(|p| p.id.as_str()).collect()
    {
        return Err(EngineError(
            "Roslyn project scope does not match its context".into(),
        ));
    }
    for file in &snapshot.sources {
        if digest(&std::fs::read(source_path(root, &file.path)?)?) != file.sha256 {
            return Err(EngineError(format!(
                "Roslyn source snapshot is stale: {}",
                file.path
            )));
        }
    }
    let mut expected_refs = BTreeSet::new();
    for project in &context.projects {
        for path in &project.references {
            expected_refs.insert(PathBuf::from(path).canonicalize()?);
        }
        for directory in &project.reference_directories {
            for entry in std::fs::read_dir(directory)? {
                let path = entry?.path();
                if path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("dll"))
                {
                    expected_refs.insert(path.canonicalize()?);
                }
            }
        }
    }
    let actual_refs = snapshot
        .references
        .iter()
        .map(|f| PathBuf::from(&f.path).canonicalize())
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual_refs != expected_refs || actual_refs.len() != snapshot.references.len() {
        return Err(EngineError(
            "Roslyn reference scope does not match its context".into(),
        ));
    }
    for reference in &snapshot.references {
        if digest(&std::fs::read(&reference.path)?) != reference.sha256 {
            return Err(EngineError("Roslyn reference snapshot is stale".into()));
        }
    }
    Ok(())
}

fn source_path(root: &Path, path: &str) -> Result<PathBuf, EngineError> {
    if Path::new(path).is_absolute() || path.split(['/', '\\']).any(|c| c == "..") {
        return Err(EngineError(
            "Roslyn source must be repository-relative".into(),
        ));
    }
    let root = root.canonicalize()?;
    let full = root.join(path).canonicalize()?;
    if !full.starts_with(&root) {
        return Err(EngineError("Roslyn source escapes repository root".into()));
    }
    Ok(full)
}

fn validate_location(
    root: &Path,
    sources: &[FileHash],
    location: &Location,
) -> Result<(), EngineError> {
    if !sources.iter().any(|s| s.path == location.path) {
        return Err(EngineError("Unknown Roslyn fact source".into()));
    }
    let text = std::fs::read_to_string(source_path(root, &location.path)?)?;
    for position in [&location.start, &location.end] {
        if !text.is_char_boundary(position.byte_offset) {
            return Err(EngineError("Invalid Roslyn byte position".into()));
        }
        let prefix = &text[..position.byte_offset];
        let line = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
        let column = prefix.rsplit('\n').next().unwrap_or_default().len() + 1;
        if line != position.line || column != position.column {
            return Err(EngineError("Roslyn line/byte position mismatch".into()));
        }
    }
    if location.start.byte_offset > location.end.byte_offset {
        return Err(EngineError("Invalid Roslyn source range".into()));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn err(error: impl std::fmt::Display) -> EngineError {
    EngineError(error.to_string())
}
fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>, EngineError> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(EngineError("Roslyn output exceeds size bound".into()));
    }
    Ok(bytes)
}
