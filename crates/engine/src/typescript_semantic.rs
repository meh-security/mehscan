//! Optional source-only TypeScript compiler navigation. No type-derived safety verdicts.
use crate::{
    EngineError,
    csharp_semantic::{digest, source_path},
};
use mehscan_core::{
    Capability, Diagnostic, DiagnosticLevel, Location, OperandFact, OperandFactKind, ScanResult,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MAX_SNAPSHOT: u64 = 8 * 1024 * 1024;
#[derive(Deserialize)]
struct Context {
    typescript_path: PathBuf,
    projects: Vec<Project>,
    #[serde(default)]
    context_files: Vec<PathBuf>,
    #[serde(default)]
    node_types: Option<PathBuf>,
}
#[derive(Deserialize)]
struct Project {
    id: String,
    sources: Vec<String>,
    #[serde(default)]
    tsconfig: Option<String>,
    #[serde(default)]
    runtime: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Query {
    pub evidence_id: String,
    pub role: String,
    pub sink: Location,
    pub operand: Location,
}
#[derive(Serialize)]
struct Request<'a> {
    schema_version: &'a str,
    root: PathBuf,
    context_path: PathBuf,
    queries: Vec<Query>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileHash {
    path: String,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Probe {
    kind: String,
    path: String,
    exists: Option<bool>,
    children: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProjectRecord {
    id: String,
    compiler_errors: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    semantic_analysis: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub evidence_id: String,
    project_id: String,
    pub facts: Vec<OperandFact>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    schema_version: String,
    pub backend: String,
    context_sha256: String,
    sources: Vec<FileHash>,
    inputs: Vec<FileHash>,
    probes: Vec<Probe>,
    projects: Vec<ProjectRecord>,
    pub observations: Vec<Observation>,
    pub diagnostics: Vec<serde_json::Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputBinding {
    context_path: PathBuf,
    snapshot: Snapshot,
}
pub enum Input<'a> {
    Snapshot(&'a Path, &'a Path),
    Backend(&'a Path, &'a Path),
}
impl InputBinding {
    pub fn capture(context: &Path, snapshot: &Snapshot) -> Result<Self, EngineError> {
        let mut snapshot = snapshot.clone();
        snapshot.observations.clear();
        snapshot.diagnostics.clear();
        Ok(Self {
            context_path: context.canonicalize()?,
            snapshot,
        })
    }
    pub fn validate(&self, root: &Path) -> Result<(), EngineError> {
        validate(root, &self.context_path, &self.snapshot)
    }
}
pub fn queries(scan: &ScanResult) -> Vec<Query> {
    scan.evidence
        .iter()
        .filter(|e| {
            matches!(
                e.location.path.rsplit('.').next(),
                Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts")
            )
        })
        .filter_map(|e| {
            let role = match e.capability {
                Capability::DatabaseQuery => "query",
                Capability::FilesystemRead | Capability::FilesystemWrite => "path",
                Capability::HtmlOutput => "content",
                Capability::ProcessExecution | Capability::ProcessArgumentSeparation => "command",
                Capability::OutboundNetworkRequest => "endpoint",
                Capability::BrowserNavigation => "destination",
                _ => return None,
            };
            // Some Node APIs capture the executable as program instead of command.
            let (role, operand) = e.captures.get(role).map(|o| (role, o)).or_else(|| {
                (role == "command")
                    .then(|| e.captures.get("program").map(|o| ("program", o)))
                    .flatten()
            })?;
            Some(Query {
                evidence_id: e.id.clone(),
                role: role.into(),
                sink: e.location.clone(),
                operand: operand.location.clone(),
            })
        })
        .collect()
}
// Node's entry-point loader does not accept Windows verbatim paths.
fn node_path(path: &Path) -> Result<PathBuf, EngineError> {
    let canonical = path.canonicalize()?;
    #[cfg(windows)]
    {
        let text = canonical.to_string_lossy();
        if let Some(unc) = text.strip_prefix("\\\\?\\UNC\\") {
            return Ok(PathBuf::from(format!("\\\\{unc}")));
        }
        if let Some(normal) = text.strip_prefix("\\\\?\\") {
            return Ok(PathBuf::from(normal));
        }
    }
    Ok(canonical)
}
pub fn collect(
    root: &Path,
    context: &Path,
    backend: &Path,
    scan: &ScanResult,
) -> Result<Snapshot, EngineError> {
    let declared: Context = serde_json::from_slice(&std::fs::read(context)?).map_err(err)?;
    context_sources(root, &declared)?;
    if !declared.typescript_path.is_absolute() {
        return Err(err("typescript_path must be absolute"));
    }
    let request = Request {
        schema_version: "1",
        root: node_path(root)?,
        context_path: node_path(context)?,
        queries: queries(scan),
    };
    let bytes = serde_json::to_vec(&request).map_err(err)?;
    if bytes.len() as u64 > MAX_SNAPSHOT {
        return Err(err("TypeScript request exceeds 8 MiB"));
    }
    let mut command = Command::new("node");
    command
        .arg(node_path(backend)?)
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
    let writer = std::thread::spawn(move || stdin.write_all(&bytes));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err("TypeScript helper exceeded 60 seconds; narrow context"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let bytes = output
        .join()
        .map_err(|_| err("TypeScript output reader failed"))??;
    writer
        .join()
        .map_err(|_| err("TypeScript input writer failed"))??;
    let errors = errors
        .join()
        .map_err(|_| err("TypeScript error reader failed"))??;
    if !status.success() {
        return Err(err(format!(
            "TypeScript helper failed: {}",
            String::from_utf8_lossy(&errors).trim()
        )));
    }
    let snapshot = serde_json::from_slice(&bytes).map_err(err)?;
    validate(root, context, &snapshot)?;
    Ok(snapshot)
}
pub fn load(path: &Path) -> Result<Snapshot, EngineError> {
    serde_json::from_slice(&read_bounded(std::fs::File::open(path)?, MAX_SNAPSHOT)?).map_err(err)
}
pub fn enrich(
    root: &Path,
    context: &Path,
    snapshot: &Snapshot,
    scan: &mut ScanResult,
) -> Result<(), EngineError> {
    validate(root, context, snapshot)?;
    let declared: Context = serde_json::from_slice(&std::fs::read(context)?).map_err(err)?;
    let queries = queries(scan)
        .into_iter()
        .map(|q| (q.evidence_id.clone(), q))
        .collect::<BTreeMap<_, _>>();
    let projects = snapshot
        .projects
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect::<BTreeMap<_, _>>();
    let mut records = BTreeMap::<&str, Vec<&Observation>>::new();
    for observation in &snapshot.observations {
        let query = queries
            .get(&observation.evidence_id)
            .ok_or_else(|| err("Unknown TypeScript operation; regenerate snapshot"))?;
        if !projects.contains_key(observation.project_id.as_str()) {
            return Err(err("Unknown TypeScript project"));
        }
        records
            .entry(&observation.evidence_id)
            .or_default()
            .push(observation);
        for fact in &observation.facts {
            let fixed_path = fact.kind == OperandFactKind::FixedFilesystemPath
                && query.role == "path"
                && fact.role == "path"
                && fact.location == query.operand
                && fact
                    .remaining_checks
                    .iter()
                    .any(|c| c == "complete_static_path_operand")
                && fact
                    .remaining_checks
                    .iter()
                    .any(|c| c == "supplied_node_path_contract");
            let browser_request = fact.kind == OperandFactKind::BrowserRequestContext
                && declared.projects.iter().any(|p| {
                    p.id == observation.project_id && p.runtime.as_deref() == Some("browser")
                })
                && query.role == "endpoint"
                && fact.role == "endpoint"
                && fact.location == query.operand
                && ["explicit_browser_runtime", "dom_fetch_binding"]
                    .iter()
                    .all(|marker| fact.remaining_checks.iter().any(|c| c == marker))
                && fact.remaining_checks.iter().any(|c| {
                    matches!(
                        c.as_str(),
                        "ordinary_get_head" | "request_options_require_review"
                    )
                });
            if (!fixed_path
                && !browser_request
                && !matches!(
                    fact.kind,
                    OperandFactKind::SemanticIdentity
                        | OperandFactKind::SemanticDefinition
                        | OperandFactKind::LocalOperandOrigin
                        | OperandFactKind::OperandBoundary
                        | OperandFactKind::LocalCallArgument
                ))
                || fact.remaining_checks.is_empty()
                || (fact.role != query.role && fact.role != "operation")
            {
                return Err(err("Unsupported TypeScript navigation fact"));
            }
            validate_location(root, &snapshot.sources, &fact.location)?;
            if matches!(
                fact.kind,
                OperandFactKind::LocalOperandOrigin
                    | OperandFactKind::LocalCallArgument
                    | OperandFactKind::FixedFilesystemPath
                    | OperandFactKind::BrowserRequestContext
            ) {
                let text = std::fs::read_to_string(source_path(root, &fact.location.path)?)?;
                if text.get(fact.location.start.byte_offset..fact.location.end.byte_offset)
                    != Some(fact.value.as_str())
                {
                    return Err(err("TypeScript source fact text mismatch"));
                }
            }
        }
    }
    for evidence in &mut scan.evidence {
        let Some(records) = records.get(evidence.id.as_str()) else {
            continue;
        };
        if records.len() != 1 {
            scan.diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Warning,
                path: Some(evidence.location.path.clone()),
                message:
                    "TypeScript: overlapping project contexts cover this operation; facts withheld"
                        .into(),
            });
            continue;
        }
        let record = records[0];
        for fact in &record.facts {
            let mut fact = fact.clone();
            if projects[record.project_id.as_str()].compiler_errors > 0
                && fact.kind != OperandFactKind::FixedFilesystemPath
            {
                fact.remaining_checks
                    .push("partial_semantic_context".into());
            }
            if !evidence.context.operand_facts.contains(&fact) {
                evidence.context.operand_facts.push(fact);
            }
        }
    }
    for project in &snapshot.projects {
        if project.compiler_errors > 0 {
            scan.diagnostics.push(Diagnostic { level: DiagnosticLevel::Warning, path: None,
            message: format!("TypeScript project {} has {} compiler errors; bindings are navigation, not runtime or safety proofs", project.id, project.compiler_errors) });
        }
    }
    Ok(())
}
fn context_sources(root: &Path, context: &Context) -> Result<BTreeSet<String>, EngineError> {
    if context.projects.is_empty() {
        return Err(err("TypeScript context requires projects"));
    }
    let ids = context
        .projects
        .iter()
        .map(|p| &p.id)
        .collect::<BTreeSet<_>>();
    if ids.len() != context.projects.len() || ids.iter().any(|id| id.is_empty()) {
        return Err(err("TypeScript context project IDs must be unique"));
    }
    let mut sources = BTreeSet::new();
    for project in &context.projects {
        if project
            .runtime
            .as_deref()
            .is_some_and(|r| !matches!(r, "browser" | "server"))
        {
            return Err(err("TypeScript runtime must be browser or server"));
        }
        if let Some(config) = &project.tsconfig {
            source_path(root, config)?;
        }
        for file in &project.sources {
            source_path(root, file)?;
            sources.insert(file.replace('\\', "/"));
        }
    }
    Ok(sources)
}
fn validate(root: &Path, context_path: &Path, snapshot: &Snapshot) -> Result<(), EngineError> {
    let bytes = std::fs::read(context_path)?;
    if snapshot.schema_version != "1"
        || digest(&bytes) != snapshot.context_sha256
        || !snapshot.backend.starts_with("typescript:")
    {
        return Err(err("TypeScript context is stale or unsupported"));
    }
    let context: Context = serde_json::from_slice(&bytes).map_err(err)?;
    let expected = context_sources(root, &context)?;
    let actual = snapshot
        .sources
        .iter()
        .map(|s| s.path.clone())
        .collect::<BTreeSet<_>>();
    if !expected.is_subset(&actual) || actual.len() != snapshot.sources.len() {
        return Err(err("TypeScript source scope does not match context"));
    }
    let ids = context
        .projects
        .iter()
        .map(|p| &p.id)
        .collect::<BTreeSet<_>>();
    if ids != snapshot.projects.iter().map(|p| &p.id).collect()
        || snapshot.projects.len() != ids.len()
    {
        return Err(err("TypeScript project scope mismatch"));
    }
    for file in &snapshot.sources {
        if digest(&std::fs::read(source_path(root, &file.path)?)?) != file.sha256 {
            return Err(err(format!(
                "TypeScript source snapshot is stale: {}",
                file.path
            )));
        }
    }
    let compiler = context.typescript_path.canonicalize()?;
    // Resolve each bound input once. Re-resolving both sides for every declared
    // context file made cached review selection perform thousands of filesystem
    // queries on Windows; the content and resolution probes below still run.
    let canonical_inputs = snapshot
        .inputs
        .iter()
        .filter_map(|file| Path::new(&file.path).canonicalize().ok())
        .collect::<BTreeSet<_>>();
    if !context.typescript_path.is_absolute() || !canonical_inputs.contains(&compiler) {
        return Err(err("TypeScript compiler input is missing"));
    }
    let unique = snapshot
        .inputs
        .iter()
        .map(|f| &f.path)
        .collect::<BTreeSet<_>>();
    if unique.len() != snapshot.inputs.len() {
        return Err(err("Duplicate TypeScript input"));
    }
    let mut declared_inputs = context.context_files.clone();
    for project in &context.projects {
        if let Some(config) = &project.tsconfig {
            declared_inputs.push(source_path(root, config)?);
        }
    }
    if let Some(node) = &context.node_types {
        if !node.is_absolute() {
            return Err(err("node_types must be absolute"));
        }
        declared_inputs.push(node.join("package.json"));
    } else if snapshot
        .observations
        .iter()
        .flat_map(|o| &o.facts)
        .any(|f| f.kind == OperandFactKind::FixedFilesystemPath)
    {
        return Err(err(
            "Fixed TypeScript path facts require supplied Node metadata",
        ));
    }
    for expected in &declared_inputs {
        if !expected.is_absolute()
            || !expected.is_file()
            || !expected
                .canonicalize()
                .ok()
                .is_some_and(|path| canonical_inputs.contains(&path))
        {
            return Err(err("TypeScript context file input is missing"));
        }
    }
    for file in &snapshot.inputs {
        if !Path::new(&file.path).is_absolute()
            || std::fs::metadata(&file.path)?.len() > 32 * 1024 * 1024
            || digest(&std::fs::read(&file.path)?) != file.sha256
        {
            return Err(err(format!(
                "TypeScript compiler/dependency input is stale: {}",
                file.path
            )));
        }
    }
    for probe in &snapshot.probes {
        if !Path::new(&probe.path).is_absolute() {
            return Err(err("Invalid TypeScript resolution probe"));
        }
        let target = Path::new(&probe.path);
        let valid = match probe.kind.as_str() {
            "file" => probe.exists == Some(target.is_file()),
            "directory" => probe.exists == Some(target.is_dir()),
            "children" => {
                let mut children = if target.is_dir() {
                    std::fs::read_dir(target)?
                        .filter_map(Result::ok)
                        .filter(|e| e.path().is_dir())
                        .map(|e| e.path().to_string_lossy().replace('\\', "/"))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                children.sort();
                probe.children.as_ref() == Some(&children)
            }
            _ => false,
        };
        if !valid {
            return Err(err(format!(
                "TypeScript module resolution is stale: {}",
                probe.path
            )));
        }
    }
    Ok(())
}
fn validate_location(
    root: &Path,
    sources: &[FileHash],
    location: &Location,
) -> Result<(), EngineError> {
    if !sources.iter().any(|f| f.path == location.path) {
        return Err(err("Unknown TypeScript fact source"));
    }
    let text = std::fs::read_to_string(source_path(root, &location.path)?)?;
    for position in [&location.start, &location.end] {
        if !text.is_char_boundary(position.byte_offset) {
            return Err(err("Invalid TypeScript byte position"));
        }
        let prefix = &text[..position.byte_offset];
        if prefix.bytes().filter(|b| *b == b'\n').count() + 1 != position.line
            || prefix.rsplit('\n').next().unwrap_or_default().len() + 1 != position.column
        {
            return Err(err("TypeScript line/byte mismatch"));
        }
    }
    if location.start.byte_offset > location.end.byte_offset {
        return Err(err("Invalid TypeScript range"));
    }
    Ok(())
}
fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>, EngineError> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(err("TypeScript output exceeds size bound"));
    }
    Ok(bytes)
}
fn err(error: impl std::fmt::Display) -> EngineError {
    EngineError(error.to_string())
}
