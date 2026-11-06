//! Explicitly opted-in SDK Razor generation, with source-validated C# projections.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mehscan_core::{Evidence, EvidenceContext, Location, OperandFact, OperandFactKind, Position};
use serde::{Deserialize, Serialize};

use crate::EngineError;

const MAX_OUTPUT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RazorOptions {
    pub backend: PathBuf,
    /// Explicit installed SDK directory, e.g. DOTNET_ROOT/sdk/10.0.402.
    pub sdk: PathBuf,
}

#[derive(Serialize)]
struct Input<'a> {
    path: &'a str,
    text: &'a str,
}
#[derive(Serialize)]
struct Request<'a> {
    schema_version: &'static str,
    root: PathBuf,
    sdk_path: PathBuf,
    files: Vec<Input<'a>>,
    projects: Vec<Input<'a>>,
}
#[derive(Deserialize)]
pub(crate) struct Output {
    schema_version: String,
    pub projections: Vec<Projection>,
    pub diagnostics: Vec<String>,
}
#[derive(Deserialize)]
pub(crate) struct Projection {
    pub path: String,
    pub code: String,
    mappings: Vec<Mapping>,
    facts: Vec<Navigation>,
    #[serde(default)]
    non_code: Vec<SourceRange>,
}
#[derive(Deserialize)]
struct SourceRange {
    start: usize,
    end: usize,
}
#[derive(Deserialize)]
struct Mapping {
    generated_start: usize,
    generated_end: usize,
    path: String,
    original_start: usize,
}
#[derive(Deserialize)]
struct Navigation {
    path: String,
    start: usize,
    end: usize,
    value: String,
}

pub(crate) fn collect(
    root: &Path,
    options: &RazorOptions,
    files: &BTreeMap<String, String>,
    projects: &[(String, String)],
) -> Result<Output, EngineError> {
    if files.len() > 4096 || files.values().map(String::len).sum::<usize>() > 32 * 1024 * 1024 {
        return Err(EngineError(
            "Razor source input exceeds 4096 files or 32 MiB; narrow the scan".into(),
        ));
    }
    let request = Request {
        schema_version: "1",
        root: root.canonicalize()?,
        sdk_path: options.sdk.canonicalize()?,
        files: files
            .iter()
            .map(|(path, text)| Input { path, text })
            .collect(),
        projects: projects
            .iter()
            .map(|(path, text)| Input { path, text })
            .collect(),
    };
    let input = serde_json::to_vec(&request).map_err(|e| EngineError(e.to_string()))?;
    let mut command = Command::new(options.backend.canonicalize()?);
    command
        .arg("--razor")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let writer = std::thread::spawn(move || {
        let mut stdin = stdin;
        stdin.write_all(&input)
    });
    let reader = std::thread::spawn(move || bounded(stdout, MAX_OUTPUT));
    let errors = std::thread::spawn(move || bounded(stderr, 8192));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(EngineError(
                "Razor frontend exceeded 60 seconds; markup-only coverage retained".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let bytes = reader
        .join()
        .map_err(|_| EngineError("Razor output reader failed".into()))??;
    let error = errors
        .join()
        .map_err(|_| EngineError("Razor error reader failed".into()))??;
    let written = writer
        .join()
        .map_err(|_| EngineError("Razor input writer failed".into()))?;
    if !status.success() {
        return Err(EngineError(format!(
            "Razor frontend failed: {}",
            String::from_utf8_lossy(&error).trim()
        )));
    }
    written?;
    let output: Output = serde_json::from_slice(&bytes).map_err(|e| EngineError(e.to_string()))?;
    if output.schema_version != "1" {
        return Err(EngineError("Unsupported Razor frontend schema".into()));
    }
    for projection in &output.projections {
        projection.validate(files)?;
    }
    Ok(output)
}

fn bounded(reader: impl Read, max: u64) -> Result<Vec<u8>, EngineError> {
    let mut bytes = Vec::new();
    reader.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(EngineError(
            "Razor helper output exceeded its size limit".into(),
        ));
    }
    Ok(bytes)
}

impl Projection {
    fn validate(&self, files: &BTreeMap<String, String>) -> Result<(), EngineError> {
        let invalid =
            || EngineError("Razor frontend returned an invalid original-source mapping".into());
        let original = files.get(&self.path).ok_or_else(invalid)?;
        let extension = Path::new(&self.path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case("razor") && !extension.eq_ignore_ascii_case("cshtml") {
            return Err(invalid());
        }
        for map in &self.mappings {
            let Some(length) = map
                .generated_end
                .checked_sub(map.generated_start)
                .filter(|n| *n > 0)
            else {
                return Err(invalid());
            };
            let Some(end) = map.original_start.checked_add(length) else {
                return Err(invalid());
            };
            if map.path != self.path
                || self
                    .code
                    .get(map.generated_start..map.generated_end)
                    .is_none()
                || self.code.get(map.generated_start..map.generated_end)
                    != original.get(map.original_start..end)
            {
                return Err(invalid());
            }
        }
        for fact in &self.facts {
            if fact.path != self.path
                || original.get(fact.start..fact.end).is_none()
                || fact.value.len() > 4096
            {
                return Err(invalid());
            }
        }
        for range in &self.non_code {
            if original.get(range.start..range.end).is_none() {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(crate) fn is_non_code(&self, location: &Location) -> bool {
        location.path == self.path
            && self
                .non_code
                .iter()
                .any(|r| r.start <= location.start.byte_offset && r.end >= location.end.byte_offset)
    }

    fn location(&self, location: &Location, original: &str) -> Option<Location> {
        if location.path != self.path {
            return None;
        }
        let start = location.start.byte_offset;
        let end = location.end.byte_offset;
        let map = self
            .mappings
            .iter()
            .find(|m| m.generated_start <= start && m.generated_end >= end)?;
        let begin = map
            .original_start
            .checked_add(start.checked_sub(map.generated_start)?)?;
        let finish = begin.checked_add(end.checked_sub(start)?)?;
        original.get(begin..finish)?;
        Some(location_at(&self.path, original, begin, finish))
    }

    /// Only fully mapped evidence survives. Generated control flow and scaffolding
    /// cannot become a native connectivity proof; AI inspects original callbacks.
    pub(crate) fn restore(&self, item: &mut Evidence, original: &str) -> bool {
        let Some(location) = self.location(&item.location, original) else {
            return false;
        };
        let mut captures = item.captures.clone();
        for capture in captures.values_mut() {
            let Some(location) = self.location(&capture.location, original) else {
                return false;
            };
            let text = &original[location.start.byte_offset..location.end.byte_offset];
            if text != capture.text {
                return false;
            }
            capture.location = location;
        }
        let mut facts: Vec<_> = item
            .context
            .operand_facts
            .iter()
            .filter_map(|f| {
                let mut fact = f.clone();
                fact.location = self.location(&f.location, original)?;
                Some(fact)
            })
            .collect();
        facts.extend(self.facts.iter().map(|f| OperandFact {
            role: "component_context".into(),
            kind: OperandFactKind::OperandBoundary,
            location: location_at(&self.path, original, f.start, f.end),
            value: f.value.clone(),
            remaining_checks: vec![
                "effective_render_mode_and_callback_reachability".into(),
                "input_state_validation_and_check_to_effect".into(),
            ],
        }));
        item.location = location;
        item.captures = captures;
        item.context = EvidenceContext {
            operand_facts: facts,
            ..EvidenceContext::default()
        };
        item.related_evidence.clear();
        item.tags.push("razor-sdk-source-projection".into());
        item.id = evidence_id(&item.rule_id, &item.location);
        true
    }
}

fn evidence_id(rule: &str, location: &Location) -> String {
    let input = format!(
        "{}\0{rule}\0{}\0{}",
        location.path, location.start.byte_offset, location.end.byte_offset
    );
    let mut hash = 0xcbf29ce484222325_u64;
    for b in input.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
fn location_at(path: &str, source: &str, start: usize, end: usize) -> Location {
    let position = |offset| {
        let prefix = &source[..offset];
        Position {
            line: prefix.bytes().filter(|b| *b == b'\n').count() + 1,
            column: prefix
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .chars()
                .count()
                + 1,
            byte_offset: offset,
        }
    };
    Location {
        path: path.into(),
        start: position(start),
        end: position(end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection() -> Projection {
        Projection {
            path: "Widget.razor".into(),
            code: "class Generated { string value = \"界😀\"; }".into(),
            mappings: vec![Mapping {
                generated_start: 18,
                generated_end: 45,
                path: "Widget.razor".into(),
                original_start: 8,
            }],
            facts: vec![],
            non_code: vec![],
        }
    }

    #[test]
    fn mappings_validate_exact_utf8_source_and_reject_untrusted_regions() {
        let source = "@code { string value = \"界😀\"; }";
        let files = BTreeMap::from([("Widget.razor".into(), source.into())]);
        let mut projection = projection();
        let code_start = projection.code.find("string").unwrap();
        let code_end = projection.code.rfind(';').unwrap() + 1;
        projection.mappings[0].generated_start = code_start;
        projection.mappings[0].generated_end = code_end;
        assert!(projection.validate(&files).is_ok());
        let mapped = projection
            .location(
                &location_at("Widget.razor", &projection.code, code_start, code_end),
                source,
            )
            .unwrap();
        assert_eq!(
            &source[mapped.start.byte_offset..mapped.end.byte_offset],
            "string value = \"界😀\";"
        );
        assert!(
            projection
                .location(&location_at("Widget.razor", &projection.code, 0, 5), source)
                .is_none()
        );
        projection.mappings[0].original_start += 1;
        assert!(projection.validate(&files).is_err());
        projection.mappings[0].original_start -= 1;
        projection.mappings[0].path = "Other.razor".into();
        assert!(projection.validate(&files).is_err());
    }

    #[test]
    fn positions_use_original_scalar_columns_not_generated_or_utf16_columns() {
        let source = "first\r\n界😀call()";
        let start = source.find("call").unwrap();
        let location = location_at("A.razor", source, start, source.len());
        assert_eq!(location.start.line, 2);
        assert_eq!(location.start.column, 3);
        assert_eq!(location.start.byte_offset, 14);
    }
}
