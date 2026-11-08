//! Offline lockfile-to-RustSec metadata matching. This is not source reachability.
use crate::EngineError;
use semver::{Version, VersionReq};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use toml_edit::DocumentMut;

#[derive(Debug, Serialize)]
pub struct RustAdvisoryReport {
    pub schema_version: u32,
    pub lockfile_sha256: String,
    pub database_files_sha256: BTreeMap<String, String>,
    pub registry_packages_checked: usize,
    pub excluded_packages: Vec<String>,
    pub findings: Vec<AdvisoryMatch>,
    pub diagnostics: Vec<String>,
    /// All eligible stable registry versions and relevant records parsed.
    /// Does not establish target applicability, reachability or database freshness.
    pub version_matching_complete: bool,
}
#[derive(Debug, Serialize)]
pub struct AdvisoryMatch {
    pub advisory_id: String,
    pub title: String,
    pub package: String,
    pub version: String,
    pub source: String,
    pub kind: String,
    pub informational: Option<String>,
    pub aliases: Vec<String>,
    pub categories: Vec<String>,
    pub patched: Vec<String>,
    pub unaffected: Vec<String>,
    pub affected_arch: Vec<String>,
    pub affected_os: Vec<String>,
    pub affected_functions: BTreeMap<String, Vec<String>>,
    pub advisory_path: String,
    pub assessment: &'static str,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn strings(item: Option<&toml_edit::Item>) -> Result<Vec<String>, EngineError> {
    let Some(item) = item else {
        return Ok(Vec::new());
    };
    let array = item
        .as_array()
        .ok_or_else(|| EngineError("expected string array".into()))?;
    array
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| EngineError("expected string array member".into()))
        })
        .collect()
}
fn required<'a>(doc: &'a DocumentMut, table: &str, key: &str) -> Result<&'a str, EngineError> {
    doc.get(table)
        .and_then(|t| t.get(key))
        .and_then(|v| v.as_str())
        .ok_or_else(|| EngineError(format!("missing {table}.{key}")))
}
fn body(source: &str) -> Result<(&str, &str), EngineError> {
    let source = source.trim_start_matches('\u{feff}');
    let (_, rest) = source
        .split_once("```toml")
        .ok_or_else(|| EngineError("missing TOML fence".into()))?;
    rest.split_once("```")
        .ok_or_else(|| EngineError("unterminated TOML fence".into()))
}
fn kind(info: Option<&str>, categories: &[String]) -> String {
    if categories.iter().any(|c| c == "malicious") {
        return "malicious".into();
    }
    info.unwrap_or("vulnerability").into()
}
fn ranges(values: &[String]) -> Result<Vec<VersionReq>, EngineError> {
    values
        .iter()
        .map(|s| {
            VersionReq::parse(s)
                .map_err(|e| EngineError(format!("invalid version range {s:?}: {e}")))
        })
        .collect()
}

pub fn inspect(
    root: &Path,
    database: &Path,
    include_informational: bool,
) -> Result<RustAdvisoryReport, EngineError> {
    if !database.join("crates").is_dir() {
        return Err(EngineError(
            "database must contain a crates directory".into(),
        ));
    }
    let bytes = fs::read(root.join("Cargo.lock"))?;
    let lock = std::str::from_utf8(&bytes)
        .map_err(|e| EngineError(e.to_string()))?
        .parse::<DocumentMut>()
        .map_err(|e| EngineError(e.to_string()))?;
    let packages = lock
        .get("package")
        .and_then(|p| p.as_array_of_tables())
        .ok_or_else(|| EngineError("Cargo.lock has no package records".into()))?;
    let mut report = RustAdvisoryReport {
        schema_version: 1,
        lockfile_sha256: hash(&bytes),
        database_files_sha256: BTreeMap::new(),
        registry_packages_checked: 0,
        excluded_packages: Vec::new(),
        findings: Vec::new(),
        diagnostics: Vec::new(),
        version_matching_complete: true,
    };
    let mut seen_packages = BTreeSet::new();
    for p in packages {
        let name = p
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError("package name missing".into()))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(EngineError("invalid crate name in lockfile".into()));
        }
        let version = p
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError(format!("version missing for {name}")))?;
        let source = p.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if !matches!(
            source,
            "registry+https://github.com/rust-lang/crates.io-index"
                | "sparse+https://index.crates.io/"
        ) {
            report.excluded_packages.push(format!(
                "{name}@{version}: local, git or unsupported registry source"
            ));
            continue;
        }
        if !seen_packages.insert((name.to_owned(), version.to_owned(), source.to_owned())) {
            continue;
        }
        let version_parsed =
            Version::parse(version).map_err(|e| EngineError(format!("{name}: {e}")))?;
        if !version_parsed.pre.is_empty() {
            report.diagnostics.push(format!(
                "{name}@{version}: prerelease version requires separate assessment"
            ));
            continue;
        }
        report.registry_packages_checked += 1;
        let entries = match fs::read_dir(database.join("crates").join(name)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                report.diagnostics.push(format!("{name}: {e}"));
                continue;
            }
        };
        let mut paths = Vec::new();
        for entry in entries {
            match entry {
                Ok(e) => {
                    if e.path().extension().is_some_and(|s| s == "md") {
                        paths.push(e.path());
                    }
                }
                Err(e) => report.diagnostics.push(format!("{name}: {e}")),
            }
        }
        paths.sort();
        let mut seen_ids = BTreeSet::new();
        for path in paths {
            let relative = path
                .strip_prefix(database)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let result = (|| -> Result<Option<AdvisoryMatch>, EngineError> {
                let bytes = fs::read(&path)?;
                if bytes.len() > 1024 * 1024 {
                    return Err(EngineError("advisory exceeds 1 MiB".into()));
                }
                report
                    .database_files_sha256
                    .insert(relative.clone(), hash(&bytes));
                let source_text =
                    std::str::from_utf8(&bytes).map_err(|e| EngineError(e.to_string()))?;
                let (metadata, description) = body(source_text)?;
                let doc = metadata
                    .parse::<DocumentMut>()
                    .map_err(|e| EngineError(e.to_string()))?;
                let id = required(&doc, "advisory", "id")?;
                let package = required(&doc, "advisory", "package")?;
                if !id.starts_with("RUSTSEC-") || package != name {
                    return Err(EngineError("advisory ID/package identity mismatch".into()));
                }
                if !seen_ids.insert(id.to_owned()) {
                    return Err(EngineError(format!("duplicate advisory ID {id}")));
                }
                let advisory = doc.get("advisory").unwrap();
                if advisory.get("withdrawn").is_some() {
                    return Ok(None);
                }
                let informational = advisory
                    .get("informational")
                    .map(|v| {
                        v.as_str().map(str::to_owned).ok_or_else(|| {
                            EngineError("informational kind must be a string".into())
                        })
                    })
                    .transpose()?;
                let categories = strings(advisory.get("categories"))?;
                let kind = kind(informational.as_deref(), &categories);
                if informational.is_some() && !include_informational && kind != "malicious" {
                    return Ok(None);
                }
                let versions = doc
                    .get("versions")
                    .and_then(|v| v.as_table())
                    .ok_or_else(|| EngineError("versions table missing".into()))?;
                let patched = strings(versions.get("patched"))?;
                let unaffected = strings(versions.get("unaffected"))?;
                if ranges(&patched)?
                    .iter()
                    .chain(ranges(&unaffected)?.iter())
                    .any(|r| r.matches(&version_parsed))
                {
                    return Ok(None);
                }
                let affected = doc.get("affected");
                let mut functions = BTreeMap::new();
                if let Some(t) = affected
                    .and_then(|a| a.get("functions"))
                    .and_then(|v| v.as_table())
                {
                    for (function, ranges_item) in t.iter() {
                        functions.insert(function.into(), strings(Some(ranges_item))?);
                    }
                }
                let title = description
                    .lines()
                    .find_map(|s| s.strip_prefix("# "))
                    .unwrap_or(id)
                    .trim()
                    .to_owned();
                Ok(Some(AdvisoryMatch {
                    advisory_id: id.into(),
                    title,
                    package: name.into(),
                    version: version.into(),
                    source: source.into(),
                    kind,
                    informational,
                    aliases: strings(advisory.get("aliases"))?,
                    categories,
                    patched,
                    unaffected,
                    affected_arch: strings(affected.and_then(|a| a.get("arch")))?,
                    affected_os: strings(affected.and_then(|a| a.get("os")))?,
                    affected_functions: functions,
                    advisory_path: relative.clone(),
                    assessment: "version_match_requires_applicability_review",
                }))
            })();
            match result {
                Ok(Some(finding)) => report.findings.push(finding),
                Ok(None) => {}
                Err(e) => report.diagnostics.push(format!("{relative}: {e}")),
            }
        }
    }
    report.version_matching_complete = report.diagnostics.is_empty();
    report.findings.sort_by(|a, b| {
        (&a.package, &a.version, &a.advisory_id).cmp(&(&b.package, &b.version, &b.advisory_id))
    });
    Ok(report)
}
