//! Lightweight, deterministic credential-material detection over original source text.
//!
//! This module deliberately does not validate credentials, infer exposure, or emit raw values.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Location, Position,
    Provenance, Resolution, SecretDetector, SecretMetadata,
};

use crate::code::comments::CommentRanges;

const REDACTED: &str = "[REDACTED]";
const INLINE_ALLOW_MARKER: &str = "mehscan: allow-secret";
const GENERIC_MIN_LENGTH: usize = 16;
const GENERIC_MAX_LENGTH: usize = 256;
const GENERIC_MIN_ENTROPY: f64 = 3.5;

#[derive(Clone, Copy)]
enum Alphabet {
    Alphanumeric,
    Token,
}

#[derive(Clone, Copy)]
struct ProviderPattern {
    prefix: &'static str,
    minimum_length: usize,
    maximum_length: usize,
    exact_length: bool,
    alphabet: Alphabet,
    detector: SecretDetector,
    rule_id: &'static str,
    tag: &'static str,
}

const PROVIDERS: [ProviderPattern; 3] = [
    ProviderPattern {
        prefix: "ghp_",
        minimum_length: 40,
        maximum_length: 40,
        exact_length: true,
        alphabet: Alphabet::Alphanumeric,
        detector: SecretDetector::GithubPersonalAccessToken,
        rule_id: "secret-github-personal-access-token",
        tag: "github",
    },
    ProviderPattern {
        prefix: "glpat-",
        minimum_length: 26,
        maximum_length: 128,
        exact_length: false,
        alphabet: Alphabet::Token,
        detector: SecretDetector::GitlabPersonalAccessToken,
        rule_id: "secret-gitlab-personal-access-token",
        tag: "gitlab",
    },
    ProviderPattern {
        prefix: "xoxb-",
        minimum_length: 25,
        maximum_length: 128,
        exact_length: false,
        alphabet: Alphabet::Token,
        detector: SecretDetector::SlackToken,
        rule_id: "secret-slack-token",
        tag: "slack",
    },
];

#[derive(Clone)]
struct Candidate {
    start: usize,
    end: usize,
    detector: SecretDetector,
    rule_id: &'static str,
    provider_tag: Option<&'static str>,
    confidence: Confidence,
    entropy_millibits_per_character: Option<u16>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SecretAllowlist {
    fingerprints: BTreeSet<String>,
    detectors: BTreeSet<SecretDetector>,
    paths: Vec<String>,
}

pub(crate) struct SecretScan {
    pub evidence: Vec<Evidence>,
    pub suppressed: usize,
}

pub(crate) fn load_allowlist(root: &Path) -> (SecretAllowlist, Vec<String>) {
    let directory = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    let path = directory.join(".mehscan-secrets-allowlist");
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return (SecretAllowlist::default(), Vec::new());
        }
        Err(error) => {
            return (
                SecretAllowlist::default(),
                vec![format!("secret allowlist could not be read: {error}")],
            );
        }
    };
    SecretAllowlist::parse(&contents)
}

pub(crate) fn scan_source(
    path: &str,
    source: &str,
    comments: &CommentRanges,
    allowlist: &SecretAllowlist,
) -> SecretScan {
    let mut candidates = provider_candidates(source);
    let provider_ranges = candidates
        .iter()
        .map(|candidate| (candidate.start, candidate.end))
        .collect::<Vec<_>>();
    candidates.extend(
        generic_assignment_candidates(source)
            .into_iter()
            .filter(|candidate| {
                !provider_ranges.iter().any(|(start, end)| {
                    ranges_overlap(candidate.start, candidate.end, *start, *end)
                })
            }),
    );
    candidates.sort_by_key(|candidate| (candidate.start, candidate.end, candidate.rule_id));

    let mut seen = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut suppressed = 0;
    for candidate in candidates
        .into_iter()
        .filter(|candidate| seen.insert((candidate.start, candidate.end, candidate.rule_id)))
    {
        let value = &source[candidate.start..candidate.end];
        let candidate_fingerprint = fingerprint(value);
        if line_is_allowed(source, candidate.start)
            || allowlist.matches(path, candidate.detector, &candidate_fingerprint)
        {
            suppressed += 1;
            continue;
        }
        evidence.push(candidate_to_evidence(
            path,
            source,
            comments,
            candidate,
            candidate_fingerprint,
        ));
    }
    SecretScan {
        evidence,
        suppressed,
    }
}

pub(crate) fn guidance_for_rule(rule_id: &str) -> Option<&'static [&'static str]> {
    if !rule_id.starts_with("secret-") {
        return None;
    }
    Some(&[
        "Determine whether the material is a real credential or an inert test fixture without exposing its value.",
        "Check repository history and deployment scope, then recommend revocation or rotation when exposure is credible.",
        "Inspect privilege, environment, and reachable systems; a textual match alone does not prove validity or impact.",
    ])
}

fn provider_candidates(source: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for pattern in PROVIDERS {
        for (start, _) in source.match_indices(pattern.prefix) {
            if start > 0 && provider_character(source.as_bytes()[start - 1], pattern.alphabet) {
                continue;
            }
            let mut end = start + pattern.prefix.len();
            while end < source.len()
                && end - start < pattern.maximum_length
                && provider_character(source.as_bytes()[end], pattern.alphabet)
            {
                end += 1;
            }
            if end < source.len() && provider_character(source.as_bytes()[end], pattern.alphabet) {
                continue;
            }
            let length = end - start;
            if length < pattern.minimum_length
                || (pattern.exact_length && length != pattern.maximum_length)
            {
                continue;
            }
            let value = &source[start..end];
            if is_placeholder(value) {
                continue;
            }
            candidates.push(Candidate {
                start,
                end,
                detector: pattern.detector,
                rule_id: pattern.rule_id,
                provider_tag: Some(pattern.tag),
                confidence: Confidence::High,
                entropy_millibits_per_character: None,
            });
        }
    }
    candidates
}

fn generic_assignment_candidates(source: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut line_start = 0;
    for line_with_ending in source.split_inclusive('\n') {
        let line = line_with_ending.trim_end_matches(['\r', '\n']);
        if let Some((value_start, value_end)) = assignment_value_range(line) {
            let value = &line[value_start..value_end];
            if generic_candidate(value) {
                let entropy = shannon_entropy(value.as_bytes());
                candidates.push(Candidate {
                    start: line_start + value_start,
                    end: line_start + value_end,
                    detector: SecretDetector::GenericHighEntropyAssignment,
                    rule_id: "secret-generic-high-entropy-assignment",
                    provider_tag: None,
                    confidence: Confidence::Medium,
                    entropy_millibits_per_character: Some(
                        (entropy * 1000.0).round().min(f64::from(u16::MAX)) as u16,
                    ),
                });
            }
        }
        line_start += line_with_ending.len();
    }
    candidates
}

fn assignment_value_range(line: &str) -> Option<(usize, usize)> {
    let separator = assignment_separator(line)?;
    let left = &line[..separator];
    if !contains_sensitive_keyword(left) {
        return None;
    }

    let bytes = line.as_bytes();
    let mut start = separator + 1;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let quote = bytes
        .get(start)
        .copied()
        .filter(|byte| matches!(byte, b'\'' | b'"' | b'`'));
    if quote.is_some() {
        start += 1;
    }
    let mut end = start;
    while end < bytes.len() {
        let byte = bytes[end];
        if quote.is_some_and(|quote| byte == quote)
            || (quote.is_none()
                && (byte.is_ascii_whitespace()
                    || matches!(byte, b',' | b';')
                    || (byte == b'/' && bytes.get(end + 1) == Some(&b'/'))))
        {
            break;
        }
        end += 1;
    }
    (end > start).then_some((start, end))
}

fn assignment_separator(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut colon = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        } else if byte == b':' && colon.is_none() {
            colon = Some(index);
        } else if byte == b'='
            && !matches!(
                bytes.get(index.wrapping_sub(1)),
                Some(b'=' | b'!' | b'<' | b'>')
            )
            && !matches!(bytes.get(index + 1), Some(b'=' | b'>'))
        {
            return Some(index);
        }
    }
    colon
}

fn contains_sensitive_keyword(left: &str) -> bool {
    let lower = left.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "auth_token",
        "client_secret",
        "private_key",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword))
}

fn generic_candidate(value: &str) -> bool {
    if !(GENERIC_MIN_LENGTH..=GENERIC_MAX_LENGTH).contains(&value.len())
        || !value.is_ascii()
        || value.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || matches!(byte, b'\'' | b'"' | b'`' | b',' | b';' | b'<' | b'>')
        })
        || is_placeholder(value)
        || looks_like_uuid(value)
        || value.contains("://")
    {
        return false;
    }
    let mut classes = [false; 4];
    let mut unique = BTreeSet::new();
    for byte in value.bytes() {
        unique.insert(byte);
        if byte.is_ascii_lowercase() {
            classes[0] = true;
        } else if byte.is_ascii_uppercase() {
            classes[1] = true;
        } else if byte.is_ascii_digit() {
            classes[2] = true;
        } else {
            classes[3] = true;
        }
    }
    unique.len() >= 8
        && classes.into_iter().filter(|present| *present).count() >= 2
        && shannon_entropy(value.as_bytes()) >= GENERIC_MIN_ENTROPY
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "example",
        "sample",
        "dummy",
        "placeholder",
        "replace",
        "redacted",
        "changeme",
        "not-a-real",
        "not_real",
        "fake",
        "${",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || value
            .bytes()
            .next()
            .is_some_and(|first| value.bytes().all(|byte| byte == first))
}

fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes()[index] == b'-')
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u16; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = f64::from(count) / length;
            -probability * probability.log2()
        })
        .sum()
}

fn provider_character(byte: u8, alphabet: Alphabet) -> bool {
    match alphabet {
        Alphabet::Alphanumeric => byte.is_ascii_alphanumeric(),
        Alphabet::Token => byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'),
    }
}

fn line_is_allowed(source: &str, offset: usize) -> bool {
    let start = source[..offset].rfind('\n').map_or(0, |index| index + 1);
    let end = source[offset..]
        .find('\n')
        .map_or(source.len(), |index| offset + index);
    source[start..end]
        .to_ascii_lowercase()
        .contains(INLINE_ALLOW_MARKER)
}

impl SecretAllowlist {
    fn parse(contents: &str) -> (Self, Vec<String>) {
        let mut allowlist = Self::default();
        let mut warnings = Vec::new();
        for (index, raw_line) in contents.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((kind, value)) = line.split_once('=') else {
                warnings.push(format!(
                    "secret allowlist line {} must use key=value",
                    index + 1
                ));
                continue;
            };
            let kind = kind.trim();
            let value = value.trim();
            match kind {
                "fingerprint" if valid_fingerprint(value) => {
                    allowlist.fingerprints.insert(value.to_string());
                }
                "detector" => match parse_detector(value) {
                    Some(detector) => {
                        allowlist.detectors.insert(detector);
                    }
                    None => warnings.push(format!(
                        "secret allowlist line {} has an unknown detector",
                        index + 1
                    )),
                },
                "path" if valid_allowlist_path(value) => {
                    allowlist.paths.push(value.replace('\\', "/"));
                }
                "fingerprint" | "path" => warnings.push(format!(
                    "secret allowlist line {} has an invalid {kind}",
                    index + 1
                )),
                _ => warnings.push(format!(
                    "secret allowlist line {} has an unknown key",
                    index + 1
                )),
            }
        }
        (allowlist, warnings)
    }

    fn matches(&self, path: &str, detector: SecretDetector, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
            || self.detectors.contains(&detector)
            || self
                .paths
                .iter()
                .any(|pattern| wildcard_match(pattern.as_bytes(), path.as_bytes()))
    }
}

fn parse_detector(value: &str) -> Option<SecretDetector> {
    match value {
        "github_personal_access_token" => Some(SecretDetector::GithubPersonalAccessToken),
        "gitlab_personal_access_token" => Some(SecretDetector::GitlabPersonalAccessToken),
        "slack_token" => Some(SecretDetector::SlackToken),
        "generic_high_entropy_assignment" => Some(SecretDetector::GenericHighEntropyAssignment),
        _ => None,
    }
}

fn valid_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("sec-fnv1a64-")
        .is_some_and(|hash| hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_allowlist_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(['/', '\\'])
        && value.as_bytes().get(1) != Some(&b':')
        && !value.replace('\\', "/").split('/').any(|part| part == "..")
}

fn wildcard_match(pattern: &[u8], value: &[u8]) -> bool {
    fn matches(
        pattern: &[u8],
        value: &[u8],
        pattern_index: usize,
        value_index: usize,
        memo: &mut BTreeMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(result) = memo.get(&(pattern_index, value_index)) {
            return *result;
        }
        let result = if pattern_index == pattern.len() {
            value_index == value.len()
        } else if pattern[pattern_index] == b'*' {
            let double = pattern.get(pattern_index + 1) == Some(&b'*');
            let next_pattern = pattern_index + if double { 2 } else { 1 };
            matches(pattern, value, next_pattern, value_index, memo)
                || (value_index < value.len()
                    && (double || value[value_index] != b'/')
                    && matches(pattern, value, pattern_index, value_index + 1, memo))
        } else {
            value_index < value.len()
                && (pattern[pattern_index] == value[value_index]
                    || (pattern[pattern_index] == b'?' && value[value_index] != b'/'))
                && matches(pattern, value, pattern_index + 1, value_index + 1, memo)
        };
        memo.insert((pattern_index, value_index), result);
        result
    }

    matches(pattern, value, 0, 0, &mut BTreeMap::new())
}

fn candidate_to_evidence(
    path: &str,
    source: &str,
    comments: &CommentRanges,
    candidate: Candidate,
    fingerprint: String,
) -> Evidence {
    let value = &source[candidate.start..candidate.end];
    let location = location(path, source, candidate.start, candidate.end);
    let mut captures = BTreeMap::new();
    captures.insert(
        "secret".to_string(),
        Capture {
            text: REDACTED.to_string(),
            location: location.clone(),
        },
    );
    let mut tags = vec!["secret".to_string(), "credential".to_string()];
    if let Some(tag) = candidate.provider_tag {
        tags.push(tag.to_string());
    } else {
        tags.push("high_entropy".to_string());
    }
    Evidence {
        id: evidence_id(path, candidate.rule_id, candidate.start, candidate.end),
        kind: EvidenceKind::Secret,
        capability: Capability::CredentialMaterial,
        location,
        enclosing_symbol: None,
        captures,
        cwe_candidates: vec!["CWE-798".to_string()],
        tags,
        confidence: candidate.confidence,
        provenance: Provenance {
            resolution: Resolution::Textual,
            engine: "mehscan-secrets 0.1".to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(candidate.start..candidate.end),
            reachability: None,
            availability: None,
            literals: BTreeMap::new(),
            secret: Some(SecretMetadata {
                detector: candidate.detector,
                fingerprint,
                redacted: REDACTED.to_string(),
                value_length: value.len(),
                entropy_millibits_per_character: candidate.entropy_millibits_per_character,
            }),
            value_transform: None,
            http_routes: Vec::new(),
            resource_policy: None,
            runtime_environment: None,
        },
        symbol_resolution: None,
        rule_id: candidate.rule_id.to_string(),
        related_evidence: Vec::new(),
    }
}

fn location(path: &str, source: &str, start: usize, end: usize) -> Location {
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
    Position {
        line,
        column: source[line_start..offset].chars().count() + 1,
        byte_offset: offset,
    }
}

fn fingerprint(value: &str) -> String {
    stable_hash("sec-fnv1a64", &format!("mehscan-secret-v1\0{value}"))
}

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    stable_hash("ev", &format!("{path}\0{rule_id}\0{start}\0{end}"))
}

fn stable_hash(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_providers_and_generic_assignments_without_returning_values() {
        let source = concat!(
            "github_token = \"ghp_0123456789abcdefghijklmnopqrstuvwxyz\"\n",
            "database_password = \"N7vQ2mL9xK4pR8sT6wY3\"\n",
        );
        let scan = scan_source(
            "fixture.js",
            source,
            &CommentRanges::default(),
            &SecretAllowlist::default(),
        );
        let evidence = scan.evidence;
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0].confidence, Confidence::High);
        assert_eq!(evidence[1].confidence, Confidence::Medium);
        let debug = format!("{evidence:?}");
        assert!(!debug.contains("ghp_0123456789abcdefghijklmnopqrstuvwxyz"));
        assert!(!debug.contains("N7vQ2mL9xK4pR8sT6wY3"));
    }

    #[test]
    fn suppresses_placeholders_inline_allows_and_overlapping_generic_matches() {
        let source = concat!(
            "password = \"replace-with-a-real-password\"\n",
            "token = \"glpat-0123456789abcdefghij\" // mehscan: allow-secret\n",
            "api_key = \"ghp_0123456789abcdefghijklmnopqrstuvwxyz\"\n",
        );
        let scan = scan_source(
            "fixture.js",
            source,
            &CommentRanges::default(),
            &SecretAllowlist::default(),
        );
        let evidence = scan.evidence;
        assert_eq!(evidence.len(), 1);
        assert_eq!(scan.suppressed, 1);
        assert_eq!(
            evidence[0]
                .context
                .secret
                .as_ref()
                .expect("secret metadata")
                .detector,
            SecretDetector::GithubPersonalAccessToken
        );
    }

    #[test]
    fn entropy_is_bounded_and_deterministic() {
        assert_eq!(shannon_entropy(b"aaaaaaaaaaaaaaaa"), 0.0);
        let first = fingerprint("N7vQ2mL9xK4pR8sT6wY3");
        assert_eq!(first, fingerprint("N7vQ2mL9xK4pR8sT6wY3"));
        assert_ne!(first, fingerprint("N7vQ2mL9xK4pR8sT6wY4"));
    }

    #[test]
    fn assignment_parsing_ignores_padding_and_type_annotation_separators() {
        let line = "const password: string = \"Ab9+/Cd8Ef7Gh6Ij5Kl4==\"";
        let (start, end) = assignment_value_range(line).expect("assignment value");
        assert_eq!(&line[start..end], "Ab9+/Cd8Ef7Gh6Ij5Kl4==");
    }

    #[test]
    fn parses_fail_open_repository_allowlists_and_matches_globs() {
        let fingerprint = fingerprint("N7vQ2mL9xK4pR8sT6wY3");
        let input = format!(
            "fingerprint={fingerprint}\ndetector=slack_token\npath=config/**/*.yaml\ninvalid\npath=../outside\n"
        );
        let (allowlist, warnings) = SecretAllowlist::parse(&input);
        assert_eq!(warnings.len(), 2);
        assert!(allowlist.fingerprints.contains(&fingerprint));
        assert!(allowlist.detectors.contains(&SecretDetector::SlackToken));
        assert!(wildcard_match(b"config/**/*.yaml", b"config/prod/app.yaml"));
        assert!(!wildcard_match(b"config/*.yaml", b"config/prod/app.yaml"));
    }
}
