use std::collections::{BTreeMap, BTreeSet};

use mehscan_core::{Capability, EvidenceKind, Language};

const ESTABLISHED_WEB_LANGUAGES: [Language; 7] = [
    Language::Csharp,
    Language::Java,
    Language::Javascript,
    Language::Typescript,
    Language::Tsx,
    Language::Python,
    Language::Go,
];

// Rust deliberately omits generic framework-policy families until a real
// corpus provides exact API and safe-control truth. Keep its closed MVP
// surface explicit so parity does not become a lowest-common-denominator or
// force method-name-only observations.
const RUST_MVP_SURFACE: [Capability; 22] = [
    Capability::HttpRequestData,
    Capability::ExternalInput,
    Capability::DatabaseQuery,
    Capability::SqlParameterization,
    Capability::ProcessExecution,
    Capability::ProcessArgumentSeparation,
    Capability::FilesystemRead,
    Capability::FilesystemWrite,
    Capability::PathCanonicalization,
    Capability::PathContainmentCheck,
    Capability::OutboundNetworkRequest,
    Capability::UrlParsing,
    Capability::UrlDestinationValidation,
    Capability::Redirect,
    Capability::HtmlOutput,
    Capability::HtmlEncoding,
    Capability::Deserialization,
    Capability::Logging,
    Capability::CorsConfiguration,
    Capability::TlsConfiguration,
    Capability::MemorySafetyBoundary,
    Capability::NativeInteropBoundary,
];

// C and C++ share portable application-security relationships where native
// APIs have stable argument roles, then add native-specific evidence that the
// managed web language contract does not represent.
const C_FAMILY_MVP_SURFACE: [Capability; 11] = [
    Capability::ExternalInput,
    Capability::ProcessExecution,
    Capability::ProcessArgumentSeparation,
    Capability::DatabaseQuery,
    Capability::FilesystemRead,
    Capability::FilesystemWrite,
    Capability::PathCanonicalization,
    Capability::OutboundNetworkRequest,
    Capability::CryptographicHash,
    Capability::BufferWrite,
    Capability::FormatStringOutput,
];

const COMMON_DECLARATIVE_SURFACE: [Capability; 29] = [
    Capability::HttpRequestData,
    Capability::HttpRequestHandling,
    Capability::DatabaseQuery,
    Capability::SqlParameterization,
    Capability::ProcessExecution,
    Capability::ProcessArgumentSeparation,
    Capability::DynamicCodeExecution,
    Capability::DynamicCodeRestriction,
    Capability::FilesystemRead,
    Capability::FilesystemWrite,
    Capability::PathCanonicalization,
    Capability::PathContainmentCheck,
    Capability::OutboundNetworkRequest,
    Capability::UrlParsing,
    Capability::UrlDestinationValidation,
    Capability::Redirect,
    Capability::RedirectDestinationValidation,
    Capability::HtmlOutput,
    Capability::HtmlEncoding,
    Capability::Deserialization,
    Capability::CryptographicHash,
    Capability::Authentication,
    Capability::Authorization,
    Capability::CookieConfiguration,
    Capability::TlsConfiguration,
    Capability::FileUpload,
    Capability::UploadedFileContent,
    Capability::UploadedFilePath,
    Capability::UploadedFilenameValidation,
];

// PHP has an explicit partial native contract. Missing policy/control roles
// must not be silently counted as supported by an unrelated API inventory.
const PHP_NATIVE_SURFACE: [Capability; 18] = [
    Capability::HttpRequestData,
    Capability::DatabaseQuery,
    Capability::SqlParameterization,
    Capability::ProcessExecution,
    Capability::ProcessArgumentSeparation,
    Capability::DynamicCodeExecution,
    Capability::FilesystemRead,
    Capability::FilesystemWrite,
    Capability::PathCanonicalization,
    Capability::OutboundNetworkRequest,
    Capability::UrlParsing,
    Capability::Redirect,
    Capability::HtmlOutput,
    Capability::HtmlEncoding,
    Capability::Deserialization,
    Capability::CryptographicHash,
    Capability::FileUpload,
    Capability::TlsConfiguration,
];

const PHP_MISSING_SURFACE: [Capability; 11] = [
    Capability::HttpRequestHandling,
    Capability::DynamicCodeRestriction,
    Capability::PathContainmentCheck,
    Capability::UrlDestinationValidation,
    Capability::RedirectDestinationValidation,
    Capability::Authentication,
    Capability::Authorization,
    Capability::CookieConfiguration,
    Capability::UploadedFileContent,
    Capability::UploadedFilePath,
    Capability::UploadedFilenameValidation,
];

#[test]
fn php_parity_accounts_for_every_common_role_and_declared_cwe() {
    let supported = PHP_NATIVE_SURFACE.into_iter().collect::<BTreeSet<_>>();
    let missing = PHP_MISSING_SURFACE.into_iter().collect::<BTreeSet<_>>();
    assert!(supported.is_disjoint(&missing));
    assert_eq!(
        supported.union(&missing).copied().collect::<BTreeSet<_>>(),
        COMMON_DECLARATIVE_SURFACE.into_iter().collect()
    );
    let rules = mehscan_engine::rules::load_builtin_rules().unwrap();
    let php = rules
        .iter()
        .filter(|r| r.language == Language::Php)
        .collect::<Vec<_>>();
    assert_eq!(
        php.iter().map(|r| r.capability).collect::<BTreeSet<_>>(),
        supported,
        "Update PHP's support/gap matrix and semantic tests when adding a capability"
    );
    let declared = php
        .iter()
        .flat_map(|r| r.cwe.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared,
        [
            "CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-98", "CWE-327",
            "CWE-434", "CWE-502", "CWE-601", "CWE-918", "CWE-295", "CWE-943"
        ]
        .into_iter()
        .collect(),
        "A CWE declaration needs an independent source/safe-case budget, not only a catalog count"
    );
}

#[test]
fn established_web_languages_keep_the_common_declarative_surface() {
    let rules = mehscan_engine::rules::load_builtin_rules().expect("rule catalog should load");
    let mut capabilities_by_language = BTreeMap::<Language, BTreeSet<Capability>>::new();
    for rule in rules {
        capabilities_by_language
            .entry(rule.language)
            .or_default()
            .insert(rule.capability);
    }

    for language in ESTABLISHED_WEB_LANGUAGES {
        let present = capabilities_by_language
            .get(&language)
            .expect("priority language should have declarative rules");
        let missing = COMMON_DECLARATIVE_SURFACE
            .iter()
            .filter(|capability| !present.contains(capability))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "{language:?} lost common declarative capabilities: {missing:?}"
        );
    }
}

#[test]
fn rust_keeps_its_explicit_closed_mvp_surface() {
    let rules = mehscan_engine::rules::load_builtin_rules().expect("rule catalog should load");
    let present = rules
        .iter()
        .filter(|rule| rule.language == Language::Rust)
        .map(|rule| rule.capability)
        .collect::<BTreeSet<_>>();
    let missing = RUST_MVP_SURFACE
        .iter()
        .filter(|capability| !present.contains(capability))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "Rust lost closed MVP capabilities: {missing:?}"
    );
}

#[test]
fn c_and_cpp_keep_their_portable_and_native_mvp_surface() {
    let rules = mehscan_engine::rules::load_builtin_rules().expect("rule catalog should load");
    for language in [Language::C, Language::Cpp] {
        let present = rules
            .iter()
            .filter(|rule| rule.language == language)
            .map(|rule| rule.capability)
            .collect::<BTreeSet<_>>();
        let missing = C_FAMILY_MVP_SURFACE
            .iter()
            .filter(|capability| !present.contains(capability))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "{language:?} lost C-family MVP capabilities: {missing:?}"
        );
    }
}

#[test]
fn security_configuration_rules_have_decisive_ai_guidance() {
    let rules = mehscan_engine::rules::load_builtin_rules().expect("rule catalog should load");
    let incomplete = rules
        .iter()
        .filter(|rule| rule.kind == EvidenceKind::SecurityConfiguration)
        .filter(|rule| {
            rule.ai.investigate.is_empty()
                || rule.ai.verify.is_empty()
                || rule.ai.exclude.is_empty()
        })
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();

    assert!(
        incomplete.is_empty(),
        "security-configuration rules need investigate, verify, and exclude guidance: {incomplete:?}"
    );
}
