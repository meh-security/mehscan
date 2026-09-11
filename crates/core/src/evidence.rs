use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Capture, Location};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Entrypoint,
    Source,
    Sink,
    Guard,
    Sanitizer,
    Validation,
    Resource,
    SensitiveOperation,
    SecurityConfiguration,
    Literal,
    Secret,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ProcessExecution,
    ProcessArgumentSeparation,
    LdapQuery,
    LdapFilterEncoding,
    LdapDistinguishedNameEncoding,
    DynamicCodeExecution,
    DynamicCodeRestriction,
    TemplateEvaluation,
    DatabaseQuery,
    SqlParameterization,
    FilesystemRead,
    FilesystemWrite,
    PathCanonicalization,
    PathContainmentCheck,
    OutboundNetworkRequest,
    UrlParsing,
    UrlDestinationValidation,
    Redirect,
    RedirectDestinationValidation,
    HtmlOutput,
    HtmlEncoding,
    HttpHeaderOutput,
    Serialization,
    Deserialization,
    DeserializationRestriction,
    XmlParsing,
    CryptographicHash,
    FixedFormatTransform,
    CryptographicEncryption,
    RandomGeneration,
    Authentication,
    Authorization,
    ResourceAccess,
    Logging,
    TokenGeneration,
    CookieConfiguration,
    CorsConfiguration,
    MemorySafetyBoundary,
    NativeInteropBoundary,
    TlsConfiguration,
    FileUpload,
    UploadedFileContent,
    UploadedFilePath,
    ArchiveEntryPath,
    UploadedFilenameValidation,
    StoredUserContent,
    HttpRequestHandling,
    HttpRequestData,
    RpcRequestData,
    BrowserInput,
    BrowserNavigation,
    BrowserCredentialedRequest,
    BrowserMessageSend,
    ExternalInput,
    ModelToolInput,
    CredentialMaterial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Ast,
    Textual,
    External,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolResolutionMethod {
    FullyQualified,
    Alias,
    ImportedNamespace,
    StaticImport,
    Unqualified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolConfidence {
    Exact,
    High,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityState {
    Reachable,
    Unreachable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityReason {
    AfterReturn,
    AfterThrow,
    AfterRaise,
    AfterBreak,
    AfterContinue,
    AfterTerminatingConditional,
    ConditionAlwaysFalse,
    ConditionAlwaysTrue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Reachability {
    pub state: ReachabilityState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<ReachabilityReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Always,
    Conditional,
    Excluded,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Availability {
    pub state: AvailabilityState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiteralState {
    Known,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LiteralValue {
    Boolean(bool),
    Number(String),
    String(String),
    Null,
    Enum(String),
    Array(Vec<LiteralValue>),
    Map(BTreeMap<String, LiteralValue>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LiteralEvaluation {
    pub state: LiteralState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<LiteralValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constant_fragments: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretDetector {
    GithubPersonalAccessToken,
    GitlabPersonalAccessToken,
    SlackToken,
    GenericHighEntropyAssignment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub detector: SecretDetector,
    /// Stable, non-cryptographic correlation key. It is not an authentication hash.
    pub fingerprint: String,
    /// Safe output substituted for the original credential material.
    pub redacted: String,
    pub value_length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_millibits_per_character: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedOutputFormat {
    LowercaseHexadecimal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValueTransform {
    pub output_format: FixedOutputFormat,
    pub exact_length: usize,
    pub algorithm: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpRouteAccess {
    Unknown,
    Authenticated,
    RoleRestricted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HttpRouteContext {
    pub method: String,
    pub path: String,
    pub access: HttpRouteAccess,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guards: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePolicyState {
    Unknown,
    OwnerScoped,
    PublicCatalog,
    SharedResource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourcePolicyContext {
    pub state: ResourcePolicyState,
    pub basis: String,
}

/// The runtime in which JavaScript-family source is expected to execute.
///
/// This is deliberately an evidence fact rather than a vulnerability verdict:
/// mixed and convention-free modules remain reviewable without pretending that
/// every network call is a server-side request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironment {
    Server,
    Browser,
    Mixed,
    Unknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceContext {
    pub comment: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<Reachability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<Availability>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub literals: BTreeMap<String, LiteralEvaluation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_transform: Option<ValueTransform>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_routes: Vec<HttpRouteContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy: Option<ResourcePolicyContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_environment: Option<RuntimeEnvironment>,
}

impl EvidenceContext {
    pub fn is_empty(&self) -> bool {
        !self.comment
            && self.reachability.is_none()
            && self.availability.is_none()
            && self.literals.is_empty()
            && self.secret.is_none()
            && self.value_transform.is_none()
            && self.http_routes.is_empty()
            && self.resource_policy.is_none()
            && self.runtime_environment.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolResolution {
    pub canonical: String,
    pub observed: String,
    pub method: SymbolResolutionMethod,
    pub confidence: SymbolConfidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub resolution: Resolution,
    pub engine: String,
    pub rule_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Deterministic ID derived from rule, path, and byte range.
    pub id: String,
    pub kind: EvidenceKind,
    pub capability: Capability,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub captures: BTreeMap<String, Capture>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub confidence: Confidence,
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "EvidenceContext::is_empty")]
    pub context: EvidenceContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_resolution: Option<SymbolResolution>,
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_evidence: Vec<String>,
}
