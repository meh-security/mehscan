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
    XpathQuery,
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
    /// A native memory-writing operation whose safety depends on destination
    /// capacity, source extent, size arithmetic, or termination semantics.
    BufferWrite,
    /// Exact local evidence that a native byte-copy size does not exceed a
    /// statically declared destination array capacity.
    BufferCapacityValidation,
    /// Exact local evidence that a bounded native string copy is followed by
    /// an in-scope terminator write within the destination capacity.
    StringTerminationValidation,
    /// An explicitly signed native value converted to the unsigned size domain
    /// immediately used by an allocation or buffer operation.
    SignedSizeConversion,
    /// A native allocation or buffer operation whose extent contains an exact
    /// signed-to-size conversion.
    SignedSizeMemoryOperation,
    /// Exact local evidence that the signed size value cannot be negative
    /// before its conversion and memory use.
    NonnegativeSizeValidation,
    /// A standard C heap allocation assigned directly to a local pointer whose
    /// same-function release contract can be established.
    LocalHeapAllocation,
    /// An exact `free(local)` that establishes the expected same-function
    /// release point for a local heap allocation.
    LocalHeapDeallocation,
    /// An exact `free(local)` executed in the same block before an early return.
    EarlyExitDeallocation,
    /// A C++ scalar or array allocation created by an ordinary `new`
    /// expression or standard `make_unique` construction.
    CppHeapAllocation,
    /// A C++ `delete` or `delete[]` applied directly to the allocated local.
    CppHeapDeallocation,
    /// Exact agreement between scalar/array allocation and deallocation forms.
    CppAllocationFamilyValidation,
    /// A standard `std::unique_ptr` or `std::make_unique` owner whose type
    /// establishes scalar versus array destruction semantics.
    CppRaiiOwner,
    /// Direct construction of a standard unique owner from a raw local.
    CppOwnershipTransfer,
    /// A C-family conversion that may discard higher-order integer bits before
    /// the converted value reaches a security-relevant arithmetic operation.
    IntegerNarrowing,
    /// A C-family division whose divisor is linked to a potentially lossy
    /// integer conversion and whose nonzero invariant requires review.
    ArithmeticDivision,
    /// Exact local evidence that a divisor derived from a narrowing conversion
    /// is rejected or positively constrained before division.
    NonzeroValidation,
    /// A caller-supplied quantity that controls a native operation and is
    /// subject to a domain-specific limit.
    InputQuantity,
    /// A limit computed from local object state rather than a fixed global
    /// storage maximum.
    DomainLimitComputation,
    /// Exact local evidence that an input quantity is rejected when it exceeds
    /// the computed domain limit.
    DomainLimitValidation,
    /// A native memory operation whose extent is derived from an input count.
    CountControlledMemoryOperation,
    /// A C-family arithmetic accumulator whose declared fixed width constrains
    /// a later security-relevant calculation.
    IntegerWidthConstraint,
    /// A C-family multiplication linked to a downstream memory-operation
    /// extent through an exact local value handoff.
    ArithmeticMultiplication,
    /// Exact local evidence that multiplication operands are range-checked
    /// against the accumulator maximum before the operation.
    MultiplicationOverflowValidation,
    /// A native input quantity whose safe upper bound depends on the target
    /// architecture's representable allocation size.
    ArchitectureSizeInput,
    /// Arithmetic derived from an architecture-sized input that determines a
    /// subsequent native allocation extent.
    AllocationSizeComputation,
    /// Exact rejecting validation that constrains an input using an
    /// architecture-size maximum before allocation-size arithmetic.
    ArchitectureSizeValidation,
    /// A pointer to a block-scoped native object stored in state that can
    /// outlive the declaring function.
    StackAddressEscape,
    /// A call site that binds a concrete callback and owner object into a
    /// callback-executing wrapper.
    LifetimeCallbackHandoff,
    /// A wrapper dereference of callback-mutated owner state after the
    /// callback has returned.
    PostReturnDereference,
    /// Exact restoration of escaped owner state before the stack object's
    /// lifetime ends.
    StackLifetimeRestoration,
    /// A C-family call whose documented status result reports that a pointer
    /// argument may no longer be valid after the call returns.
    InvalidatingReturnContract,
    /// A use of a pointer argument after a call that may have invalidated it.
    PostInvalidationUse,
    /// Exact status handling that terminates the current path before a
    /// possibly invalidated pointer can be used again.
    InvalidationStatusValidation,
    /// A binary or serialized blob returned by a native loader for subsequent
    /// fixed-layout processing.
    SerializedBlobLoad,
    /// A native copy whose extent is derived from the expected fixed layout
    /// of a loaded serialized blob.
    SerializedBlobCopy,
    /// Exact validation that the loaded blob length matches the fixed-layout
    /// copy extent before the copy occurs.
    SerializedBlobLengthValidation,
    /// A scalar count or dimension returned by a native serialized-input
    /// loader and used in a local memory-extent calculation.
    SerializedScalarLoad,
    /// A native allocation/copy extent computed from a serialized scalar and
    /// additional local multiplicative operands.
    LoadedMemoryExtent,
    /// Exact rejecting checks that make a loaded multiplicative memory extent
    /// representable before it is computed and consumed.
    MemoryExtentOverflowValidation,
    /// A decoded native length or extent compared with an authoritative
    /// remaining-input boundary before buffer consumption.
    DecodedInputExtent,
    /// A native buffer-consuming operation whose source position and extent
    /// are locally related to a remaining-input check.
    RemainingInputRead,
    /// A non-wrapping rejecting comparison that proves a decoded extent fits
    /// the authoritative remaining input before the read.
    RemainingInputValidation,
    /// A native object member whose required initialization can be skipped by
    /// an exceptional input path.
    RequiredStateInitialization,
    /// A required object-state pointer passed to a helper that consumes it.
    StatePointerHandoff,
    /// An indexed access through a handed-off required-state pointer.
    StateDependentDereference,
    /// A fatal rejection that prevents execution from continuing with absent
    /// required object state.
    FatalStateInvariantValidation,
    /// A native allocation stored in persistent object state whose release is
    /// governed by an independent ownership contract.
    OwnedResourceAllocation,
    /// Registration of an ownership bit for a specific allocated state member.
    OwnershipFlagRegistration,
    /// Cleanup of an allocated state member gated by its ownership bit.
    OwnershipGatedRelease,
    /// A printf-family operation where the format string controls how later
    /// arguments are interpreted.
    FormatStringOutput,
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
