use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mehscan_core::{AvailabilityState, CandidateReport, Capability, Language, SecurityPathState};

#[test]
fn native_same_path_check_use_requires_atomic_or_nofollow_controls() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-toctou-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create TOCTOU fixture");
    let source = r#"
#define F_OK 0
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 64
#define O_EXCL 128
#define O_NOFOLLOW 256
int access(const char *, int);
int stat(const char *, void *);
int lstat(const char *, void *);
int open(const char *, int, ...);
void *fopen(const char *, const char *);
int unlink(const char *);

void cases(char *p1, char *p2, char *p3, char *p4, char *p5,
           char *p6, char *p7, char *other, void *st) {
    if (access(p1, F_OK) != 0) open(p1, O_WRONLY | O_CREAT, 0600);
    if (access(p2, F_OK) != 0)
        open(p2, O_WRONLY | O_CREAT | O_EXCL, 0600);
    stat(p3, st);
    fopen(p3, "w");
    lstat(p4, st);
    open(p4, O_RDONLY);
    lstat(p5, st);
    open(p5, O_RDONLY | O_NOFOLLOW);
    if (access(p7, F_OK) != 0) {}
    open(p7, O_WRONLY | O_CREAT | O_EXCL, 0600);

    access(p6, F_OK);
    p6 = other;
    unlink(p6);
    access(other, F_OK);
    unlink(p1);
    api.access(p1, F_OK);
    api.open(p1, O_WRONLY);
}

"#;
    fs::write(root.join("cases.c"), source).expect("write C TOCTOU fixture");
    fs::write(root.join("cases.cpp"), source).expect("write C++ TOCTOU fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan TOCTOU fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat TOCTOU fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.provenance.engine.contains("same-path check-use"))
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 16);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        4
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        12
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.cwe_candidates == ["CWE-59"])
            .count(),
        4
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(40), true)
        .expect("TOCTOU reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.cwe_candidates == ["CWE-367"]
            && review
                .open_questions
                .iter()
                .any(|question| question.contains("already-open directory/file descriptor"))
    }));
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "native-same-path-metadata-check")
            .count(),
        12,
        "reassignment, different-path use, and member-call lookalikes stay excluded"
    );
    fs::remove_dir_all(&root).expect("remove TOCTOU fixture");
}

#[test]
fn native_same_path_paths_share_one_sink_evidence_item() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-shared-toctou-sink-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create shared TOCTOU sink fixture");
    fs::write(
        root.join("shared.c"),
        r#"
#define O_RDONLY 0
int stat(const char *, void *);
int lstat(const char *, void *);
int open(const char *, int, ...);

void shared_sink(char *path, void *metadata) {
    stat(path, metadata);
    lstat(path, metadata);
    open(path, O_RDONLY);
}
"#,
    )
    .expect("write shared TOCTOU sink fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan shared TOCTOU sink fixture");
    let unique_ids = result
        .evidence
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique_ids.len(), result.evidence.len());
    CandidateReport::from_scan(&result).expect("build candidates from shared sink evidence");

    let sink = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "native-same-path-filesystem-use")
        .expect("shared filesystem use");
    assert_eq!(sink.related_evidence.len(), 2);
    fs::remove_dir_all(&root).expect("remove shared TOCTOU sink fixture");
}

#[test]
fn libarchive_extraction_keeps_path_symlink_and_privilege_invariants_separate() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-libarchive-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create libarchive fixture");
    let source = r#"
#define ARCHIVE_EXTRACT_OWNER 1
#define ARCHIVE_EXTRACT_PERM 2
#define ARCHIVE_EXTRACT_SECURE_SYMLINKS 256
#define ARCHIVE_EXTRACT_SECURE_NODOTDOT 512
#define ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS 65536
int archive_read_extract(void *, void *, int);
int archive_read_extract2(void *, void *, void *);
int archive_write_disk_set_options(void *, int);
int archive_write_header(void *, void *);

void cases(void *reader, void *entry, void *disk, void *conditional_disk, int dynamic_flags) {
    archive_read_extract(reader, entry, 0);
    archive_read_extract(reader, entry,
        ARCHIVE_EXTRACT_SECURE_NODOTDOT |
        ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS |
        ARCHIVE_EXTRACT_SECURE_SYMLINKS);
    archive_read_extract(reader, entry, ARCHIVE_EXTRACT_SECURE_NODOTDOT);
    archive_read_extract(reader, entry, ARCHIVE_EXTRACT_SECURE_SYMLINKS);
    archive_read_extract(reader, entry,
        ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_PERM);

    archive_write_disk_set_options(disk,
        ARCHIVE_EXTRACT_SECURE_NODOTDOT |
        ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS |
        ARCHIVE_EXTRACT_SECURE_SYMLINKS);
    archive_write_header(disk, entry);
    archive_read_extract2(reader, entry, disk);

    int fixed_flags;
    fixed_flags = ARCHIVE_EXTRACT_SECURE_NODOTDOT;
    fixed_flags |= ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;
    fixed_flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;
    archive_read_extract(reader, entry, fixed_flags);

    archive_read_extract(reader, entry, dynamic_flags);
    int changed_flags = ARCHIVE_EXTRACT_SECURE_SYMLINKS;
    changed_flags = dynamic_flags;
    archive_read_extract(reader, entry, changed_flags);
    api.archive_read_extract(reader, entry, ARCHIVE_EXTRACT_SECURE_SYMLINKS);
    archive_write_header(reader, entry);
    if (dynamic_flags)
        archive_write_disk_set_options(conditional_disk,
            ARCHIVE_EXTRACT_SECURE_NODOTDOT |
            ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS |
            ARCHIVE_EXTRACT_SECURE_SYMLINKS);
    archive_write_header(conditional_disk, entry);
}
"#;
    fs::write(root.join("cases.c"), source).expect("write C libarchive fixture");
    fs::write(root.join("cases.cpp"), source).expect("write C++ libarchive fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan libarchive fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat libarchive fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.provenance
                .engine
                .contains("libarchive extraction-options")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 50);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        28
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        22
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.cwe_candidates == ["CWE-732"])
            .count(),
        2,
        "privilege-sensitive owner/permission restore is separate review context"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(80), true)
        .expect("libarchive extraction reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.cwe_candidates == ["CWE-732"]
            && review
                .open_questions
                .iter()
                .any(|question| question.contains("privileged ownership or modes"))
    }));
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "native-libarchive-entry-path")
            .count(),
        16,
        "dynamic, reassigned, member-call, and writer-without-disk-setup lookalikes stay excluded"
    );
    fs::remove_dir_all(&root).expect("remove libarchive fixture");
}

#[test]
fn libxml2_external_entity_options_preserve_partial_control_semantics() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-libxml2-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create libxml2 fixture");
    let source = r#"
typedef void xmlDoc;
xmlDoc *xmlReadMemory(const char *, int, const char *, const char *, int);
xmlDoc *xmlReadFile(const char *, const char *, int);
xmlDoc *xmlCtxtReadMemory(void *, const char *, int, const char *, const char *, int);
void *xmlReaderForIO(void *, void *, void *, const char *, const char *, int);
#define XML_PARSE_NOENT 2
#define XML_PARSE_DTDLOAD 4
#define XML_PARSE_DTDATTR 8
#define XML_PARSE_NONET 2048
#define XML_PARSE_NO_XXE 8388608

void cases(const char *xml, int dynamic_options) {
    xmlReadMemory(xml, 10, 0, 0, XML_PARSE_NOENT);
    xmlReadFile("input.xml", 0, XML_PARSE_DTDLOAD | XML_PARSE_NONET);
    xmlCtxtReadMemory(0, xml, 10, 0, 0,
        XML_PARSE_DTDATTR | XML_PARSE_NO_XXE);
    xmlReaderForIO(0, 0, 0, 0, 0,
        XML_PARSE_NOENT | XML_PARSE_NONET | XML_PARSE_NO_XXE);
    int fixed_options = XML_PARSE_NOENT | XML_PARSE_NONET;
    xmlReadMemory(xml, 10, 0, 0, fixed_options);

    xmlReadMemory(xml, 10, 0, 0, 0);
    xmlReadMemory(xml, 10, 0, 0, dynamic_options);
    xmlReadMemory(xml, XML_PARSE_NOENT, 0, 0, 0);
    notXmlReadMemory(xml, 10, 0, 0, XML_PARSE_NOENT);
    ops.xmlReadMemory(xml, 10, 0, 0, XML_PARSE_NOENT);
}
"#;
    fs::write(root.join("cases.c"), source).expect("write C libxml2 fixture");
    fs::write(root.join("cases.cpp"), source).expect("write C++ libxml2 fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan libxml2 fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat libxml2 fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::XmlParsing
                && path.provenance.engine.contains("libxml2 parser-options")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 10);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        4
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        6
    );
    assert!(paths.iter().all(|path| path.cwe_candidates == ["CWE-611"]));
    assert_eq!(
        paths
            .iter()
            .flat_map(|path| &path.steps)
            .filter(|step| step.kind == mehscan_core::SecurityPathStepKind::IneffectiveProtection)
            .count(),
        6,
        "NONET is visible but does not by itself establish XXE protection"
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "native-libxml2-external-entity-enablement")
            .count(),
        10,
        "zero, dynamic, wrong-position, and lookalike calls stay outside the claim"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), true)
        .expect("libxml2 reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::XmlParsing
            && review
                .open_questions
                .iter()
                .any(|question| question.contains("external DTD or entity"))
    }));
    fs::remove_dir_all(&root).expect("remove libxml2 fixture");
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-native-cpp-mvp")
}

#[test]
fn raw_native_buffer_writes_stay_out_of_ai_observation_jobs() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-buffer-review-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create native buffer review fixture");
    fs::write(
        root.join("buffer.c"),
        r#"
typedef unsigned long size_t;
void *memcpy(void *destination, const void *source, size_t size);
char *getenv(const char *name);

void raw_copy(char *destination, const char *source, size_t size) {
    memcpy(destination, source, size);
}

void linked_copy(char *destination) {
    char *input = getenv("MEHSCAN_INPUT");
    memcpy(destination, input, 16);
}
"#,
    )
    .expect("write native buffer review fixture");

    let scan = mehscan_engine::scan_path(&root).expect("scan native buffer review fixture");
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|item| item.capability == Capability::BufferWrite)
            .count(),
        2,
        "raw native buffer operations remain available as scan evidence"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), true)
        .expect("build native buffer reviews");
    assert!(
        reviews
            .reviews
            .iter()
            .any(|review| review.candidate.capability == Capability::BufferWrite),
        "the source-linked native buffer path remains reviewable"
    );
    assert!(reviews.observation_reviews.iter().all(|review| {
        review
            .evidence
            .iter()
            .all(|item| item.capability != Capability::BufferWrite)
    }));

    fs::remove_dir_all(&root).expect("remove native buffer review fixture");
}

#[test]
fn cpp_allocation_families_and_unique_ownership_are_bounded() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-cpp-ownership-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create C++ ownership fixture");
    fs::write(
        root.join("ownership.cpp"),
        r#"
namespace std {
template<class T> class unique_ptr { public: explicit unique_ptr(T*); };
template<class T> unique_ptr<T> make_unique();
}
struct Widget {};
struct Deleter {};

void cases(Widget *other, void *storage) {
    Widget *scalarGood = new Widget;
    delete scalarGood;

    Widget *arrayBad = new Widget[4];
    delete arrayBad;

    Widget *scalarBad = new Widget;
    delete[] scalarBad;

    Widget *arrayGood = new Widget[4];
    delete[] arrayGood;

    Widget *indexedArgument = new Widget(other[0]);
    delete indexedArgument;

    std::unique_ptr<Widget> direct(new Widget);
    std::unique_ptr<Widget[]> directArray(new Widget[3]);
    std::unique_ptr<Widget> wrongOwner(new Widget[2]);
    std::unique_ptr<Widget, Deleter> customOwner(new Widget);

    Widget *raw = new Widget[2];
    std::unique_ptr<Widget[]> transferred(raw);

    Widget *rawWrong = new Widget[2];
    std::unique_ptr<Widget> transferredWrong(rawWrong);

    auto made = std::make_unique<Widget>();
    auto madeArray = std::make_unique<Widget[]>(4);

    Widget *reassigned = new Widget;
    reassigned = other;
    delete reassigned;

    Widget *placed = new (storage) Widget;
}
"#,
    )
    .expect("write C++ ownership fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan C++ ownership fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat C++ ownership fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::CppHeapDeallocation | Capability::CppRaiiOwner
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 12);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        8
    );
    assert!(paths.iter().all(|path| {
        path.cwe_candidates == vec!["CWE-762".to_string()]
            && path.source_evidence_id != path.sink_evidence_id
    }));
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::CppOwnershipTransfer)
            .count(),
        2
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::CppHeapAllocation)
            .count(),
        12,
        "placement new, shared/custom ownership, and reassigned raw locals stay outside the claim"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), true)
        .expect("C++ ownership reviews");
    let ownership_reviews = reviews
        .reviews
        .iter()
        .filter(|review| {
            matches!(
                review.candidate.capability,
                Capability::CppHeapDeallocation | Capability::CppRaiiOwner
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(ownership_reviews.len(), 4);
    assert!(
        ownership_reviews
            .iter()
            .all(|review| review.candidate.state == SecurityPathState::Unknown)
    );
    assert!(reviews.reviews.iter().any(|review| {
        matches!(
            review.candidate.capability,
            Capability::CppHeapDeallocation | Capability::CppRaiiOwner
        ) && review
            .open_questions
            .iter()
            .any(|question| question.contains("scalar") && question.contains("array"))
    }));
    fs::remove_dir_all(&root).expect("remove C++ ownership fixture");
}

#[test]
fn local_heap_lifetime_requires_an_established_release_contract() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-heap-lifetime-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create heap-lifetime fixture");
    let source = |cpp: bool| {
        let cast = if cpp { "(char *)" } else { "" };
        format!(
            r#"
void consume(char *value);
void free(void *value);
void *malloc(unsigned long size);
void *calloc(unsigned long count, unsigned long size);
char *strdup(const char *value);
struct Owner {{ char *slot; }};

long cases(int bad, int take, char *other, struct Owner *owner) {{
    char *missing = {cast}malloc(16);
    if (bad) return -1;
    consume(missing);
    free(missing);

    char *matched = {cast}calloc(2, 8);
    if (bad) {{ free(matched); return -2; }}
    free(matched);

    char *null_only = {cast}malloc(8);
    if (!null_only) return -3;
    free(null_only);

    char *conditioned;
    if ((conditioned = {cast}malloc(8)) == 0) return -3;
    free(conditioned);

    char *negated;
    if (!(negated = {cast}malloc(8))) return -3;
    free(negated);

    char *alias_owner;
    char *alias = alias_owner = {cast}malloc(8);
    if (!alias) return -3;
    free(alias_owner);

    char *transferred = strdup("value");
    if (take) return (long)transferred;
    free(transferred);

    char *wrong = {cast}malloc(4);
    if (bad) {{ free(other); return -4; }}
    free(wrong);

    char *reassigned = {cast}malloc(4);
    if (bad) return -5;
    reassigned = other;
    free(reassigned);

    char *escaped = {cast}malloc(4);
    owner->slot = escaped;
    if (bad) return -5;
    free(escaped);

    char *profiled = {cast}malloc(32);
    if (bad) {{
#ifdef FIX_PROFILE
        free(profiled);
#endif
        return -6;
    }}
    free(profiled);
    return 0;
}}
"#
        )
    };
    fs::write(root.join("lifetime.c"), source(false)).expect("write C lifetime fixture");
    fs::write(root.join("lifetime.cpp"), source(true)).expect("write C++ lifetime fixture");
    let write_profile = |fixed: bool| {
        let define = if fixed {
            "-DFIX_PROFILE"
        } else {
            "-UFIX_PROFILE"
        };
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[
                  {{"directory":".","file":"lifetime.c","arguments":["cc","{define}","lifetime.c"]}},
                  {{"directory":".","file":"lifetime.cpp","arguments":["c++","{define}","lifetime.cpp"]}}
                ]"#
            ),
        )
        .expect("write heap-lifetime profile");
    };

    write_profile(false);
    let vulnerable = mehscan_engine::scan_path(&root).expect("vulnerable lifetime profile");
    let vulnerable_paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::LocalHeapDeallocation)
        .collect::<Vec<_>>();
    assert_eq!(vulnerable_paths.len(), 8);
    assert_eq!(
        vulnerable_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        2
    );
    assert!(vulnerable_paths.iter().all(|path| {
        path.cwe_candidates == vec!["CWE-401".to_string()]
            && path.source_evidence_id != path.sink_evidence_id
    }));
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), true)
        .expect("heap-lifetime reviews");
    let lifetime_reviews = reviews
        .reviews
        .iter()
        .filter(|review| review.candidate.capability == Capability::LocalHeapDeallocation)
        .collect::<Vec<_>>();
    assert_eq!(lifetime_reviews.len(), 6);
    assert!(
        lifetime_reviews
            .iter()
            .all(|review| review.candidate.state == SecurityPathState::Unknown)
    );
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::LocalHeapDeallocation
            && review.open_questions.iter().any(|question| {
                question.contains("early return") && question.contains("exact free")
            })
    }));

    write_profile(true);
    let fixed = mehscan_engine::scan_path(&root).expect("fixed lifetime profile");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat fixed lifetime profile");
    fs::remove_dir_all(&root).expect("remove heap-lifetime fixture");
    assert_eq!(fixed.evidence, repeated.evidence);
    assert_eq!(fixed.security_paths, repeated.security_paths);
    let fixed_paths = fixed
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::LocalHeapDeallocation)
        .collect::<Vec<_>>();
    assert_eq!(fixed_paths.len(), 8);
    assert_eq!(
        fixed_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        4
    );
    assert_eq!(
        fixed
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::LocalHeapAllocation)
            .count(),
        8,
        "allocation-failure exits, returned or stored ownership, and reassigned locals must not form paths"
    );
}

#[test]
fn scans_c_and_cpp_with_portable_and_native_security_relationships() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("native fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("native fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert!(
        result
            .coverage
            .files
            .iter()
            .any(|file| file.language == Some(Language::C))
    );
    assert!(
        result
            .coverage
            .files
            .iter()
            .any(|file| file.language == Some(Language::Cpp))
    );

    let capabilities = result
        .evidence
        .iter()
        .map(|item| item.capability)
        .collect::<BTreeSet<_>>();
    for capability in [
        Capability::ExternalInput,
        Capability::ProcessExecution,
        Capability::FormatStringOutput,
        Capability::BufferWrite,
        Capability::BufferCapacityValidation,
        Capability::IntegerNarrowing,
        Capability::ArithmeticDivision,
        Capability::NonzeroValidation,
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::PathCanonicalization,
        Capability::DatabaseQuery,
        Capability::OutboundNetworkRequest,
        Capability::CryptographicHash,
        Capability::ProcessArgumentSeparation,
    ] {
        assert!(capabilities.contains(&capability), "missing {capability:?}");
    }

    for fixture in ["positive/native.c", "positive/native.cpp"] {
        for capability in [
            Capability::ProcessExecution,
            Capability::FormatStringOutput,
            Capability::BufferWrite,
            Capability::FilesystemRead,
            Capability::DatabaseQuery,
            Capability::OutboundNetworkRequest,
        ] {
            assert!(
                result.security_paths.iter().any(|path| {
                    path.capability == capability
                        && path
                            .steps
                            .first()
                            .is_some_and(|step| step.location.path == fixture)
                }),
                "missing {fixture} bounded path for {capability:?}: {:#?}",
                result.security_paths
            );
        }
    }

    assert!(result.security_paths.iter().all(|path| {
        path.state == SecurityPathState::Protected
            || path
                .steps
                .iter()
                .all(|step| step.location.path.starts_with("positive/"))
    }));

    let insufficient_sink = result
        .evidence
        .iter()
        .find(|item| {
            item.capability == Capability::BufferWrite
                && item.location.path == "positive/native.c"
                && item
                    .captures
                    .get("size")
                    .is_some_and(|size| size.text == "64")
        })
        .expect("find known-insufficient native copy");
    assert!(
        insufficient_sink
            .tags
            .iter()
            .any(|tag| tag == "buffer-capacity:known-insufficient")
    );
    assert_eq!(
        insufficient_sink
            .captures
            .get("capacity")
            .map(|capture| capture.text.as_str()),
        Some("16")
    );

    let validation = result
        .evidence
        .iter()
        .find(|item| {
            item.capability == Capability::BufferCapacityValidation
                && item.location.path == "safe/constants.c"
        })
        .expect("find exact safe capacity validation");
    assert_eq!(
        validation
            .captures
            .get("capacity")
            .map(|capture| capture.text.as_str()),
        Some("64")
    );
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::BufferWrite
            && path.state == SecurityPathState::Protected
            && path
                .steps
                .first()
                .is_some_and(|step| step.location.path == "safe/constants.c")
    }));

    let arithmetic_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ArithmeticDivision)
        .collect::<Vec<_>>();
    assert_eq!(arithmetic_paths.len(), 3);
    for fixture in ["positive/native.c", "positive/native.cpp"] {
        assert!(arithmetic_paths.iter().any(|path| {
            path.state == SecurityPathState::Unknown
                && path
                    .steps
                    .first()
                    .is_some_and(|step| step.location.path == fixture)
                && path
                    .uncertainty_reasons
                    .iter()
                    .any(|reason| reason == "converted_divisor_nonzero_invariant_unproven")
        }));
    }
    assert!(arithmetic_paths.iter().any(|path| {
        path.state == SecurityPathState::Protected
            && path
                .steps
                .first()
                .is_some_and(|step| step.location.path == "safe/constants.c")
            && path.protection_evidence_ids.len() == 1
    }));
    assert!(result.security_paths.iter().all(|path| {
        result
            .evidence
            .iter()
            .any(|evidence| evidence.id == path.source_evidence_id)
            && result
                .evidence
                .iter()
                .any(|evidence| evidence.id == path.sink_evidence_id)
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| result.evidence.iter().any(|evidence| evidence.id == *id))
    }));

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(5), true)
            .expect("native review jobs should build");
    assert!(reviews.observation_reviews.iter().all(|review| {
        review.evidence.iter().all(|item| {
            !(item.capability == Capability::FormatStringOutput
                && item.location.path == "safe/constants.c")
                && item.capability != Capability::ProcessExecution
        })
    }));
    let arithmetic_review = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.capability == Capability::ArithmeticDivision)
        .expect("narrowed divisor should be reviewer visible");
    assert!(arithmetic_review.open_questions.iter().any(|question| {
        question.contains("unsigned 32-bit range") && question.contains("low 32 bits are zero")
    }));
}

#[test]
fn compile_commands_selects_c_preprocessor_profile_without_running_compiler() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-build-profile-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    fs::write(
        root.join("profile.c"),
        "typedef unsigned long size_t;\ntypedef unsigned int uint32_t;\nchar *getenv(const char *);\nint system(const char *);\n#ifdef MAGMA_ENABLE_FIXES\nvoid run(void) { system(\"fixed\"); }\nsize_t ratio(size_t input) { size_t wide = input; size_t divisor = wide; return 10 / divisor; }\n#else\nvoid run(void) { system(getenv(\"QUERY\")); }\nsize_t ratio(size_t input) { size_t wide = input; size_t divisor = (uint32_t)wide; return 10 / divisor; }\n#endif\n",
    )
    .expect("write C profile source");
    fs::write(
        root.join("compile_commands.json"),
        r#"[{"directory":".","file":"profile.c","arguments":["cc","-UMAGMA_ENABLE_FIXES","profile.c"]}]"#,
    )
    .expect("write compilation database");

    let result = mehscan_engine::scan_path(&root).expect("profile fixture should scan");

    let fixed = result
        .evidence
        .iter()
        .find(|evidence| {
            evidence.location.path == "profile.c"
                && evidence.capability == Capability::ProcessExecution
                && evidence.location.start.line == 6
        })
        .expect("fixed branch process observation");
    assert_eq!(
        fixed
            .context
            .availability
            .as_ref()
            .expect("fixed branch availability")
            .state,
        AvailabilityState::Excluded
    );

    let vulnerable = result
        .evidence
        .iter()
        .find(|evidence| {
            evidence.location.path == "profile.c"
                && evidence.capability == Capability::ProcessExecution
                && evidence.location.start.line == 9
        })
        .expect("vulnerable branch process observation");
    assert_eq!(
        vulnerable
            .context
            .availability
            .as_ref()
            .expect("vulnerable branch availability")
            .state,
        AvailabilityState::Always
    );
    assert!(
        result
            .security_paths
            .iter()
            .any(|path| path.capability == Capability::ArithmeticDivision)
    );

    fs::write(
        root.join("compile_commands.json"),
        r#"[{"directory":".","file":"profile.c","arguments":["cc","-DMAGMA_ENABLE_FIXES","profile.c"]}]"#,
    )
    .expect("select fixed compilation profile");
    let fixed_result = mehscan_engine::scan_path(&root).expect("fixed profile fixture should scan");
    fs::remove_dir_all(&root).expect("remove temporary fixture");
    assert!(
        fixed_result
            .security_paths
            .iter()
            .all(|path| path.capability != Capability::ArithmeticDivision)
    );
}

#[test]
fn static_build_profiles_select_only_literal_unconditional_c_family_branches() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-static-build-profile-{}-{nonce}",
        std::process::id()
    ));
    for directory in ["cmake", "meson", "bazel"] {
        fs::create_dir_all(root.join(directory)).expect("create build-profile directory");
    }
    let source = |symbol: &str| {
        format!(
            "char *getenv(const char *);\nint system(const char *);\n#ifdef {symbol}\nvoid run(void) {{ system(\"fixed\"); }}\n#else\nvoid run(void) {{ system(getenv(\"QUERY\")); }}\n#endif\n"
        )
    };
    fs::write(root.join("cmake/profile.c"), source("CMAKE_FIXED")).expect("write CMake source");
    fs::write(
        root.join("cmake/CMakeLists.txt"),
        "add_executable(app profile.c)\ntarget_compile_definitions(app PRIVATE CMAKE_FIXED)\n",
    )
    .expect("write CMake profile");
    fs::write(root.join("meson/profile.cpp"), source("MESON_FIXED")).expect("write Meson source");
    fs::write(
        root.join("meson/meson.build"),
        "add_project_arguments('-DMESON_FIXED', language : 'cpp')\n",
    )
    .expect("write Meson profile");
    fs::write(root.join("bazel/profile.c"), source("BAZEL_FIXED")).expect("write Bazel source");
    fs::write(
        root.join("bazel/BUILD.bazel"),
        "cc_binary(name = \"app\", srcs = [\"profile.c\"], local_defines = [\"BAZEL_FIXED\"])\n",
    )
    .expect("write Bazel profile");

    let result = mehscan_engine::scan_path(&root).expect("scan static build-profile fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat static build-profile fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let excluded_inputs = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::ExternalInput)
        .filter(|item| {
            item.context
                .availability
                .as_ref()
                .is_some_and(|availability| availability.state == AvailabilityState::Excluded)
        })
        .count();
    assert_eq!(excluded_inputs, 3);
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(40), true)
        .expect("build static-profile reviews");
    assert!(
        reviews
            .reviews
            .iter()
            .all(|review| review.candidate.capability != Capability::ProcessExecution)
    );
    fs::remove_dir_all(root).expect("remove static build-profile fixture");
}

#[test]
fn recovered_native_arithmetic_paths_keep_all_referenced_evidence() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-recovered-arithmetic-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    fs::write(
        root.join("recovered.c"),
        "#ifdef UNFINISHED\ntypedef unsigned long size_t;\ntypedef unsigned int uint32_t;\nsize_t ratio(size_t input) { size_t wide = input; size_t divisor = (uint32_t)wide; return 10 / divisor; }\n",
    )
    .expect("write recovered C source");

    let result = mehscan_engine::scan_path(&root).expect("recovered fixture should scan");
    fs::remove_dir_all(&root).expect("remove temporary fixture");
    assert_eq!(result.coverage.totals.parse_failed, 1);
    let path = result
        .security_paths
        .iter()
        .find(|path| path.capability == Capability::ArithmeticDivision)
        .expect("locally complete arithmetic relationship survives broad recovery error");
    assert!(
        result
            .evidence
            .iter()
            .any(|evidence| evidence.id == path.source_evidence_id)
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|evidence| evidence.id == path.sink_evidence_id)
    );
}

#[test]
fn derived_domain_limit_distinguishes_broad_and_exact_count_validation() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-domain-limit-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    fs::write(
        root.join("palette.c"),
        "#define DOMAIN_MAXIMUM 256\nstruct info { int indexed; unsigned depth; };\nvoid *memcpy(void *, const void *, unsigned long);\nvoid set_palette(struct info *info, char *dst, const char *src, int count) {\n  unsigned derived_maximum = info->indexed ? (1u << info->depth) : DOMAIN_MAXIMUM;\n#ifdef FIX_PROFILE\n  if (count < 0 || count > (int)derived_maximum) return;\n#else\n  if (count < 0 || count > DOMAIN_MAXIMUM) return;\n#endif\n  memcpy(dst, src, (unsigned)count * sizeof(char));\n}\n",
    )
    .expect("write domain-bound fixture");
    fs::write(
        root.join("compile_commands.json"),
        r#"[{"directory":".","file":"palette.c","arguments":["cc","-UFIX_PROFILE","palette.c"]}]"#,
    )
    .expect("select broad-bound profile");

    let broad = mehscan_engine::scan_path(&root).expect("broad profile should scan");
    let broad_path = broad
        .security_paths
        .iter()
        .find(|path| path.capability == Capability::CountControlledMemoryOperation)
        .expect("broad validation should produce a domain-bound path");
    assert_eq!(broad_path.state, SecurityPathState::Unknown);
    assert!(
        broad_path
            .uncertainty_reasons
            .iter()
            .any(|reason| { reason == "applied_upper_bound_differs_from_derived_domain_limit" })
    );
    let input = broad
        .evidence
        .iter()
        .find(|item| item.id == broad_path.source_evidence_id)
        .expect("input evidence exists");
    assert_eq!(
        input
            .captures
            .get("applied_upper_bound")
            .map(|capture| capture.text.as_str()),
        Some("DOMAIN_MAXIMUM")
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(5), true)
        .expect("domain-bound review jobs should build");
    let review = reviews
        .reviews
        .iter()
        .find(|review| review.candidate.capability == Capability::CountControlledMemoryOperation)
        .expect("broad domain validation should be reviewer visible");
    assert!(review.open_questions.iter().any(|question| {
        question.contains("authoritative limit") && question.contains("broader applied bound")
    }));
    assert!(review.open_questions.iter().any(|question| {
        question.contains("admitted quantity") && question.contains("memory-operation extent")
    }));

    fs::write(
        root.join("compile_commands.json"),
        r#"[{"directory":".","file":"palette.c","arguments":["cc","-DFIX_PROFILE","palette.c"]}]"#,
    )
    .expect("select exact-bound profile");
    let exact = mehscan_engine::scan_path(&root).expect("exact profile should scan");
    fs::remove_dir_all(&root).expect("remove temporary fixture");
    let exact_path = exact
        .security_paths
        .iter()
        .find(|path| path.capability == Capability::CountControlledMemoryOperation)
        .expect("exact validation should produce a protected domain-bound path");
    assert_eq!(exact_path.state, SecurityPathState::Protected);
    assert_eq!(exact_path.protection_evidence_ids.len(), 1);
    assert!(exact.evidence.iter().any(|item| {
        item.capability == Capability::DomainLimitComputation
            && item
                .captures
                .get("limit")
                .is_some_and(|capture| capture.text == "derived_maximum")
    }));
}

#[test]
fn fixed_width_multiplication_requires_a_memory_extent_handoff_and_range_guard() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-multiplication-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    fs::write(
        root.join("rows.c"),
        "#define UINT32_MAXIMUM 4294967295u\ntypedef unsigned int uint32_t;\ntypedef unsigned long size_t;\nvoid *memcpy(void *, const void *, size_t);\nvoid expand(char *dst, const char *src, unsigned width, unsigned depth) {\n#ifdef FIX_PROFILE\n  size_t row_width = width;\n#else\n  uint32_t row_width = width;\n#endif\n  unsigned bytes;\n  row_width *= depth;\n  bytes = row_width;\n  memcpy(dst, src, bytes);\n}\nvoid guarded(char *dst, const char *src, unsigned width, unsigned depth) {\n  uint32_t row_width = width;\n  unsigned bytes;\n  if (depth == 0 || row_width > UINT32_MAXIMUM / depth) return;\n  row_width *= depth;\n  bytes = row_width;\n  memcpy(dst, src, bytes);\n}\n",
    )
    .expect("write multiplication fixture");
    fs::write(
        root.join("compile_commands.json"),
        r#"[{"directory":".","file":"rows.c","arguments":["cc","-UFIX_PROFILE","rows.c"]}]"#,
    )
    .expect("select fixed-width profile");

    let vulnerable = mehscan_engine::scan_path(&root).expect("fixed-width profile should scan");
    let multiplication_paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ArithmeticMultiplication)
        .collect::<Vec<_>>();
    assert_eq!(multiplication_paths.len(), 2);
    assert!(multiplication_paths.iter().any(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "multiplication_range_not_proven")
    }));
    assert!(multiplication_paths.iter().any(|path| {
        path.state == SecurityPathState::Protected && path.protection_evidence_ids.len() == 1
    }));
    let sink = vulnerable
        .evidence
        .iter()
        .find(|item| {
            item.capability == Capability::ArithmeticMultiplication
                && item
                    .captures
                    .get("multiplication")
                    .is_some_and(|capture| capture.location.start.line == 12)
        })
        .expect("memory-relevant multiplication evidence");
    assert_eq!(
        sink.captures
            .get("memory_extent_value")
            .map(|capture| capture.text.as_str()),
        Some("bytes")
    );
    assert!(
        sink.captures
            .get("downstream_memory_operation")
            .is_some_and(|capture| capture.text == "memcpy(dst, src, bytes)")
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(5), true)
        .expect("multiplication review jobs should build");
    let review = reviews
        .reviews
        .iter()
        .find(|review| {
            review.candidate.capability == Capability::ArithmeticMultiplication
                && review.candidate.state == SecurityPathState::Unknown
        })
        .expect("unguarded multiplication should be reviewer visible");
    assert!(review.open_questions.iter().any(|question| {
        question.contains("operand product") && question.contains("memory-operation extent")
    }));

    fs::write(
        root.join("compile_commands.json"),
        r#"[{"directory":".","file":"rows.c","arguments":["cc","-DFIX_PROFILE","rows.c"]}]"#,
    )
    .expect("select allocation-width profile");
    let fixed = mehscan_engine::scan_path(&root).expect("allocation-width profile should scan");
    fs::remove_dir_all(&root).expect("remove temporary fixture");
    assert_eq!(
        fixed
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::ArithmeticMultiplication)
            .count(),
        1,
        "the explicitly guarded sibling remains, but the fixed profile removes the unguarded path"
    );
    assert!(fixed.security_paths.iter().all(|path| {
        path.capability != Capability::ArithmeticMultiplication
            || path.state == SecurityPathState::Protected
    }));
}

#[test]
fn recovered_cpp_multiplication_keeps_the_bounded_memory_handoff() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-cpp-recovered-multiplication-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    fs::write(
        root.join("rows.cpp"),
        "#ifdef UNFINISHED\ntypedef unsigned int uint32_t;\nvoid *memcpy(void *, const void *, unsigned long);\nvoid expand_cpp(char *dst, const char *src, unsigned width, unsigned depth) {\n  uint32_t row_width = width;\n  unsigned bytes;\n  row_width *= depth;\n  bytes = row_width;\n  memcpy(dst, src, bytes);\n}\n",
    )
    .expect("write recovered C++ fixture");

    let result = mehscan_engine::scan_path(&root).expect("recovered C++ fixture should scan");
    fs::remove_dir_all(&root).expect("remove temporary fixture");
    assert_eq!(result.coverage.totals.parse_failed, 1);
    let path = result
        .security_paths
        .iter()
        .find(|path| path.capability == Capability::ArithmeticMultiplication)
        .expect("locally complete C++ multiplication relationship survives recovery");
    assert!(
        result
            .evidence
            .iter()
            .any(|evidence| evidence.id == path.source_evidence_id)
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|evidence| evidence.id == path.sink_evidence_id)
    );
}

#[test]
fn architecture_limit_validation_protects_macro_derived_allocation_size() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-allocation-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    let boundary = |suffix: &str| {
        format!(
            "typedef unsigned long size_t;\n#define SIZE_MAXIMUM ((size_t)-1)\nint gt(size_t,size_t);\nvoid fatal(void);\nvoid validate_{suffix}(unsigned width) {{\n  int error = 0;\n  if (gt(((width + 7) & ~7U), ((SIZE_MAXIMUM - 48 - 1) / 8 - 1))) {{\n#ifdef FIX_PROFILE\n    error = 1;\n#endif\n  }}\n  if (error == 1) fatal();\n}}\nvoid unrelated_bound_{suffix}(unsigned height) {{\n  if (gt(height, SIZE_MAXIMUM / 4)) fatal();\n}}\n"
        )
    };
    let allocation = |suffix: &str| {
        format!(
            "typedef unsigned long size_t;\ntypedef struct {{ unsigned width; unsigned stride; }} image_{suffix};\n#define ROW_BYTES(bits,width) ((size_t)(width) * ((size_t)(bits) >> 3))\nvoid *allocate(size_t);\nvoid rows_{suffix}(image_{suffix} *image, unsigned depth) {{\n  size_t row_bytes;\n  row_bytes = ((image->width + 7) & ~7U);\n  row_bytes = ROW_BYTES(depth, row_bytes) + 1 + ((depth + 7) >> 3);\n  void *buffer = allocate(row_bytes + 48);\n}}\nvoid unrelated_allocation_{suffix}(image_{suffix} *image, unsigned depth) {{\n  size_t scratch;\n  scratch = ((image->stride + 7) & ~7U);\n  scratch = ROW_BYTES(depth, scratch) + 1;\n  void *buffer = allocate(scratch + 48);\n}}\n"
        )
    };
    fs::write(root.join("boundary.c"), boundary("c")).expect("write C boundary");
    fs::write(root.join("rows.c"), allocation("c")).expect("write C allocation");
    fs::write(root.join("boundary.cpp"), boundary("cpp")).expect("write C++ boundary");
    fs::write(root.join("rows.cpp"), allocation("cpp")).expect("write C++ allocation");
    fs::write(
        root.join("compile_commands.json"),
        r#"[
          {"directory":".","file":"boundary.c","arguments":["cc","-UFIX_PROFILE","boundary.c"]},
          {"directory":".","file":"rows.c","arguments":["cc","rows.c"]},
          {"directory":".","file":"boundary.cpp","arguments":["c++","-UFIX_PROFILE","boundary.cpp"]},
          {"directory":".","file":"rows.cpp","arguments":["c++","rows.cpp"]}
        ]"#,
    )
    .expect("select vulnerable profile");

    let vulnerable = mehscan_engine::scan_path(&root).expect("vulnerable profile should scan");
    let vulnerable_paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::AllocationSizeComputation)
        .collect::<Vec<_>>();
    assert_eq!(vulnerable_paths.len(), 2, "one bounded path per language");
    assert_eq!(
        vulnerable
            .evidence
            .iter()
            .filter(|item| matches!(
                item.capability,
                Capability::ArchitectureSizeInput | Capability::AllocationSizeComputation
            ))
            .count(),
        4,
        "unlinked SIZE_MAX checks and allocation calculations are pruned"
    );
    assert!(vulnerable_paths.iter().all(|path| {
        path.state == SecurityPathState::Unknown
            && path.uncertainty_reasons.iter().any(|reason| {
                reason == "macro_expansion_and_target_size_width_require_confirmation"
            })
    }));
    let allocation_evidence = vulnerable
        .evidence
        .iter()
        .find(|item| item.capability == Capability::AllocationSizeComputation)
        .expect("allocation-size evidence");
    assert!(
        allocation_evidence
            .captures
            .get("size_macro")
            .is_some_and(|capture| capture.text == "ROW_BYTES(depth, row_bytes)")
    );
    assert!(
        allocation_evidence
            .captures
            .get("allocation")
            .is_some_and(|capture| capture.text == "allocate(row_bytes + 48)")
    );

    fs::write(
        root.join("compile_commands.json"),
        r#"[
          {"directory":".","file":"boundary.c","arguments":["cc","-DFIX_PROFILE","boundary.c"]},
          {"directory":".","file":"rows.c","arguments":["cc","rows.c"]},
          {"directory":".","file":"boundary.cpp","arguments":["c++","-DFIX_PROFILE","boundary.cpp"]},
          {"directory":".","file":"rows.cpp","arguments":["c++","rows.cpp"]}
        ]"#,
    )
    .expect("select fixed profile");
    let fixed = mehscan_engine::scan_path(&root).expect("fixed profile should scan");
    let repeated = mehscan_engine::scan_path(&root).expect("fixed profile should rescan");
    let fixed_paths = fixed
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::AllocationSizeComputation)
        .collect::<Vec<_>>();
    assert_eq!(fixed_paths.len(), 2);
    assert!(fixed_paths.iter().all(|path| {
        path.state == SecurityPathState::Protected && path.protection_evidence_ids.len() == 1
    }));
    assert_eq!(fixed.evidence, repeated.evidence);
    assert_eq!(fixed.security_paths, repeated.security_paths);

    fs::write(
        root.join("compile_commands.json"),
        r#"[
          {"directory":".","file":"boundary.c","arguments":["cc","-UFIX_PROFILE","boundary.c"]},
          {"directory":".","file":"rows.c","arguments":["cc","rows.c"]},
          {"directory":".","file":"boundary.cpp","arguments":["c++","-UFIX_PROFILE","boundary.cpp"]},
          {"directory":".","file":"rows.cpp","arguments":["c++","rows.cpp"]}
        ]"#,
    )
    .expect("restore vulnerable profile for review");
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(5), true)
        .expect("allocation review jobs should build");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::AllocationSizeComputation
            && review.open_questions.iter().any(|question| {
                question.contains("SIZE_MAX-derived") && question.contains("allocation extent")
            })
    }));
    fs::remove_dir_all(&root).expect("remove temporary fixture");
}

#[test]
fn callback_stack_state_requires_restoration_before_post_return_dereference() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-lifetime-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    let callback = |suffix: &str| {
        format!(
            "typedef struct control_{suffix} {{ void *error; }} control_{suffix};\ntypedef struct image_{suffix} {{ control_{suffix} *opaque; }} image_{suffix};\nint run_{suffix}(image_{suffix}*, int (*)(void*), void*);\nvoid release_control_{suffix}(void*);\nint release_{suffix}(void *argument) {{\n  image_{suffix} *image = (image_{suffix}*)argument;\n  control_{suffix} local;\n  control_{suffix} *saved = image->opaque;\n  image->opaque = &local;\n  release_control_{suffix}(saved);\n#ifdef RESTORE_PROFILE\n  image->opaque = saved;\n#endif\n  return 1;\n}}\nvoid free_{suffix}(image_{suffix} *image) {{\n#ifdef VULN_PROFILE\n  (void)run_{suffix}(image, release_{suffix}, image);\n#else\n  (void)release_{suffix}(image);\n#endif\n}}\nint unrelated_escape_{suffix}(image_{suffix} *image) {{ control_{suffix} local; image->opaque = &local; return 1; }}\n"
        )
    };
    let wrapper = |suffix: &str| {
        format!(
            "typedef struct control_{suffix} {{ void *error; }} control_{suffix};\ntypedef struct image_{suffix} {{ control_{suffix} *opaque; }} image_{suffix};\nint run_{suffix}(image_{suffix} *image_in, int (*function)(void*), void *arg) {{\n  image_{suffix} *image = image_in;\n  void *saved_error = image->opaque->error;\n  int result = function(arg);\n  image->opaque->error = saved_error;\n  return result;\n}}\nint unrelated_wrapper_{suffix}(image_{suffix} *image, int (*function)(void*), void *arg) {{\n  void *saved_error = image->opaque->error;\n  int result = function(arg);\n  image->opaque = (control_{suffix}*)saved_error;\n  return result;\n}}\n"
        )
    };
    for (name, source) in [
        ("callback.c", callback("c")),
        ("wrapper.c", wrapper("c")),
        ("callback.cpp", callback("cpp")),
        ("wrapper.cpp", wrapper("cpp")),
    ] {
        fs::write(root.join(name), source).expect("write lifetime fixture");
    }
    let write_profile = |defined: bool, restored: bool| {
        let vuln = if defined {
            "-DVULN_PROFILE"
        } else {
            "-UVULN_PROFILE"
        };
        let restore = if restored {
            "-DRESTORE_PROFILE"
        } else {
            "-URESTORE_PROFILE"
        };
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[
                  {{"directory":".","file":"callback.c","arguments":["cc","{vuln}","{restore}","callback.c"]}},
                  {{"directory":".","file":"wrapper.c","arguments":["cc","wrapper.c"]}},
                  {{"directory":".","file":"callback.cpp","arguments":["c++","{vuln}","{restore}","callback.cpp"]}},
                  {{"directory":".","file":"wrapper.cpp","arguments":["c++","wrapper.cpp"]}}
                ]"#
            ),
        )
        .expect("write lifetime profile");
    };

    write_profile(true, false);
    let vulnerable = mehscan_engine::scan_path(&root).expect("vulnerable lifetime profile");
    let paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::PostReturnDereference)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2, "one exact lifetime path per language");
    assert!(
        paths
            .iter()
            .all(|path| path.state == SecurityPathState::Unknown)
    );
    assert_eq!(
        vulnerable
            .evidence
            .iter()
            .filter(|item| matches!(
                item.capability,
                Capability::StackAddressEscape
                    | Capability::LifetimeCallbackHandoff
                    | Capability::PostReturnDereference
                    | Capability::StackLifetimeRestoration
            ))
            .count(),
        6,
        "unlinked escape and wrapper lookalikes are pruned"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(10), true)
        .expect("lifetime reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::PostReturnDereference
            && review.open_questions.iter().any(|question| {
                question.contains("callback-local storage") && question.contains("dereferences")
            })
    }));

    write_profile(true, true);
    let protected = mehscan_engine::scan_path(&root).expect("protected lifetime profile");
    let protected_paths = protected
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::PostReturnDereference)
        .collect::<Vec<_>>();
    assert_eq!(protected_paths.len(), 2);
    assert!(
        protected_paths
            .iter()
            .all(|path| path.state == SecurityPathState::Protected
                && path.protection_evidence_ids.len() == 1)
    );
    let repeated = mehscan_engine::scan_path(&root).expect("deterministic lifetime rescan");
    assert_eq!(protected.evidence, repeated.evidence);
    assert_eq!(protected.security_paths, repeated.security_paths);

    write_profile(false, false);
    let fixed = mehscan_engine::scan_path(&root).expect("fixed direct-call profile");
    assert!(
        fixed
            .security_paths
            .iter()
            .all(|path| path.capability != Capability::PostReturnDereference)
    );
    assert!(fixed.evidence.iter().all(|item| !matches!(
        item.capability,
        Capability::StackAddressEscape
            | Capability::LifetimeCallbackHandoff
            | Capability::PostReturnDereference
            | Capability::StackLifetimeRestoration
    )));
    fs::remove_dir_all(&root).expect("remove temporary fixture");
}

#[test]
fn exceptional_state_requires_fatal_rejection_before_indexed_dereference() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-exceptional-state-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    let initializer = |suffix: &str| {
        format!(
            "typedef struct color_{suffix} {{ unsigned char red; }} color_{suffix};\ntypedef struct image_{suffix} {{ color_{suffix} *palette; color_{suffix} *cache; }} image_{suffix};\n#define NULL ((void*)0)\nvoid report_{suffix}(const char*);\nvoid fatal_{suffix}(const char*);\ncolor_{suffix} *allocate_{suffix}(void);\nvoid set_palette_{suffix}(image_{suffix} *image, color_{suffix} *palette, int count) {{\n  if (count > 0 && palette == NULL) {{\n#ifdef FIX_PROFILE\n    fatal_{suffix}(\"invalid palette\");\n#else\n    report_{suffix}(\"invalid palette\");\n    return;\n#endif\n  }}\n  image->palette = allocate_{suffix}();\n}}\nvoid unrelated_cache_{suffix}(image_{suffix} *image, color_{suffix} *cache) {{\n  if (cache == NULL) {{ report_{suffix}(\"missing cache\"); return; }}\n  image->cache = allocate_{suffix}();\n}}\n"
        )
    };
    let consumer = |suffix: &str| {
        format!(
            "static unsigned consume_palette_{suffix}(color_{suffix} *palette) {{ return palette[0].red; }}\nunsigned expand_{suffix}(image_{suffix} *image) {{ return consume_palette_{suffix}(image->palette); }}\nvoid validate_{suffix}(image_{suffix} *image) {{\n#ifdef GUARD_PROFILE\n  if (image->palette == NULL) fatal_{suffix}(\"palette required\");\n#endif\n}}\nstatic unsigned unrelated_consume_{suffix}(int mode, color_{suffix} *cache) {{ return cache[0].red + mode; }}\nunsigned unrelated_handoff_{suffix}(image_{suffix} *image) {{ return unrelated_consume_{suffix}(0, image->palette); }}\n"
        )
    };
    for (name, source) in [
        (
            "profile.c",
            format!("{}\n{}", initializer("c"), consumer("c")),
        ),
        (
            "profile.cpp",
            format!("{}\n{}", initializer("cpp"), consumer("cpp")),
        ),
    ] {
        fs::write(root.join(name), source).expect("write exceptional-state fixture");
    }
    let write_profile = |fixed: bool, guarded: bool| {
        let fix = if fixed {
            "-DFIX_PROFILE"
        } else {
            "-UFIX_PROFILE"
        };
        let guard = if guarded {
            "-DGUARD_PROFILE"
        } else {
            "-UGUARD_PROFILE"
        };
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[
                  {{"directory":".","file":"profile.c","arguments":["cc","{fix}","{guard}","profile.c"]}},
                  {{"directory":".","file":"profile.cpp","arguments":["c++","{fix}","{guard}","profile.cpp"]}}
                ]"#
            ),
        )
        .expect("write exceptional-state profile");
    };

    write_profile(false, false);
    let vulnerable =
        mehscan_engine::scan_path(&root).expect("vulnerable exceptional-state profile");
    let vulnerable_paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::StateDependentDereference)
        .collect::<Vec<_>>();
    assert_eq!(vulnerable_paths.len(), 2, "one bounded path per language");
    assert!(vulnerable_paths.iter().all(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "recoverable_exception_can_leave_required_state_absent")
    }));
    assert_eq!(
        vulnerable
            .evidence
            .iter()
            .filter(|item| matches!(
                item.capability,
                Capability::RequiredStateInitialization
                    | Capability::StatePointerHandoff
                    | Capability::StateDependentDereference
                    | Capability::FatalStateInvariantValidation
            ))
            .count(),
        6,
        "unlinked state lookalikes are pruned"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(10), true)
        .expect("exceptional-state reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::StateDependentDereference
            && review.open_questions.iter().any(|question| {
                question.contains("recoverable exceptional path")
                    && question.contains("fatal invariant check")
            })
    }));

    write_profile(false, true);
    let protected = mehscan_engine::scan_path(&root).expect("protected exceptional-state profile");
    let repeated = mehscan_engine::scan_path(&root).expect("deterministic protected rescan");
    assert_eq!(protected.evidence, repeated.evidence);
    assert_eq!(protected.security_paths, repeated.security_paths);
    assert!(
        protected
            .security_paths
            .iter()
            .filter(|path| { path.capability == Capability::StateDependentDereference })
            .all(|path| {
                path.state == SecurityPathState::Protected
                    && !path.protection_evidence_ids.is_empty()
            })
    );

    write_profile(true, false);
    let fixed = mehscan_engine::scan_path(&root).expect("source-fatal exceptional-state profile");
    fs::remove_dir_all(&root).expect("remove temporary fixture");
    let fixed_paths = fixed
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::StateDependentDereference)
        .collect::<Vec<_>>();
    assert_eq!(fixed_paths.len(), 2);
    assert!(fixed_paths.iter().all(|path| {
        path.state == SecurityPathState::Protected && !path.protection_evidence_ids.is_empty()
    }));
}

#[test]
fn exceptional_state_rejects_unrelated_owners_scopes_and_component_domains() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-exceptional-state-negative-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("nss")).expect("create nss fixture directory");
    fs::create_dir_all(root.join("gnutls")).expect("create gnutls fixture directory");

    fs::write(
        root.join("owner-mismatch.c"),
        r#"
typedef struct color { unsigned char red; } color;
typedef struct image { color *palette; } image;
#define NULL ((void*)0)
void report(const char*);
color *allocate(void);
void seed(image *image, color *palette) {
  if (palette == NULL) { report("missing palette"); return; }
  image->palette = allocate();
}
static unsigned consume_palette(color *palette) { return palette[0].red; }
unsigned consume_other(image *other) { return consume_palette(other->palette); }
"#,
    )
    .expect("write owner mismatch fixture");
    fs::write(
        root.join("scope-mismatch.c"),
        r#"
typedef struct color { unsigned char red; } color;
typedef struct image { color *palette; } image;
#define NULL ((void*)0)
void report(const char*);
color *allocate(void);
void reject_unrelated(color *palette) {
  if (palette == NULL) { report("missing palette"); return; }
}
void initialize_later(image *image) { image->palette = allocate(); }
static unsigned read_later(color *palette) { return palette[0].red; }
unsigned handoff_later(image *image) { return read_later(image->palette); }
"#,
    )
    .expect("write scope mismatch fixture");
    fs::write(
        root.join("nss/source.c"),
        r#"
typedef struct color { unsigned char red; } color;
typedef struct image { color *palette; } image;
#define NULL ((void*)0)
void report(const char*);
color *allocate(void);
void backend_seed(image *image, color *palette) {
  if (palette == NULL) { report("missing palette"); return; }
  image->palette = allocate();
}
"#,
    )
    .expect("write component source fixture");
    fs::write(
        root.join("gnutls/consumer.c"),
        r#"
typedef struct color { unsigned char red; } color;
typedef struct image { color *palette; } image;
static unsigned backend_read(color *palette) { return palette[0].red; }
unsigned backend_handoff(image *image) { return backend_read(image->palette); }
"#,
    )
    .expect("write component consumer fixture");

    let result = mehscan_engine::scan_path(&root).expect("scan negative state fixture");
    assert!(
        result
            .security_paths
            .iter()
            .all(|path| path.capability != Capability::StateDependentDereference)
    );
    assert!(result.evidence.iter().all(|item| !matches!(
        item.capability,
        Capability::RequiredStateInitialization
            | Capability::StatePointerHandoff
            | Capability::StateDependentDereference
            | Capability::FatalStateInvariantValidation
    )));
    fs::remove_dir_all(&root).expect("remove negative state fixture");
}

#[test]
fn persistent_allocation_requires_matching_ownership_registration() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-ownership-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temporary fixture");
    let producer = |suffix: &str| {
        format!(
            "typedef struct owner_{suffix} {{ void *payload_buf; void *cache_buf; unsigned free_me; }} owner_{suffix};\n#define OWN_FREE_PAYLOAD 4u\n#define OWN_FREE_CACHE 8u\nvoid *allocate_{suffix}(unsigned);\nvoid read_{suffix}(void*);\nvoid load_{suffix}(owner_{suffix} *owner, unsigned size) {{\n#ifdef FIX_PROFILE\n  owner->free_me |= OWN_FREE_PAYLOAD;\n#endif\n  owner->payload_buf = allocate_{suffix}(size);\n  read_{suffix}(owner->payload_buf);\n}}\nvoid lookalike_{suffix}(owner_{suffix} *owner) {{ owner->cache_buf = allocate_{suffix}(8); owner->free_me |= OWN_FREE_PAYLOAD; }}\n"
        )
    };
    let cleanup = |suffix: &str| {
        format!(
            "typedef struct owner_{suffix} {{ void *payload_buf; void *cache_buf; unsigned free_me; }} owner_{suffix};\n#define OWN_FREE_PAYLOAD 4u\nvoid release_{suffix}(void*);\nvoid cleanup_{suffix}(owner_{suffix} *owner, unsigned mask) {{\n  if ((mask & OWN_FREE_PAYLOAD) & owner->free_me) {{ release_{suffix}(owner->payload_buf); }}\n}}\n"
        )
    };
    for (name, source) in [
        ("producer.c", producer("c")),
        ("cleanup.c", cleanup("c")),
        ("producer.cpp", producer("cpp")),
        ("cleanup.cpp", cleanup("cpp")),
    ] {
        fs::write(root.join(name), source).expect("write ownership fixture");
    }
    let write_profile = |fixed: bool| {
        let define = if fixed {
            "-DFIX_PROFILE"
        } else {
            "-UFIX_PROFILE"
        };
        fs::write(root.join("compile_commands.json"), format!(
            r#"[
              {{"directory":".","file":"producer.c","arguments":["cc","{define}","producer.c"]}},
              {{"directory":".","file":"cleanup.c","arguments":["cc","cleanup.c"]}},
              {{"directory":".","file":"producer.cpp","arguments":["c++","{define}","producer.cpp"]}},
              {{"directory":".","file":"cleanup.cpp","arguments":["c++","cleanup.cpp"]}}
            ]"#
        )).expect("write ownership profile");
    };

    write_profile(false);
    let vulnerable = mehscan_engine::scan_path(&root).expect("vulnerable ownership profile");
    let vulnerable_paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::OwnershipGatedRelease)
        .collect::<Vec<_>>();
    assert_eq!(vulnerable_paths.len(), 2, "one bounded path per language");
    assert!(vulnerable_paths.iter().all(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "persistent_allocation_ownership_registration_not_found")
    }));
    assert_eq!(
        vulnerable
            .evidence
            .iter()
            .filter(|item| matches!(
                item.capability,
                Capability::OwnedResourceAllocation
                    | Capability::OwnershipFlagRegistration
                    | Capability::OwnershipGatedRelease
            ))
            .count(),
        4,
        "unlinked allocation and wrong-member registration are pruned"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(10), true)
        .expect("ownership reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::OwnershipGatedRelease
            && review.open_questions.iter().any(|question| {
                question.contains("ownership flag") && question.contains("exceptional exit")
            })
    }));

    write_profile(true);
    let fixed = mehscan_engine::scan_path(&root).expect("fixed ownership profile");
    let repeated = mehscan_engine::scan_path(&root).expect("deterministic ownership rescan");
    fs::remove_dir_all(&root).expect("remove temporary fixture");
    assert_eq!(fixed.evidence, repeated.evidence);
    assert_eq!(fixed.security_paths, repeated.security_paths);
    let fixed_paths = fixed
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::OwnershipGatedRelease)
        .collect::<Vec<_>>();
    assert_eq!(fixed_paths.len(), 2);
    assert!(fixed_paths.iter().all(|path| {
        path.state == SecurityPathState::Protected && path.protection_evidence_ids.len() == 1
    }));
}

#[test]
fn bounded_string_copy_requires_capacity_and_explicit_termination() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-termination-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create termination fixture");
    let source = |suffix: &str| {
        let size = if suffix == "c" {
            "(sizeof destination)"
        } else {
            "sizeof(destination)"
        };
        let terminator_index = if suffix == "c" {
            "(sizeof destination) - 1"
        } else {
            "sizeof(destination)-1"
        };
        format!(
            "typedef unsigned long size_t;\nchar *getenv(const char*);\nchar *strncpy(char*,const char*,size_t);\nchar *strncat(char*,const char*,size_t);\nvoid copy_{suffix}(void) {{\n  char destination[16];\n  char *input = getenv(\"VALUE\");\n  strncpy(destination, input, {size});\n#ifdef UNSELECTED_PROFILE\n  destination[{terminator_index}] = '\\0';\n#endif\n#ifdef FIX_PROFILE\n  destination[{terminator_index}] = '\\0';\n#endif\n}}\nvoid append_{suffix}(void) {{\n  char destination[16];\n  char *input = getenv(\"VALUE\");\n  strncat(destination, input, {size});\n  destination[{terminator_index}] = '\\0';\n}}\n"
        )
    };
    fs::write(root.join("copy.c"), source("c")).expect("write C termination fixture");
    fs::write(root.join("copy.cpp"), source("cpp")).expect("write C++ termination fixture");
    let write_profile = |fixed: bool| {
        let define = if fixed {
            "-DFIX_PROFILE"
        } else {
            "-UFIX_PROFILE"
        };
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[
              {{"directory":".","file":"copy.c","arguments":["cc","{define}","copy.c"]}},
              {{"directory":".","file":"copy.cpp","arguments":["c++","{define}","copy.cpp"]}}
            ]"#
            ),
        )
        .expect("write termination profile");
    };
    write_profile(false);
    let vulnerable = mehscan_engine::scan_path(&root).expect("vulnerable termination profile");
    let copies = vulnerable
        .evidence
        .iter()
        .filter(|item| {
            item.capability == Capability::BufferWrite
                && item
                    .captures
                    .get("source")
                    .is_some_and(|capture| capture.text == "input")
        })
        .collect::<Vec<_>>();
    assert_eq!(copies.len(), 4);
    assert!(
        copies.iter().all(|item| item.tags.iter().any(|tag| {
            tag == "string-termination:unproven"
                || tag == "buffer-capacity:destination-offset-unproven"
        })),
        "bounded copy evidence: {copies:#?}"
    );
    assert!(
        !vulnerable
            .evidence
            .iter()
            .any(|item| item.capability == Capability::StringTerminationValidation)
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(10), true)
        .expect("bounded string-copy reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::BufferWrite
            && review.open_questions.iter().any(|question| {
                question.contains("destination capacity")
                    && question.contains("in-bounds terminator")
            })
    }));

    write_profile(true);
    let fixed = mehscan_engine::scan_path(&root).expect("fixed termination profile");
    let repeated = mehscan_engine::scan_path(&root).expect("deterministic termination rescan");
    fs::remove_dir_all(&root).expect("remove termination fixture");
    assert_eq!(fixed.evidence, repeated.evidence);
    assert_eq!(fixed.security_paths, repeated.security_paths);
    assert_eq!(
        fixed
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::StringTerminationValidation)
            .count(),
        2
    );
    assert_eq!(
        fixed
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::BufferCapacityValidation)
            .count(),
        2,
        "strncat remains unprotected because its destination offset is unknown"
    );
    assert_eq!(
        fixed
            .security_paths
            .iter()
            .filter(|path| {
                path.capability == Capability::BufferWrite
                    && path.state == SecurityPathState::Protected
            })
            .count(),
        2,
        "only the terminated strncpy path is protected in C and C++"
    );
}

#[test]
fn signed_values_require_nonnegative_proof_before_memory_size_conversion() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-signed-size-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create signed-size fixture");
    let source = |cpp: bool| {
        let cast = if cpp {
            "static_cast<size_t>(count)"
        } else {
            "(size_t)count"
        };
        format!(
            "typedef unsigned long size_t;\nvoid *malloc(size_t);\nvoid *memcpy(void*,const void*,size_t);\nvoid profile_copy(char *dst, const char *src, int count) {{\n#ifdef FIX_PROFILE\n  if (count < 0) return;\n#endif\n  memcpy(dst, src, {cast});\n}}\nvoid less_one_copy(char *dst, const char *src, int count) {{\n  if (count < 1) return;\n  memcpy(dst, src, {cast});\n}}\nvoid nonpositive_copy(char *dst, const char *src, int count) {{\n  if (count <= 0) return;\n  memcpy(dst, src, {cast});\n}}\nvoid enclosed_copy(char *dst, const char *src, int count) {{\n  if (count >= 0) memcpy(dst, src, {cast});\n}}\nvoid else_lookalike(char *dst, const char *src, int count) {{\n  if (count >= 0) return; else memcpy(dst, src, {cast});\n}}\nvoid mismatch_copy(char *dst, const char *src, int count, int other) {{\n  if (other < 0) return;\n  memcpy(dst, src, {cast});\n}}\nvoid nested_guard_lookalike(char *dst, const char *src, int count, int enabled) {{\n  if (enabled) {{ if (count < 0) return; }}\n  memcpy(dst, src, {cast});\n}}\nvoid *profile_allocate(int count) {{\n#ifdef FIX_PROFILE\n  if (count < 0) return 0;\n#endif\n  return malloc({cast});\n}}\nvoid unsigned_lookalike(char *dst, const char *src, unsigned int count) {{\n  memcpy(dst, src, (size_t)count);\n}}\nsize_t arithmetic_only(int count) {{ return (size_t)count + 1; }}\n"
        )
    };
    fs::write(root.join("signed.c"), source(false)).expect("write C signed-size fixture");
    fs::write(root.join("signed.cpp"), source(true)).expect("write C++ signed-size fixture");
    let write_profile = |fixed: bool| {
        let define = if fixed {
            "-DFIX_PROFILE"
        } else {
            "-UFIX_PROFILE"
        };
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[
                  {{"directory":".","file":"signed.c","arguments":["cc","{define}","signed.c"]}},
                  {{"directory":".","file":"signed.cpp","arguments":["c++","{define}","signed.cpp"]}}
                ]"#
            ),
        )
        .expect("write signed-size profile");
    };

    write_profile(false);
    let vulnerable = mehscan_engine::scan_path(&root).expect("vulnerable signed-size profile");
    let vulnerable_paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::SignedSizeMemoryOperation)
        .collect::<Vec<_>>();
    assert_eq!(vulnerable_paths.len(), 16);
    assert_eq!(
        vulnerable_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        6
    );
    assert_eq!(
        vulnerable
            .evidence
            .iter()
            .filter(|item| item.capability == Capability::SignedSizeConversion)
            .count(),
        16,
        "unsigned and non-memory lookalikes must not become signed-size paths"
    );
    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), true)
        .expect("signed-size reviews");
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.capability == Capability::SignedSizeMemoryOperation
            && review.open_questions.iter().any(|question| {
                question.contains("signed value")
                    && question.contains("converted to size_t")
                    && question.contains("negative")
            })
    }));

    write_profile(true);
    let fixed = mehscan_engine::scan_path(&root).expect("fixed signed-size profile");
    let repeated = mehscan_engine::scan_path(&root).expect("deterministic signed-size rescan");
    fs::remove_dir_all(&root).expect("remove signed-size fixture");
    assert_eq!(fixed.evidence, repeated.evidence);
    assert_eq!(fixed.security_paths, repeated.security_paths);
    let fixed_paths = fixed
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::SignedSizeMemoryOperation)
        .collect::<Vec<_>>();
    assert_eq!(fixed_paths.len(), 16);
    assert_eq!(
        fixed_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        10
    );
    assert!(fixed_paths.iter().all(|path| {
        path.cwe_candidates.contains(&"CWE-195".to_string())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| fixed.evidence.iter().any(|item| item.id == *id))
    }));
}

#[test]
fn drogon_routes_keep_authentication_separate_from_resource_ownership() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "mehscan-native-drogon-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create Drogon fixture");
    fs::write(
        root.join("Token.cc"),
        r#"
auto TokenVerifier::decode(const std::string &token) {
  auto decoded = jwt::decode(token);
  verifier.verify(decoded);
  return decoded;
}
"#,
    )
    .expect("write verified decoder");
    fs::write(
        root.join("Filters.cc"),
        r#"
void AuthFilter::doFilter(const HttpRequestPtr &req, FilterCallback &&fail,
                          FilterChainCallback &&next) {
  try {
    auto token = req->getHeader("Authorization");
    auto decoded = verifier.decode(token);
    auto userId = decoded.get_payload_claim("user_id").as_int();
    req->attributes()->insert("user_id", userId);
    next();
  } catch (jwt::token_verification_exception &error) { fail(response); }
}
void ShapeFilter::doFilter(const HttpRequestPtr &req, FilterCallback &&fail,
                           FilterChainCallback &&next) {
  if (!req->getHeader("Authorization").empty()) next(); else fail(response);
}
"#,
    )
    .expect("write filter fixture");
    fs::write(
        root.join("Api.h"),
        r#"
ADD_METHOD_TO(Api::openDelete, "/open/{1}", Delete);
ADD_METHOD_TO(Api::authenticatedDelete, "/authenticated/{1}", Delete, "AuthFilter");
ADD_METHOD_TO(Api::ownedDelete, "/owned/{1}", Delete, "AuthFilter");
ADD_METHOD_TO(Api::lookalikeDelete, "/lookalike/{1}", Delete, "ShapeFilter");
// ADD_METHOD_TO(Api::commented, "/commented/{1}", Delete, "AuthFilter");
ADD_METHOD_TO(Api::dynamic, route_value, Delete, "AuthFilter");
"#,
    )
    .expect("write routes");
    fs::write(
        root.join("Api.cc"),
        r#"
void Api::openDelete(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int itemId) {
  mapper.deleteBy(Criteria(Item::Cols::_id, EQ, itemId));
}
void Api::authenticatedDelete(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int itemId) {
  mapper.deleteBy(Criteria(Item::Cols::_id, EQ, itemId));
}
void Api::ownedDelete(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int itemId) {
  auto callerId = req->attributes()->get<int>("user_id");
  if (callerId != itemId) return;
  mapper.deleteBy(Criteria(Item::Cols::_id, EQ, itemId));
}
void Api::lookalikeDelete(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, int itemId) {
  auto callerId = req->attributes()->get<int>("user_id");
  int otherId = 0;
  if (callerId != otherId) return;
  mapper.deleteBy(Criteria(Item::Cols::_id, EQ, itemId));
}
"#,
    )
    .expect("write controllers");

    let result = mehscan_engine::scan_path(&root).expect("scan Drogon fixture");
    let repeated = mehscan_engine::scan_path(&root).expect("repeat Drogon fixture");
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    let authentication = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-306"])
        .collect::<Vec<_>>();
    assert_eq!(authentication.len(), 4);
    assert_eq!(
        authentication
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        2,
        "only the filter with a verified-token success path authenticates routes"
    );
    let resource_paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-639"])
        .collect::<Vec<_>>();
    assert_eq!(resource_paths.len(), 3);
    assert!(
        resource_paths
            .iter()
            .all(|path| path.protection_evidence_ids.is_empty())
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| {
                item.capability == Capability::ResourceAccess
                    && item.context.resource_policy.as_ref().is_some_and(|policy| {
                        policy.state == mehscan_core::ResourcePolicyState::OwnerScoped
                    })
            })
            .count(),
        1,
        "the exact principal-to-resource rejecting guard closes only its own operation"
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "cpp-drogon-request-parameter")
            .count(),
        4,
        "unmapped callback and body parameters do not become request sources"
    );

    let reviews = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), true)
        .expect("Drogon review jobs");
    let repeated_reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), true)
            .expect("repeat Drogon review jobs");
    assert_eq!(reviews, repeated_reviews);
    assert!(reviews.reviews.iter().any(|review| {
        review.candidate.cwe_candidates == ["CWE-639"]
            && review.open_questions.iter().any(|question| {
                question.contains("owner") && question.contains("exact selected resource")
            })
    }));
    fs::remove_dir_all(&root).expect("remove Drogon fixture");
}
