use std::fs;
use std::path::PathBuf;

use mehscan_core::{FileOutline, InvestigationJob, QueryResponse};

#[test]
fn investigation_v02_golden_round_trips() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/expected/investigation-outline-v0.2.json");
    let source = fs::read_to_string(path).expect("golden response should be readable");
    let response: QueryResponse<FileOutline> =
        serde_json::from_str(&source).expect("golden response should deserialize");
    assert_eq!(response.schema_version, "0.2");
    assert_eq!(response.operation, "get_file_outline");
    assert_eq!(response.results.symbols[0].name, "review");
    let encoded = serde_json::to_value(&response).expect("response should serialize");
    let expected: serde_json::Value =
        serde_json::from_str(&source).expect("golden JSON should parse");
    assert_eq!(encoded, expected);
}

#[test]
fn investigation_job_v02_golden_round_trips() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/expected/investigation-job-v0.2.json");
    let source = fs::read_to_string(path).expect("golden job should be readable");
    let job: InvestigationJob =
        serde_json::from_str(&source).expect("golden job should deserialize");
    assert_eq!(job.schema_version, "0.2");
    assert_eq!(job.operation, "build_investigation_units");
    assert_eq!(job.limits.max_units, 25);
    let encoded = serde_json::to_value(&job).expect("job should serialize");
    let expected: serde_json::Value =
        serde_json::from_str(&source).expect("golden JSON should parse");
    assert_eq!(encoded, expected);
}
