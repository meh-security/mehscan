use mehscan_core::ScanResult;

const GOLDEN: &str = include_str!("../../../tests/expected/scan-result-v0.1.json");
const GOLDEN_V02: &str = include_str!("../../../tests/expected/scan-result-v0.2.json");
const GOLDEN_V03: &str = include_str!("../../../tests/expected/scan-result-v0.3.json");
const GOLDEN_V04: &str = include_str!("../../../tests/expected/scan-result-v0.4.json");
const GOLDEN_V05: &str = include_str!("../../../tests/expected/scan-result-v0.5.json");
const GOLDEN_V06: &str = include_str!("../../../tests/expected/scan-result-v0.6.json");
const GOLDEN_V07: &str = include_str!("../../../tests/expected/scan-result-v0.7.json");
const GOLDEN_V08: &str = include_str!("../../../tests/expected/scan-result-v0.8.json");
const GOLDEN_V09: &str = include_str!("../../../tests/expected/scan-result-v0.9.json");
const GOLDEN_V10: &str = include_str!("../../../tests/expected/scan-result-v1.0.json");
const GOLDEN_V11: &str = include_str!("../../../tests/expected/scan-result-v1.1.json");
const GOLDEN_V12: &str = include_str!("../../../tests/expected/scan-result-v1.2.json");
const GOLDEN_V13: &str = include_str!("../../../tests/expected/scan-result-v1.3.json");
const GOLDEN_V14: &str = include_str!("../../../tests/expected/scan-result-v1.4.json");
const GOLDEN_V15: &str = include_str!("../../../tests/expected/scan-result-v1.5.json");
const GOLDEN_V16: &str = include_str!("../../../tests/expected/scan-result-v1.6.json");
const GOLDEN_V17: &str = include_str!("../../../tests/expected/scan-result-v1.7.json");
const GOLDEN_V18: &str = include_str!("../../../tests/expected/scan-result-v1.8.json");
const GOLDEN_V19: &str = include_str!("../../../tests/expected/scan-result-v1.9.json");
const GOLDEN_V20: &str = include_str!("../../../tests/expected/scan-result-v2.0.json");
const GOLDEN_V21: &str = include_str!("../../../tests/expected/scan-result-v2.1.json");

#[test]
fn scan_result_v01_round_trips_without_shape_drift() {
    let expected: serde_json::Value = serde_json::from_str(GOLDEN).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v02_round_trips_symbol_resolution() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V02).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v03_round_trips_context_annotations() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V03).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v04_round_trips_literal_annotations() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V04).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v05_round_trips_http_entrypoint_capability() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V05).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v06_round_trips_redacted_secret_metadata() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V06).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v07_round_trips_text_secret_coverage() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V07).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v08_round_trips_http_request_sources() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V08).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v09_round_trips_sql_protection_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V09).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v10_round_trips_bounded_security_paths() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V10).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v11_round_trips_protected_process_paths() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V11).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v12_round_trips_html_encoding_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V12).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v13_round_trips_path_protection_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V13).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v14_round_trips_url_context_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V14).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v15_round_trips_redirect_validation_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V15).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v16_round_trips_uploaded_path_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V16).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v17_round_trips_deserialization_restriction_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V17).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v18_round_trips_dynamic_code_restriction_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V18).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v19_round_trips_uploaded_file_content_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V19).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v20_round_trips_stored_user_content_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V20).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}

#[test]
fn scan_result_v21_round_trips_fixed_format_transform_evidence() {
    let expected: serde_json::Value =
        serde_json::from_str(GOLDEN_V21).expect("golden JSON is valid");
    let result: ScanResult =
        serde_json::from_value(expected.clone()).expect("schema is compatible");
    let actual = serde_json::to_value(result).expect("scan result serializes");
    assert_eq!(actual, expected);
}
