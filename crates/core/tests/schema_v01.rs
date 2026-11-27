use mehscan_core::ScanResult;

macro_rules! round_trip {
    ($name:ident, $version:literal) => {
        #[test]
        fn $name() {
            let fixture = include_str!(concat!(
                "../../../tests/expected/scan-result-v",
                $version,
                ".json"
            ));
            let expected: serde_json::Value =
                serde_json::from_str(fixture).expect("golden JSON is valid");
            let result: ScanResult =
                serde_json::from_value(expected.clone()).expect("schema is compatible");
            assert_eq!(
                serde_json::to_value(result).expect("scan result serializes"),
                expected
            );
        }
    };
}

round_trip!(scan_result_v01_round_trips_without_shape_drift, "0.1");
round_trip!(scan_result_v02_round_trips_symbol_resolution, "0.2");
round_trip!(scan_result_v03_round_trips_context_annotations, "0.3");
round_trip!(scan_result_v04_round_trips_literal_annotations, "0.4");
round_trip!(
    scan_result_v05_round_trips_http_entrypoint_capability,
    "0.5"
);
round_trip!(scan_result_v06_round_trips_redacted_secret_metadata, "0.6");
round_trip!(scan_result_v07_round_trips_text_secret_coverage, "0.7");
round_trip!(scan_result_v08_round_trips_http_request_sources, "0.8");
round_trip!(scan_result_v09_round_trips_sql_protection_evidence, "0.9");
round_trip!(scan_result_v10_round_trips_bounded_security_paths, "1.0");
round_trip!(scan_result_v11_round_trips_protected_process_paths, "1.1");
round_trip!(scan_result_v12_round_trips_html_encoding_evidence, "1.2");
round_trip!(scan_result_v13_round_trips_path_protection_evidence, "1.3");
round_trip!(scan_result_v14_round_trips_url_context_evidence, "1.4");
round_trip!(
    scan_result_v15_round_trips_redirect_validation_evidence,
    "1.5"
);
round_trip!(scan_result_v16_round_trips_uploaded_path_evidence, "1.6");
round_trip!(
    scan_result_v17_round_trips_deserialization_restriction_evidence,
    "1.7"
);
round_trip!(
    scan_result_v18_round_trips_dynamic_code_restriction_evidence,
    "1.8"
);
round_trip!(
    scan_result_v19_round_trips_uploaded_file_content_evidence,
    "1.9"
);
round_trip!(
    scan_result_v20_round_trips_stored_user_content_evidence,
    "2.0"
);
round_trip!(
    scan_result_v21_round_trips_fixed_format_transform_evidence,
    "2.1"
);
