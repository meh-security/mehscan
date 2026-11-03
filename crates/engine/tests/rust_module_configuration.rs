use mehscan_core::{AvailabilityState, ScanResult};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

fn scan(files: &[(&str, &str)], include_tests: bool) -> ScanResult {
    let root = std::env::temp_dir().join(format!(
        "mehscan-module-cfg-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let mut sources: BTreeMap<_, _> = files
        .iter()
        .map(|(path, text)| (path.to_string(), text.to_string()))
        .collect();
    sources
        .entry("Cargo.toml".into())
        .or_insert("[package]\nname=\"sample\"\nversion=\"0.1.0\"\nedition=\"2021\"\n".into());
    for (path, text) in &sources {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let result = mehscan_engine::scan_path_with_options(
        &root,
        mehscan_engine::ScanOptions {
            include_tests,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        result.coverage.totals.parse_failed, 0,
        "{:#?}",
        result.diagnostics
    );
    for evidence in &result.evidence {
        for dep in &evidence.context.configuration_dependencies {
            let source = &sources[&dep.declaration.location.path];
            let location = &dep.declaration.location;
            assert_eq!(
                &source[location.start.byte_offset..location.end.byte_offset],
                dep.declaration.text
            );
            assert_eq!(
                format!("{:x}", Sha256::digest(source.as_bytes())),
                dep.source_sha256
            );
            assert!(sources.contains_key(&dep.target_path));
        }
    }
    fs::remove_dir_all(root).unwrap();
    result
}

const QUERY: &str =
    "pub async fn run(q:&str,pool:&sqlx::PgPool){sqlx::query(q).execute(pool).await;}";

#[test]
fn unknown_package_expansion_uses_one_witness_and_keeps_the_actual_module_route() {
    for count in [16, 128] {
        let mut parent = "#[cfg(feature=\"extra\")] mod helper;\n".to_string();
        let mut files = vec![("src/helper.rs".to_string(), QUERY.to_string())];
        for i in 0..count {
            parent.push_str(&format!("mod opaque_{i};\n"));
            files.push((
                format!("src/opaque_{i}.rs"),
                "external_generator!{}\n".into(),
            ));
        }
        files.push(("src/lib.rs".into(), parent));
        let files: Vec<_> = files
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect();
        let result = scan(&files, false);
        let fact = result
            .evidence
            .iter()
            .find(|fact| fact.location.path == "src/helper.rs")
            .unwrap();
        assert_eq!(
            fact.context.availability.as_ref().unwrap().state,
            AvailabilityState::Unknown
        );
        assert!(
            fact.context.configuration_dependencies.len() <= 5,
            "unrelated opaque macros cannot multiply identical uncertainty proof"
        );
        assert!(
            fact.context
                .configuration_dependencies
                .iter()
                .any(|dependency| {
                    dependency.declaration.location.path == "src/lib.rs"
                        && dependency.declaration.text.contains("mod helper")
                })
        );
    }
}

fn state(result: &ScanResult, path: &str) -> Option<AvailabilityState> {
    result
        .evidence
        .iter()
        .find(|e| {
            e.location.path == path && e.capability == mehscan_core::Capability::DatabaseQuery
        })
        .map(|e| e.context.availability.as_ref().unwrap().state)
}

#[test]
fn external_module_conditions_and_test_policy_reach_the_actual_file() {
    for (attribute, expected) in [
        (
            "#[cfg(feature=\"extra\")]",
            Some(AvailabilityState::Conditional),
        ),
        ("#[cfg(any())]", None),
        ("#[cfg(false)]", None),
        ("#[cfg(test)]", None),
        ("#[cfg(all())]", Some(AvailabilityState::Always)),
        ("#[cfg(true)]", Some(AvailabilityState::Always)),
    ] {
        let parent = format!("// Unicode stays physical: 🦀\n{attribute}\nmod helper;");
        let result = scan(&[("src/lib.rs", &parent), ("src/helper.rs", QUERY)], false);
        assert_eq!(state(&result, "src/helper.rs"), expected, "{attribute}");
        if expected == Some(AvailabilityState::Conditional) {
            let fact = result
                .evidence
                .iter()
                .find(|e| e.location.path == "src/helper.rs")
                .unwrap();
            assert!(
                fact.context
                    .availability
                    .as_ref()
                    .unwrap()
                    .condition
                    .as_ref()
                    .unwrap()
                    .contains("extra")
            );
            assert!(
                fact.context
                    .configuration_dependencies
                    .iter()
                    .any(|d| d.target_path == "src/helper.rs"
                        && d.declaration.text.contains("mod helper"))
            );
        }
    }
    let include = scan(
        &[
            ("src/lib.rs", "#[cfg(test)] mod helper;"),
            ("src/helper.rs", QUERY),
        ],
        true,
    );
    assert_eq!(
        state(&include, "src/helper.rs"),
        Some(AvailabilityState::Conditional)
    );
}

#[test]
fn alternate_roots_and_sibling_module_owners_do_not_borrow_exclusion() {
    let result = scan(
        &[
            (
                "src/lib.rs",
                "#[cfg(any())] #[path=\"helper.rs\"] mod helper;",
            ),
            (
                "src/main.rs",
                "#[path=\"helper.rs\"] mod helper; fn main(){}",
            ),
            ("src/helper.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/helper.rs"),
        Some(AvailabilityState::Always)
    );
    let result = scan(
        &[
            ("src/lib.rs", "mod left;mod right;"),
            ("src/left.rs", "#[cfg(feature=\"extra\")] mod helper;"),
            ("src/right.rs", "mod helper;"),
            ("src/left/helper.rs", QUERY),
            ("src/right/helper.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/left/helper.rs"),
        Some(AvailabilityState::Conditional)
    );
    assert_eq!(
        state(&result, "src/right/helper.rs"),
        Some(AvailabilityState::Always)
    );
}

#[test]
fn nested_paths_target_metadata_and_unresolved_routes_keep_their_boundaries() {
    let result = scan(
        &[
            (
                "src/lib.rs",
                "#[cfg(feature=\"extra\")] mod outer { mod helper; }",
            ),
            ("src/outer/helper.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/outer/helper.rs"),
        Some(AvailabilityState::Conditional)
    );
    let result = scan(
        &[
            ("src/lib.rs", "mod outer;"),
            (
                "src/outer/mod.rs",
                "#[cfg(feature=\"extra\")] #[path=r#\"../shared.rs\"#] mod helper;",
            ),
            ("src/shared.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/shared.rs"),
        Some(AvailabilityState::Conditional)
    );
    let result = scan(
        &[
            (
                "Cargo.toml",
                "[package]\nname=\"sample\"\nversion=\"0.1.0\"\nautobins=false\n[[bin]]\nname=\"tool\"\npath=\"tools/start.rs\"\nrequired-features=[\"extra\"]\n",
            ),
            ("tools/start.rs", "mod helper;fn main(){}"),
            ("tools/helper.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "tools/helper.rs"),
        Some(AvailabilityState::Conditional)
    );
    let result = scan(
        &[
            (
                "Cargo.toml",
                "[package]\nname=\"sample\"\nversion=\"0.1.0\"\n[[test]]\nname=\"tool\"\npath=\"tools/check.rs\"\n",
            ),
            ("tools/check.rs", QUERY),
        ],
        false,
    );
    assert_eq!(state(&result, "tools/check.rs"), None);
    let result = scan(
        &[
            ("src/lib.rs", "mod helper;"),
            ("src/helper.rs", QUERY),
            ("src/helper/mod.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/helper.rs"),
        Some(AvailabilityState::Unknown)
    );
    assert_eq!(
        state(&result, "src/helper/mod.rs"),
        Some(AvailabilityState::Unknown)
    );
    let result = scan(
        &[
            ("src/lib.rs", "#[cfg(any())] mod helper; make_modules!();"),
            ("src/helper.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/helper.rs"),
        Some(AvailabilityState::Unknown)
    );
    let result = scan(
        &[
            ("src/lib.rs", "#[path=\"lib.rs\"] mod again;"),
            ("src/orphan.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/orphan.rs"),
        Some(AvailabilityState::Always)
    );
}

#[test]
fn path_loaded_files_and_root_loaded_files_keep_separate_search_contexts() {
    let result = scan(
        &[
            (
                "src/lib.rs",
                "#[cfg(feature=\"extra\")] #[path=\"renamed.rs\"] mod alias;",
            ),
            ("src/renamed.rs", "mod helper;"),
            ("src/helper.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/helper.rs"),
        Some(AvailabilityState::Conditional)
    );
    let result = scan(
        &[
            ("src/lib.rs", "mod container;"),
            (
                "src/container.rs",
                "#[cfg(feature=\"extra\")] #[path=\"selected\"] mod inline {mod helper;}",
            ),
            ("src/selected/helper.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/selected/helper.rs"),
        Some(AvailabilityState::Conditional)
    );
    let fact = result
        .evidence
        .iter()
        .find(|e| e.location.path == "src/selected/helper.rs")
        .unwrap();
    assert!(
        fact.context
            .configuration_dependencies
            .iter()
            .any(|d| d.declaration.text.contains("selected"))
    );
    let result = scan(
        &[
            ("src/lib.rs", "mod child;"),
            (
                "src/main.rs",
                "#[cfg(feature=\"extra\")] mod lib;fn main(){}",
            ),
            ("src/child.rs", QUERY),
            ("src/lib/child.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/child.rs"),
        Some(AvailabilityState::Always)
    );
    assert_eq!(
        state(&result, "src/lib/child.rs"),
        Some(AvailabilityState::Conditional)
    );
    let result = scan(
        &[
            ("src/lib.rs", "#[cfg(feature=\"extra\")] mod r#type;"),
            ("src/type.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/type.rs"),
        Some(AvailabilityState::Conditional)
    );
}

#[test]
fn observation_packets_carry_configuration_and_changed_manifests_reject_reuse() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-cfg-packet-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("src")).unwrap();
    let cargo = "[package]\nname=\"sample\"\nversion=\"0.1.0\"\n";
    fs::write(root.join("Cargo.toml"), cargo).unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "#[cfg(feature=\"extra\")] mod helper;",
    )
    .unwrap();
    fs::write(root.join("src/helper.rs"), QUERY).unwrap();
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    assert!(
        job.observation_reviews
            .iter()
            .filter_map(|r| r.review_basis.as_ref())
            .flat_map(|b| &b.observations)
            .any(|b| b
                .configuration
                .as_ref()
                .is_some_and(|a| a.state == AvailabilityState::Conditional)
                && b.configuration_dependencies
                    .iter()
                    .any(|d| d.target_path == "src/helper.rs"))
    );
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    let mut old = inventory.clone();
    old.rust_configuration_revision = None;
    assert!(mehscan_engine::investigation::validate_review_inventory(&root, &old).is_err());
    let ids = [inventory.entries[0].review_id.clone()]
        .into_iter()
        .collect();
    fs::write(root.join("Cargo.toml"), format!("{cargo}autolib=false\n")).unwrap();
    assert!(
        mehscan_engine::investigation::build_selected_review_jobs(&root, &inventory, &ids, None)
            .is_err()
    );
    fs::write(root.join("Cargo.toml"), cargo).unwrap();
    fs::write(root.join("src/lib.rs"), "#[cfg(any())] mod helper;").unwrap();
    assert!(
        mehscan_engine::investigation::build_selected_review_jobs(&root, &inventory, &ids, None)
            .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn module_applicability_does_not_erase_a_same_file_null_guard() {
    let source = "struct View {address:*mut u8} impl View {fn empty()->Self{Self{address:std::ptr::null_mut()}} fn bytes(&self)->&[u8]{if self.address.is_null(){return &[];}unsafe{std::slice::from_raw_parts(self.address,0)}}}";
    let result = scan(
        &[
            ("src/lib.rs", "#[cfg(feature=\"extra\")] mod helper;"),
            ("src/helper.rs", source),
        ],
        false,
    );
    let path = result
        .security_paths
        .iter()
        .find(|p| p.capability == mehscan_core::Capability::RustRawSliceConstruction)
        .expect("the concrete invariant remains observable");
    assert_eq!(path.state, mehscan_core::SecurityPathState::Protected);
    assert_eq!(
        result
            .evidence
            .iter()
            .find(|e| e.id == path.sink_evidence_id)
            .unwrap()
            .context
            .availability
            .as_ref()
            .unwrap()
            .state,
        AvailabilityState::Conditional
    );
}

#[test]
fn transforming_attributes_and_conditional_paths_never_prove_an_unconditional_route() {
    for source in [
        "#[vendor::transform] mod helper;",
        "#[cfg_attr(feature=\"extra\", vendor::transform)] mod helper;",
        "#[cfg_attr(feature=\"extra\", path=\"other.rs\")] mod helper;",
    ] {
        let result = scan(
            &[
                ("src/lib.rs", source),
                ("src/helper.rs", QUERY),
                ("src/other.rs", QUERY),
            ],
            false,
        );
        assert_eq!(
            state(&result, "src/helper.rs"),
            Some(AvailabilityState::Unknown),
            "{source}"
        );
    }
    let result = scan(
        &[
            (
                "src/lib.rs",
                "#[cfg(any())] #[macro_use] mod helper; mod live;",
            ),
            ("src/helper.rs", "macro_rules! make {()=>{mod hidden;}}"),
            ("src/live.rs", QUERY),
        ],
        false,
    );
    assert_eq!(
        state(&result, "src/live.rs"),
        Some(AvailabilityState::Always)
    );
}
