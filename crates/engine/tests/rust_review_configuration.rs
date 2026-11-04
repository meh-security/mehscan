mod support;
use std::{fs, path::PathBuf};

struct Project(PathBuf);

impl Project {
    fn new(parent: &str) -> Self {
        let root = support::temp_dir("rust-review-cfg");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"review_cfg\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), parent).unwrap();
        fs::write(root.join("src/models.rs"),r#"
pub struct Meter { used:i32, ceiling:i32 }
impl Meter {
  pub fn load(conn:&mut Connection)->Option<Self>{meters::table.filter(id.eq(7)).first::<Self>(conn).ok()}
  pub fn commit(&mut self,conn:&mut Connection){diesel::update(meters::table).set(self).execute(conn);}
}
"#).unwrap();
        fs::write(
            root.join("src/operations.rs"),
            r#"
use crate::models::Meter;
fn consume(conn:&mut Connection)->Result<(),Error>{
  let mut row=Meter::load(conn).unwrap();
  if row.used>=row.ceiling{return Err(Error::Limit);}
  row.used+=1;
  row.commit(conn);
  Ok(())
}
"#,
        )
        .unwrap();
        Self(root)
    }

    fn inventory(&self) -> mehscan_engine::investigation::ReviewInventory {
        mehscan_engine::investigation::build_review_inventory(&self.0, false).unwrap()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn shared_state_ids(inventory: &mehscan_engine::investigation::ReviewInventory) -> Vec<&str> {
    inventory
        .entries
        .iter()
        .filter(|entry| entry.rule_id == "rust-shared-state-limit-review-marker")
        .map(|entry| entry.review_id.as_str())
        .collect()
}

#[test]
fn excluded_callers_and_excluded_model_definitions_do_not_generate_review_work() {
    let enabled = Project::new("mod models;mod operations;");
    assert_eq!(
        shared_state_ids(&enabled.inventory()).len(),
        1,
        "supported load/check/change/persistence question must survive"
    );
    for parent in [
        "mod models;#[cfg(any())] mod operations;",
        "#[cfg(any())] mod models;mod operations;",
        "mod models;#[cfg(test)] mod operations;",
    ] {
        let project = Project::new(parent);
        let scan = mehscan_engine::scan_path(&project.0).unwrap();
        assert!(
            scan.coverage
                .files
                .iter()
                .any(|file| file.status == mehscan_core::FileStatus::Ignored
                    && file.reason.as_deref()
                        == Some("Rust module excluded by established source configuration")),
            "{parent}"
        );
        assert!(
            shared_state_ids(&project.inventory()).is_empty(),
            "excluded source cannot supply a marker or its model proof: {parent}"
        );
    }
}

#[test]
fn conditional_configuration_reaches_derived_markers_and_initial_workspace_questions() {
    let project = Project::new("mod models;#[cfg(feature=\"extra\")] mod operations;");
    let inventory = project.inventory();
    assert_eq!(shared_state_ids(&inventory).len(), 1);
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.rule_id == "rust-shared-state-limit-review-marker")
        .unwrap();
    let entry = serde_json::to_value(entry).unwrap();
    assert_eq!(
        entry["source_configuration"]["state"], "conditional",
        "initial workspace questions must retain parent configuration"
    );
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&project.0, None, false).unwrap();
    let marker = job
        .observation_reviews
        .iter()
        .flat_map(|review| &review.evidence)
        .find(|fact| fact.rule_id == "rust-shared-state-limit-review-marker")
        .unwrap();
    assert_eq!(
        marker.context.availability.as_ref().unwrap().state,
        mehscan_core::AvailabilityState::Conditional
    );
    assert!(
        marker
            .context
            .configuration_dependencies
            .iter()
            .any(
                |dependency| dependency.declaration.location.path == "src/lib.rs"
                    && dependency.declaration.text.contains("mod operations")
            )
    );
}

#[test]
fn disabled_persistence_helpers_cannot_establish_production_review_mechanisms() {
    for attribute in ["#[cfg(test)]", "#[cfg(any())]"] {
        let project = Project::new("mod models;mod operations;");
        let path = project.0.join("src/models.rs");
        let source = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            source.replace("pub fn commit", &format!("{attribute} pub fn commit")),
        )
        .unwrap();
        assert!(
            shared_state_ids(&project.inventory()).is_empty(),
            "an unavailable write cannot establish a production persistence effect: {attribute}"
        );
    }
}

#[test]
fn local_caller_configuration_reaches_the_initial_question() {
    let project = Project::new("mod models;mod operations;");
    let path = project.0.join("src/operations.rs");
    let source = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        source.replace("fn consume", "#[cfg(feature=\"extra\")] fn consume"),
    )
    .unwrap();
    let inventory = project.inventory();
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.rule_id == "rust-shared-state-limit-review-marker")
        .unwrap();
    assert_eq!(
        serde_json::to_value(entry).unwrap()["source_configuration"]["state"],
        "conditional"
    );
}

#[test]
fn local_helper_conditions_survive_and_test_duplicates_do_not_hide_active_helpers() {
    let project = Project::new("mod models;mod operations;");
    let path = project.0.join("src/models.rs");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        original.replace("pub fn commit", "#[cfg(feature=\"write\")] pub fn commit"),
    )
    .unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&project.0, None, false).unwrap();
    let fact = jobs
        .observation_reviews
        .iter()
        .flat_map(|review| &review.evidence)
        .find(|fact| fact.rule_id == "rust-shared-state-limit-review-marker")
        .unwrap();
    assert_eq!(
        fact.context.availability.as_ref().unwrap().state,
        mehscan_core::AvailabilityState::Conditional
    );
    assert!(
        fact.context
            .configuration_dependencies
            .iter()
            .any(|dependency| {
                dependency.declaration.location.path == "src/models.rs"
                    && dependency.declaration.text.contains("feature=\"write\"")
            })
    );
    fs::write(&path, format!("{original}\n#[cfg(test)] impl Meter {{pub fn commit(&mut self,conn:&mut Connection){{local_test_write(self,conn);}}}}\n")).unwrap();
    assert_eq!(
        shared_state_ids(&project.inventory()).len(),
        1,
        "a test-only duplicate cannot make the real persistence helper ambiguous"
    );
}

#[test]
fn excluded_local_callers_are_not_admitted_but_test_mode_can_select_test_helpers() {
    let project = Project::new("mod models;mod operations;");
    let path = project.0.join("src/operations.rs");
    let original = fs::read_to_string(&path).unwrap();
    for attribute in ["#[cfg(any())]", "#[cfg(test)]", "#[test]"] {
        fs::write(
            &path,
            original.replace("fn consume", &format!("{attribute} fn consume")),
        )
        .unwrap();
        assert!(
            shared_state_ids(&project.inventory()).is_empty(),
            "{attribute}"
        );
    }
    fs::write(&path, original).unwrap();
    let path = project.0.join("src/models.rs");
    let source = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        source.replace("pub fn commit", "#[cfg(test)] pub fn commit"),
    )
    .unwrap();
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&project.0, true).unwrap();
    assert_eq!(shared_state_ids(&inventory).len(), 1);
}

#[test]
fn test_only_sdk_shadows_do_not_suppress_an_active_persistence_helper() {
    for (attribute, expected) in [("#[cfg(test)]", 1), ("", 0)] {
        let project = Project::new("mod models;mod operations;");
        let path = project.0.join("src/models.rs");
        let source = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{source}\n{attribute} mod diesel {{}}\n")).unwrap();
        assert_eq!(
            shared_state_ids(&project.inventory()).len(),
            expected,
            "{attribute}"
        );
    }
}

#[test]
fn cached_rust_inventory_from_before_pointer_cast_admission_requires_regeneration() {
    let project = Project::new(
        "mod models;mod operations;pub fn bytes<T:Copy>(v:Vec<T>)->Vec<u8>{let mut v=std::mem::ManuallyDrop::new(v);unsafe{Vec::from_raw_parts(v.as_mut_ptr().cast::<u8>(),v.len()*std::mem::size_of::<T>(),v.capacity()*std::mem::size_of::<T>())}}",
    );
    let mut inventory = project.inventory();
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.rule_id == "rust-vector-layout-review")
    );
    mehscan_engine::investigation::validate_review_inventory(&project.0, &inventory).unwrap();
    for previous in [
        "typed-source-and-raw-memory-v4",
        "typed-source-and-raw-memory-v5",
        "typed-source-and-raw-memory-v6",
        "typed-source-and-raw-memory-v7",
        "typed-source-and-raw-memory-v8",
    ] {
        inventory.rust_configuration_revision = Some(previous.into());
        let error =
            mehscan_engine::investigation::validate_review_inventory(&project.0, &inventory)
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("Rust source configuration analysis changed"),
            "{error}"
        );
    }
}
