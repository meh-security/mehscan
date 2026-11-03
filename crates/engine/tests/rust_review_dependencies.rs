mod support;
use std::{fs, path::PathBuf};
struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        let root = support::temp_dir("rust-review-dependencies");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"dependencies\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "mod models;mod operations;mod identity;",
        )
        .unwrap();
        fs::write(root.join("src/models.rs"),r#"
macro_rules! persist {($e:expr)=>{{let _guard=connection_lock();$e}}}
pub struct Connection{pool:Pool}
pub struct Meter{used:i32,ceiling:i32}
impl Meter{
 pub fn load(conn:&mut Connection)->Option<Self>{meters::table.first::<Self>(conn).ok()}
 pub fn commit(&mut self,conn:&mut Connection){persist!(diesel::update(meters::table).set(self).execute(conn));}
}
"#).unwrap();
        fs::write(root.join("src/identity.rs"),"pub struct Actor{person:Person}\npub struct Person{id:i64}\nimpl Actor{pub fn authorized(&self)->bool{self.person.id>0}}\n").unwrap();
        fs::write(
            root.join("src/operations.rs"),
            r#"
use crate::models::{Meter,Connection};use crate::identity::Actor;
fn consume(conn:&mut Connection,actor:Actor)->Result<(),Error>{
 if !actor.authorized(){return Err(Error::Denied);}
 let mut row=Meter::load(conn).unwrap();
 if row.used>=row.ceiling{return Err(Error::Limit);}
 row.used+=1;row.commit(conn);Ok(())
}
"#,
        )
        .unwrap();
        Self(root)
    }
    fn fact(&self) -> mehscan_core::Evidence {
        mehscan_engine::investigation::build_all_path_review_jobs(&self.0, None, false)
            .unwrap()
            .observation_reviews
            .into_iter()
            .flat_map(|r| r.evidence)
            .find(|e| e.rule_id == "rust-shared-state-limit-review-marker")
            .unwrap()
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn typed_identity_and_macro_persistence_context_is_automatic_source_exact_and_not_a_dispatch_verdict()
 {
    let p = Project::new();
    let fact = p.fact();
    let context = fact
        .captures
        .iter()
        .filter(|(role, _)| role.starts_with("rust_context_"))
        .map(|(_, c)| c.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(context.contains("struct Actor"), "{context}");
    assert!(context.contains("authorized(&self)"), "{context}");
    assert!(context.contains("macro_rules! persist"), "{context}");
    assert!(
        fact.tags
            .iter()
            .any(|t| t == "rust-source-context:not-dispatch-proof")
    );
    let job = mehscan_engine::investigation::build_all_path_review_jobs(&p.0, None, false).unwrap();
    let delivered = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.rule_id == "rust-shared-state-limit-review-marker")
        })
        .unwrap()
        .facts
        .iter()
        .map(|f| f.excerpt.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(delivered.contains("struct Actor"), "{delivered}");
    assert!(delivered.contains("authorized(&self)"), "{delivered}");
    assert!(delivered.contains("macro_rules! persist"), "{delivered}");
    assert!(
        fact.tags
            .iter()
            .any(|t| t == "macro-persistence-semantics-unresolved")
    );
    for c in fact.captures.values() {
        let bytes = fs::read(p.0.join(&c.location.path)).unwrap();
        assert_eq!(
            &bytes[c.location.start.byte_offset..c.location.end.byte_offset],
            c.text.as_bytes()
        );
    }
}
#[test]
fn test_only_and_excluded_definitions_never_supply_production_context() {
    let p = Project::new();
    fs::write(p.0.join("src/identity.rs"),"pub struct Actor;#[cfg(any())]impl Actor{pub fn authorized(&self)->bool{false}}\n#[cfg(test)]mod hidden{pub struct Actor{test_secret:bool}}\n").unwrap();
    let fact = p.fact();
    let context = fact
        .captures
        .iter()
        .filter(|(k, _)| k.starts_with("rust_context_"))
        .map(|(_, c)| c.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!context.contains("test_secret"));
    assert!(!context.contains("->bool{false}"));
}
#[test]
fn ambiguous_macro_bodies_are_not_selected_as_unique_implementations() {
    let p = Project::new();
    let path = p.0.join("src/identity.rs");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(
        path,
        original + "\nmacro_rules! persist {($e:expr)=>{not_the_database($e)}}\n",
    )
    .unwrap();
    let fact = p.fact();
    assert!(
        !fact
            .captures
            .iter()
            .filter(|(k, _)| k.starts_with("rust_context_"))
            .any(|(_, c)| c.text.contains("not_the_database"))
    );
}

#[test]
fn optional_context_does_not_gate_the_operation() {
    let p = Project::new();
    fs::write(p.0.join("src/identity.rs"),"#[cfg(feature=\"optional\")]pub struct Actor;impl Actor{pub fn authorized(&self)->bool{true}}\n").unwrap();
    let fact = p.fact();
    assert_eq!(
        fact.context.availability.as_ref().map(|a| &a.state),
        Some(&mehscan_core::AvailabilityState::Always)
    );
    assert!(
        fact.captures
            .iter()
            .any(|(k, c)| k.starts_with("rust_context_") && c.text.contains("struct Actor"))
    );
}

#[test]
fn trait_object_identity_keeps_its_contract_without_selecting_an_unrelated_concrete_type() {
    let p = Project::new();
    let path = p.0.join("src/identity.rs");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        text + "\npub trait Check{fn authorized(&self)->bool;}\n",
    )
    .unwrap();
    let path = p.0.join("src/operations.rs");
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace(
            "use crate::identity::Actor;",
            "use crate::identity::{Actor,Check};",
        )
        .replace("actor:Actor", "actor:&dyn Check");
    fs::write(path, text).unwrap();
    let fact = p.fact();
    let context = fact
        .captures
        .iter()
        .filter(|(k, _)| k.starts_with("rust_context_"))
        .map(|(_, c)| c.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(context.contains("trait Check"), "{context}");
    assert!(!context.contains("person:Person"), "{context}");
    assert!(!context.contains("self.person.id>0"), "{context}");
}
