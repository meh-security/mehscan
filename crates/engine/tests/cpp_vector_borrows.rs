mod support;
use mehscan_core::Capability;
use std::fs;

const SOURCE: &str = r#"
#include <vector>
#include <map>
std::map<int,std::vector<int>> rows;
std::map<int,int*> pointers;
void collect(int key, int n) {
 for(int i=0;i<n;++i){
   std::vector<int>& values=rows[key];
   values.resize(n);
   pointers.insert({i,&values[0]});
 }
}
"#;
fn scan(source: &str) -> mehscan_core::ScanResult {
    let root = support::temp_dir("cpp-vector-borrow");
    fs::write(root.join("source.cpp"), source).unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for fact in scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::ContainerBorrowLifetime)
    {
        for capture in fact.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
    scan
}
fn count(source: &str) -> usize {
    scan(source)
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::ContainerBorrowLifetime)
        .count()
}

#[test]
fn typed_persistent_borrow_and_complete_guarded_operation_remain_reviewable() {
    assert_eq!(count(SOURCE), 1);
    assert_eq!(count(&SOURCE.replace("values", "éléments")), 1);
    assert_eq!(
        count(
            &SOURCE
                .replace("std::vector<int>& values", "vector<int>& values")
                .replace("void collect", "using std::vector;void collect")
        ),
        1
    );
    assert_eq!(
        count(&SOURCE.replace("std::vector<int>& values", "vector<int>& values")),
        0
    );
    assert_eq!(
        count(&SOURCE.replace("std::vector<int>& values", "::vector<int>& values")),
        0
    );
    let guarded = SOURCE.replace(
        "values.resize(n);",
        "if(!values.empty()){continue;}values.resize(n);",
    );
    let result = scan(&guarded);
    let fact = result
        .evidence
        .iter()
        .find(|e| e.capability == Capability::ContainerBorrowLifetime)
        .unwrap();
    assert!(
        fact.captures["operation_definition"]
            .text
            .contains("if(!values.empty())")
    );
    assert_eq!(
        count(&SOURCE.replace("std::vector<int>& values", "::std::vector<int>& values")),
        1
    );
    assert_eq!(
        count(
            &SOURCE
                .replace("std::vector<int>& values", "runtime::vector<int>& values")
                .replace("void collect", "namespace runtime=std;void collect")
        ),
        1
    );
}

#[test]
fn conditional_publication_alternatives_do_not_become_joint_requirements() {
    let source=SOURCE.replace("values.resize(n);\n   pointers.insert({i,&values[0]});",
        "#ifdef FIRST\nvalues.resize(n);pointers.insert({i,&values[0]});\n#else\nvalues.reserve(n);pointers.insert({i,&values[0]});\n#endif");
    let result = scan(&source);
    let fact = result
        .evidence
        .iter()
        .find(|e| e.capability == Capability::ContainerBorrowLifetime)
        .unwrap();
    assert!(
        fact.context
            .availability
            .as_ref()
            .unwrap()
            .condition
            .as_ref()
            .unwrap()
            .contains(" || ")
    );
    assert!(fact.captures.contains_key("outward_call_1"));
}

#[test]
fn a_valid_foreign_vector_and_nested_namespace_alias_supply_no_standard_effect() {
    let source = r#"
namespace custom {
 template<class T>struct vector {void resize(int);T& operator[](int);};
 struct Grid {vector<int>& operator[](int);};
}
namespace consumer {
 namespace std=custom;
 extern custom::Grid rows;
 struct Output {void insert(int*);};extern Output out;
 void collect(int n){for(int i=0;i<n;++i){std::vector<int>& values=rows[i];values.resize(n);out.insert(&values[0]);}}
}
"#;
    assert_eq!(count(source), 0);
}

#[test]
fn foreign_types_macros_other_objects_and_noncycling_contexts_supply_no_relationship() {
    for source in [
  SOURCE.replace("std::vector<int>& values","Foreign& values"),
  SOURCE.replace("for(int i=0;i<n;++i)","if(n>0)").replace("{i,&values", "{key,&values"),
  SOURCE.replace("for(int i=0;i<n;++i)","for(int i=0;false;++i)"),
  SOURCE.replace("values.resize(n);","other.resize(n);"),
  SOURCE.replace("values.resize(n);","if(false){values.resize(n);}"),
  SOURCE.replace("values.resize(n);","return;values.resize(n);"),
  SOURCE.replace("values.resize(n);", "if(n>0){values.resize(n);}else{pointers.insert({i,&values[0]});}").replace("   pointers.insert({i,&values[0]});", ""),
  SOURCE.replace("#include <vector>","#include <vector>\n#define resize ignored"),
  SOURCE.replace("#include <vector>","#include <vector>\n#define vector Foreign"),
  SOURCE.replace("#include <vector>","#include <vector>\nnamespace foreign{template<class T>struct vector{};} namespace nested{namespace std=foreign;")+"}",
  SOURCE.replace("values.resize(n);","values.resize(n);{int values[1]={7};").replace("   pointers.insert({i,&values[0]});", "   pointers.insert({i,&values[0]});}"),
 ] {assert_eq!(count(&source),0,"{source}");}
}

#[test]
fn configuration_and_same_object_branch_captures_survive_together() {
    let source = SOURCE
        .replace(
            "std::vector<int>& values",
            "#ifdef ALIAS\nstd::vector<int>& values",
        )
        .replace("values=rows[key];", "values=rows[key];\n#endif")
        .replace(
            "values.resize(n);",
            "#ifdef CHANGE\nvalues.resize(n);\n#endif",
        );
    let result = scan(&source);
    let fact = result
        .evidence
        .iter()
        .find(|e| e.capability == Capability::ContainerBorrowLifetime)
        .unwrap();
    let condition = fact
        .context
        .availability
        .as_ref()
        .unwrap()
        .condition
        .as_ref()
        .unwrap();
    assert!(
        condition.contains("ALIAS") && condition.contains("CHANGE"),
        "{condition}"
    );
}

#[test]
fn cpp_cache_revision_expires_older_cpp_only() {
    for (extension, source) in [("cpp", SOURCE), ("js", "const value=1;")] {
        let root = support::temp_dir("cpp-vector-cache");
        fs::write(root.join(format!("source.{extension}")), source).unwrap();
        let mut inv = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
        mehscan_engine::investigation::validate_review_inventory(&root, &inv).unwrap();
        inv.cpp_effect_revision = None;
        assert_eq!(
            mehscan_engine::investigation::validate_review_inventory(&root, &inv).is_err(),
            extension == "cpp"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
