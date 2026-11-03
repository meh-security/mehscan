mod support;
use mehscan_core::Capability;
use std::fs;

const SOURCE: &str = r#"
#include <vector>
#include <string>
#include <string_view>
void collect(int n) {
 std::vector<std::string> values;
 std::vector<std::string_view> saved;
 for(int i=0;i<n;++i){
  values.push_back("short");
  saved.push_back(values.back());
 }
 for(auto text:saved) consume(text);
}
"#;
fn scan(source: &str) -> mehscan_core::ScanResult {
    let root = support::temp_dir("cpp-vector-publication");
    fs::write(root.join("source.cpp"), source).unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for fact in scan
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::ContainerBorrowLifetime)
    {
        assert_eq!(fact.rule_id, "cpp-vector-element-publication-review");
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
fn explicit_vector_reference_publication_keeps_storage_and_full_operation() {
    let result = scan(SOURCE);
    let fact = result
        .evidence
        .iter()
        .find(|e| e.capability == Capability::ContainerBorrowLifetime)
        .unwrap();
    assert_eq!(
        fact.captures["outward_storage_0"].text,
        "std::vector<std::string_view> saved;"
    );
    assert!(
        fact.captures["operation_definition"]
            .text
            .contains("consume(text)")
    );
    assert_eq!(count(&SOURCE.replace("values", "éléments")), 1);
    assert_eq!(count(&SOURCE.replace("values.back()", "values.front()")), 1);
    assert_eq!(
        count(&SOURCE.replace(
            "std::vector<std::string> values;",
            "::std::vector<std::string> values;"
        )),
        1
    );
}
#[test]
fn owning_copy_capacity_and_unknown_storage_remain_questions_not_automatic_bugs() {
    for source in [
        SOURCE.replace(
            "std::vector<std::string_view> saved",
            "std::vector<std::string> saved",
        ),
        SOURCE.replace("std::vector<std::string_view> saved", "OpaqueLedger saved"),
        SOURCE.replace(" for(int i", " values.reserve(n);\n for(int i"),
        SOURCE.replace(
            "  values.push_back",
            "  if(i==0) return;\n  values.push_back",
        ),
    ] {
        assert_eq!(count(&source), 1, "{source}");
    }
}
#[test]
fn foreign_shadowed_macro_fresh_and_unreachable_objects_do_not_supply_the_relationship() {
    for source in [
        SOURCE.replace("std::vector<std::string> values", "Foreign values"),
        SOURCE.replace(
            "std::vector<std::string> values",
            "vector<std::string> values",
        ),
        SOURCE
            .replace(" std::vector<std::string> values;", "")
            .replace(
                "  values.push_back",
                "  std::vector<std::string> values;values.push_back",
            ),
        SOURCE.replace(
            "values.push_back(\"short\");",
            "other.push_back(\"short\");",
        ),
        SOURCE.replace(
            "values.push_back(\"short\");",
            "if(false){values.push_back(\"short\");}",
        ),
        SOURCE.replace(
            "values.push_back(\"short\");",
            "return;values.push_back(\"short\");",
        ),
        SOURCE.replace("i<n", "false"),
        SOURCE.replace(
            "#include <vector>",
            "#include <vector>\n#define back replacement",
        ),
        SOURCE
            .replace("  saved.push_back", "  { Foreign values; saved.push_back")
            .replace("values.back());", "values.back());}"),
        SOURCE.replace("for(int i=0;i<n;++i)", "for(auto &values:others)"),
        SOURCE
            .replace(
                "values.push_back(\"short\");",
                "if(n){values.push_back(\"short\");}else{",
            )
            .replace("values.back());", "values.back());}"),
    ] {
        assert_eq!(count(&source), 0, "{source}");
    }
}
#[test]
fn fixed_publication_and_separate_lambdas_do_not_supply_the_selected_reference() {
    assert_eq!(
        count(&SOURCE.replace("values.back()", "std::string(\"copy\")")),
        0
    );
    assert_eq!(
        count(
            &SOURCE
                .replace("  saved.push_back", "  auto callback=[&](){saved.push_back")
                .replace("values.back());", "values.back());};")
        ),
        0
    );
}
#[test]
fn separate_loops_keep_distinct_anchors_and_conditions_survive() {
    let repeated=SOURCE.replace(" for(auto text:saved)", " for(int j=0;j<n;++j){values.emplace_back(\"next\");saved.push_back(values.front());}\n for(auto text:saved)");
    assert_eq!(count(&repeated), 2);
    let conditional = SOURCE
        .replace("  values.push_back", "#ifdef GROW\n  values.push_back")
        .replace("  saved.push_back", "#endif\n  saved.push_back");
    let result = scan(&conditional);
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
            .contains("GROW")
    );
}
