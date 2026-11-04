mod support;
use mehscan_core::Capability;
use std::fs;

const SOURCE: &str = r#"
#include <vector>
#include <stdexcept>
struct Item{int data;};
bool reject(int);
void collect(int count){
 std::vector<Item*> pending;
 for(int i=0;i<count;++i){
  if(reject(i)){
   CLEANUP
   throw std::runtime_error("bad");
  }
  pending.push_back(new Item{42});
 }
 for(auto *p:pending) delete p;
}
"#;
fn scan(source: &str) -> mehscan_core::ScanResult {
    let root = support::temp_dir("cpp-exception-cleanup");
    fs::write(root.join("source.cpp"), source).unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for fact in result
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::ExceptionalOwnershipCleanup)
    {
        assert_eq!(fact.rule_id, "cpp-pending-collection-exception-review");
        for c in fact.captures.values() {
            assert_eq!(
                &source[c.location.start.byte_offset..c.location.end.byte_offset],
                c.text
            );
        }
    }
    result
}
fn count(source: &str) -> usize {
    scan(source)
        .evidence
        .iter()
        .filter(|e| e.capability == Capability::ExceptionalOwnershipCleanup)
        .count()
}
#[test]
fn raw_collection_throw_and_fresh_allocation_remain_a_bounded_review_question() {
    let source = SOURCE.replace("CLEANUP", "");
    assert_eq!(count(&source), 1);
    assert_eq!(count(&source.replace("pending", "éléments")), 1);
    assert_eq!(
        count(&source.replace("std::vector<Item*>", "::std::vector<Item*>")),
        1
    );
    assert_eq!(
        count(
            &source
                .replace("std::vector<Item*>", "store::vector<Item*>")
                .replace("void collect", "namespace store=std;void collect")
        ),
        1
    );
    let result = scan(&source);
    let fact = result
        .evidence
        .iter()
        .find(|e| e.capability == Capability::ExceptionalOwnershipCleanup)
        .unwrap();
    assert!(
        fact.captures["operation_definition"]
            .text
            .contains("for(auto *p:pending) delete p")
    );
    assert_eq!(fact.captures["allocation_0"].text, "new Item{42}");
}
#[test]
fn cleanup_proof_and_opaque_cleanup_are_reviewed_in_the_complete_operation() {
    for cleanup in [
        "for(auto *p:pending)delete p;pending.clear();",
        "cleanup(pending);",
    ] {
        let source = SOURCE.replace("CLEANUP", cleanup);
        let result = scan(&source);
        let fact = result
            .evidence
            .iter()
            .find(|e| e.capability == Capability::ExceptionalOwnershipCleanup)
            .unwrap();
        assert!(fact.captures["operation_definition"].text.contains(cleanup));
    }
}
#[test]
fn wrong_object_foreign_types_macros_unreachable_and_fresh_collections_do_not_establish_pending_ownership()
 {
    let source = SOURCE.replace("CLEANUP", "");
    for variant in [
        source.replace("std::vector<Item*>", "Foreign"),
        source.replace("std::vector<Item*>", "vector<Item*>"),
        source.replace("std::vector<Item*>", "std::vector<std::unique_ptr<Item>>"),
        source.replace(" std::vector<Item*> pending;", "").replace(
            "  if(reject(i))",
            "  std::vector<Item*> pending;\n  if(reject(i))",
        ),
        source.replace(
            "pending.push_back(new Item{42});",
            "other.push_back(new Item{42});",
        ),
        source.replace(
            "pending.push_back(new Item{42});",
            "if(false){pending.push_back(new Item{42});}",
        ),
        source.replace(
            "pending.push_back(new Item{42});",
            "return;pending.push_back(new Item{42});",
        ),
        source.replace("i<count", "false"),
        source.replace("if(reject(i))", "if(true)"),
        source.replace(
            "  pending.push_back",
            "  throw std::runtime_error(\"always\");pending.push_back",
        ),
        source.replace("if(reject(i))", "if(false)"),
        source.replace("new Item{42}", "new(place) Item{42}"),
        source.replace(
            "#include <vector>",
            "#include <vector>\n#define push_back append",
        ),
        source.replace(
            "#include <vector>",
            "#include <vector>\n#define new alternative",
        ),
        source
            .replace(
                "  pending.push_back",
                "  {Foreign pending;pending.push_back",
            )
            .replace("new Item{42});", "new Item{42});}"),
        source.replace(
            "pending.push_back(new Item{42});",
            "auto f=[&](){pending.push_back(new Item{42});};",
        ),
    ] {
        assert_eq!(count(&variant), 0, "{variant}");
    }
}
#[test]
fn a_different_loop_and_value_only_containers_do_not_supply_this_relationship() {
    let source = SOURCE.replace("CLEANUP", "");
    assert_eq!(count(&source.replace("pending.push_back(new Item{42});", "").replace(" for(auto *p:pending)"," for(int j=0;j<count;++j){pending.push_back(new Item{42});}\n for(auto *p:pending)")),0);
    assert_eq!(
        count(
            &source
                .replace("std::vector<Item*>", "std::vector<Item>")
                .replace("new Item{42}", "Item{42}")
        ),
        0
    );
}
#[test]
fn alternative_allocations_keep_disjunctive_availability_and_both_anchors() {
    let source=SOURCE.replace("CLEANUP","").replace("  pending.push_back(new Item{42});","#ifdef FIRST\npending.push_back(new Item{42});\n#else\npending.emplace_back(new Item{17});\n#endif");
    let result = scan(&source);
    let fact = result
        .evidence
        .iter()
        .find(|e| e.capability == Capability::ExceptionalOwnershipCleanup)
        .unwrap();
    assert!(fact.captures.contains_key("allocation_1"));
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
}
