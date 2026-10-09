use mehscan_core::EvidenceKind;
use mehscan_engine::investigation::build_review_inventory;
use std::fs;
#[test]
fn only_unused_publisher_setup_leaves_the_queue() {
    let root =
        std::env::temp_dir().join(format!("mehscan-reactive-cleanup-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("App.kt"),r#"import org.springframework.web.reactive.function.client.WebClient
class App(private val client:WebClient) {
fun unused(url:String) {val never=client.get().uri(url).retrieve().bodyToMono(String::class.java)}
fun returned(url:String)=client.get().uri(url).retrieve().bodyToMono(String::class.java)
fun consumed(url:String)=client.get().uri(url).retrieve().bodyToMono(String::class.java).block()
fun handoff(url:String) {val pub=client.get().uri(url).retrieve().bodyToMono(String::class.java); pass(pub)}
fun reused(url:String) {val spec=client.get();spec.uri(url);spec.retrieve().bodyToMono(String::class.java).block()}
}"#).unwrap();
    fs::write(root.join("App.java"),r#"import org.springframework.web.reactive.function.client.WebClient;
class App {WebClient client;
void unused(String url){var never=client.get().uri(url).retrieve().bodyToMono(String.class);}
void discarded(String url){client.get().uri(url).retrieve().bodyToMono(String.class);}
Object returned(String url){return client.get().uri(url).retrieve().bodyToMono(String.class);}
Object consumed(String url){return client.get().uri(url).retrieve().bodyToMono(String.class).block();}
void handoff(String url){var pub=client.get().uri(url).retrieve().bodyToMono(String.class);pass(pub);}
}"#).unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let observations = scan
        .evidence
        .iter()
        .filter(|e| {
            matches!(
                e.rule_id.as_str(),
                "kotlin-webclient-uri" | "java-spring-webclient-outbound-request"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(observations.len(), 10, "{observations:#?}");
    assert_eq!(
        observations
            .iter()
            .filter(|e| e.kind == EvidenceKind::Resource)
            .count(),
        3,
        "{observations:#?}"
    );
    assert_eq!(
        observations
            .iter()
            .filter(|e| e.captures.contains_key("consumer"))
            .count(),
        2,
        "{observations:#?}"
    );
    let inventory = build_review_inventory(&root, false).unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| matches!(e.symbol.as_deref(), Some("unused" | "discarded"))),
        "{:#?}",
        inventory.entries
    );
    for method in ["returned", "consumed", "handoff", "reused"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(method)),
            "missing {method}: {:#?}",
            inventory.entries
        );
    }
    fs::remove_dir_all(root).unwrap();
}
