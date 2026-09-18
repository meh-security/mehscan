use std::collections::BTreeSet;

#[test]
fn all_canonical_client_verbs_keep_builder_context_without_final_url_flow() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-ktor-builders-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let verbs = [
        "get", "post", "put", "delete", "patch", "head", "options", "request",
    ];
    let mut source = String::from(
        "import io.ktor.client.HttpClient\nimport io.ktor.client.request.url\nimport io.ktor.server.application.ApplicationCall\n",
    );
    for verb in verbs {
        source.push_str(&format!("import io.ktor.client.request.{verb}\n"));
    }
    for verb in verbs {
        source.push_str(&format!(
            "suspend fun {verb}Builder(client: HttpClient, call: ApplicationCall) {{ val target = call.request.queryParameters[\"url\"]!!; client.{verb} {{ url(target) }} }}\n\
             suspend fun {verb}Replacement(client: HttpClient, call: ApplicationCall, replacement: String) {{ val target = call.request.queryParameters[\"url\"]!!; client.{verb}(target) {{ url(replacement) }} }}\n",
        ));
    }
    source.push_str("class Other { fun put(block: () -> Unit) { block() } }\nfun foreign(other: Other) { other.put { println(\"fixed\") } }\n");
    let file = root.join("app.kt");
    std::fs::write(&file, source).unwrap();
    let result = mehscan_engine::scan_path(&root);
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true);
    std::fs::remove_file(file).unwrap();
    std::fs::remove_dir(root).unwrap();
    let result = result.unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let sinks = result
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-ktor-client-request")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 16);
    let owners = sinks
        .iter()
        .map(|e| e.enclosing_symbol.clone().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(!owners.contains("foreign"));
    assert!(sinks.iter().all(|e| e.captures.contains_key("builder")));
    assert!(
        result.security_paths.is_empty(),
        "builder replacement forbids initial-URL native propagation"
    );
    assert_eq!(jobs.unwrap().observation_reviews.len(), 16);
}
