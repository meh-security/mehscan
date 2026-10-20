use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn url_suffixes_do_not_close_unknown_destinations_in_other_languages() {
    let root =
        std::env::temp_dir().join(format!("mehscan-prefix-admission-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        ("suffix", "value + \"/login\"", true),
        ("leading", "\"/login/\" + value", false),
        ("scheme", "\"javascript:run(\" + value + \")\"", true),
        ("slash", "\"/\" + value", true),
        ("authority", "\"https://fixed.test\" + value", true),
        ("httpSuffix", "value + \"https://fixed.test/path\"", true),
        ("httpLeading", "\"https://fixed.test/path/\" + value", false),
        ("opaque", "transform(\"/login/\" + value)", true),
        ("parenthesized", "(\"/login/\" + value)", false),
        ("nestedSuffix", "(value + \"/login/\") + \"/more\"", true),
        ("escaped", "\"/\\\\\" + value", true),
    ];
    for (name, expr, _) in cases {
        for (ext, source) in [
            (
                "cs",
                format!("class App {{ void Run(string value) {{ Response.Redirect({expr}); }} }}"),
            ),
            (
                "java",
                format!(
                    "class App {{ void run(String value) {{ response.sendRedirect({expr}); }} }}"
                ),
            ),
            (
                "py",
                format!(
                    "from flask import redirect\ndef run(value):\n    return redirect({expr})\n"
                ),
            ),
        ] {
            fs::write(root.join(format!("{name}.{ext}")), source).unwrap();
        }
    }
    for (name, expr, _) in cases {
        if !matches!(name, "httpSuffix" | "httpLeading" | "authority") {
            continue;
        }
        for (ext, source) in [
            (
                "cs",
                format!(
                    "using System.Net.Http; class App {{ void Run(string value, HttpClient client) {{ client.GetAsync({expr}); }} }}"
                ),
            ),
            (
                "java",
                format!(
                    "import org.springframework.web.client.RestTemplate; class App {{ void run(String value, RestTemplate client) {{ client.getForObject({expr}, String.class); }} }}"
                ),
            ),
            (
                "py",
                format!("import requests\ndef run(value):\n    requests.get({expr})\n"),
            ),
        ] {
            fs::write(root.join(format!("outbound-{name}.{ext}")), source).unwrap();
        }
    }
    for (path, source) in [
        (
            "proxy.java",
            "import java.net.URL; import java.net.Proxy; class App { void run(String value, Proxy proxy) throws Exception { new URL(\"https://fixed.test/path/\" + value).openConnection(proxy).getInputStream(); } }",
        ),
        (
            "interpolation.cs",
            "class App { void Run(string value) { Response.Redirect($\"{value}/login\"); } }",
        ),
        (
            "interpolation.py",
            "from flask import redirect\ndef run(value):\n    return redirect(f\"{value}/login\")\n",
        ),
        (
            "source.cs",
            "using System.Net.Http; class App { void Run(dynamic Request, HttpClient client) { client.GetAsync(\"https://fixed.test/path/\" + Request.Query[\"id\"]); } }",
        ),
        (
            "source.java",
            "import org.springframework.web.client.RestTemplate; class App { void run(HttpServletRequest request, RestTemplate client) { client.getForObject(\"https://fixed.test/path/\" + request.getParameter(\"id\"), String.class); } }",
        ),
        (
            "source.py",
            "import requests\nfrom flask import request\ndef run():\n    requests.get(\"https://fixed.test/path/\" + request.args[\"id\"])\n",
        ),
    ] {
        fs::write(root.join(path), source).unwrap();
    }
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for (name, _, admitted) in cases {
        for ext in ["cs", "java", "py"] {
            let path = format!("{name}.{ext}");
            assert!(
                inventory
                    .scan
                    .evidence
                    .iter()
                    .any(|e| e.location.path == path && e.capability == Capability::Redirect),
                "missing sink {path}"
            );
            assert_eq!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.path == path && e.capability == Capability::Redirect),
                admitted,
                "wrong admission for {path}"
            );
        }
    }
    for ext in ["cs", "java", "py"] {
        for (name, admitted) in [
            ("httpSuffix", true),
            ("httpLeading", false),
            ("authority", true),
        ] {
            let path = format!("outbound-{name}.{ext}");
            assert!(
                inventory
                    .scan
                    .evidence
                    .iter()
                    .any(|e| e.location.path == path
                        && e.capability == Capability::OutboundNetworkRequest),
                "missing HTTP sink {path}"
            );
            assert_eq!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.path == path && e.capability == Capability::OutboundNetworkRequest),
                admitted,
                "wrong HTTP admission {path}: {:#?}",
                inventory
                    .scan
                    .evidence
                    .iter()
                    .filter(|e| e.location.path == path)
                    .collect::<Vec<_>>()
            );
        }
        let path = format!("source.{ext}");
        let sink = inventory
            .scan
            .evidence
            .iter()
            .find(|e| e.location.path == path && e.capability == Capability::OutboundNetworkRequest)
            .unwrap();
        assert!(
            inventory
                .scan
                .security_paths
                .iter()
                .any(|p| p.sink_evidence_id == sink.id),
            "lost source-supported path {path}"
        );
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.path == path && e.capability == Capability::OutboundNetworkRequest),
            "lost source-supported review {path}"
        );
    }
    for path in ["interpolation.cs", "interpolation.py"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.path == path && e.capability == Capability::Redirect),
            "unknown interpolation prefix closed: {path}"
        );
    }
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.path == "proxy.java" && e.capability == Capability::OutboundNetworkRequest),
        "fixed endpoint must not close unknown proxy policy"
    );
    fs::remove_dir_all(root).unwrap();
}
