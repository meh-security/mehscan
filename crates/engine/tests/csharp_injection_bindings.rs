use mehscan_core::{Capability, EvidenceKind};

#[test]
fn injection_bindings_preserve_aliases_qualified_types_and_shadow_controls() {
    let root =
        std::env::temp_dir().join(format!("mehscan-injection-bindings-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("Probe.cs"),
        r#"
global using System.Xml.XPath;
using System.DirectoryServices;
using DS = System.DirectoryServices;
using Searcher = System.DirectoryServices.DirectorySearcher;
using Encode = Microsoft.Security.Application.Encoder;
class DirectorySearcher { public DirectorySearcher(string value) {} }
class Probe {
    void Run(string input, XPathNavigator navigator) {
        var unrelated = new System.Collections.Generic.List<string>();
        var shadow = new DirectorySearcher(input);
        var namespaceAlias = new DS.DirectorySearcher(input);
        var typeAlias = new Searcher(Encode.LdapFilterEncode(input));
        var qualified = new System.DirectoryServices.DirectorySearcher(input);
        navigator.Select(input);
    }
}
"#,
    )
    .unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    std::fs::remove_dir_all(&root).unwrap();

    let ldap: Vec<_> = scan
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::LdapQuery)
        .collect();
    assert_eq!(ldap.len(), 3, "{ldap:#?}");
    assert!(ldap.iter().all(|item| item.kind == EvidenceKind::Sink));
    assert!(ldap.iter().all(|item| {
        item.captures["filter"].text == "input"
            || item.captures["filter"].text == "Encode.LdapFilterEncode(input)"
    }));
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|item| { item.rule_id == "csharp-antixss-filter-applied-to-ldap-filter" })
            .count(),
        1
    );
    let xpath: Vec<_> = scan
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::XpathQuery)
        .collect();
    assert_eq!(xpath.len(), 1, "{xpath:#?}");
    assert_eq!(xpath[0].captures["expression"].text, "input");
}
