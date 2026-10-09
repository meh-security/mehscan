use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::build_review_inventory;
#[test]
fn anonymous_effects_are_local_and_noop_routes_are_context() {
    let root = std::env::temp_dir().join(format!("mehscan-route-context-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("App.cs"),r#"using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
class App:ControllerBase {
[HttpPost][AllowAnonymous]public object Noop(){return Ok();}
[HttpDelete][AllowAnonymous]public object Remove(){File.Delete("private.db");return Ok();}
[HttpPost][IgnoreAntiforgeryToken]public object Clear(){File.WriteAllText("private.db","");return Ok();}
void Setup(WebApplication app){app.MapDelete("/noop",()=>"ok").AllowAnonymous();app.MapDelete("/remove",()=>File.Delete("private.db")).AllowAnonymous();}
}"#).unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    let markers = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| {
            matches!(
                e.rule_id.as_str(),
                "csharp-anonymous-state-change-review"
                    | "csharp-minimal-anonymous-state-change-review"
                    | "csharp-antiforgery-exemption-review"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(markers.len(), 5, "{markers:#?}");
    assert_eq!(
        markers
            .iter()
            .filter(|e| e.kind == EvidenceKind::Resource)
            .count(),
        2,
        "{markers:#?}"
    );
    assert_eq!(
        markers
            .iter()
            .filter(|e| e.captures.contains_key("effect") && !e.related_evidence.is_empty())
            .count(),
        3,
        "{markers:#?}"
    );
    for method in ["Remove", "Clear"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(method)
                    && e.capability == Capability::Authorization),
            "lost auth effect {method}: {:#?}",
            inventory.entries
        );
    }
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("Noop"))
    );
    std::fs::remove_dir_all(root).unwrap();
}
