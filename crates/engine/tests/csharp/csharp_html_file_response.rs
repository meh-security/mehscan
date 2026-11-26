use mehscan_core::Capability;

#[test]
fn html_file_responses_distinguish_payload_mime_disposition_and_ownership() {
    let root = std::env::temp_dir().join(format!("mehscan-html-file-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let source = r#"using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
class DownloadController : ControllerBase {
    object Inline(byte[] bytes) => File(bytes, "text/html");
    object Stream(System.IO.Stream stream) => File(stream, "TEXT/HTML; charset=utf-8");
    object Named(byte[] bytes) => File(contentType: "text/html", fileContents: bytes);
    object UnknownDisposition(byte[] bytes, string name) => File(bytes, "text/html", name);
    object Binary(byte[] bytes) => File(bytes, "application/octet-stream");
    object Attachment(byte[] bytes) => File(bytes, "text/html", "download.html");
    object Minimal(byte[] bytes) => Results.File(bytes, "text/html");
    object MinimalAttachment(byte[] bytes) => TypedResults.File(bytes, "text/html", "download.html");
    object Dynamic(byte[] bytes, string type) => File(bytes, type);
    string Documentation = "File(bytes, \"text/html\")";
}
class CustomController : ControllerBase {
    object File(byte[] b, string type) => b;
    object Local(byte[] bytes) => File(bytes, "text/html");
}
class Other {
    object File(byte[] b, string type) => b;
    object Local(byte[] bytes) => File(bytes, "text/html");
}
"#;
    std::fs::write(root.join("Downloads.cs"), source).unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    let items: Vec<_> = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-aspnet-html-file-response")
        .collect();
    assert_eq!(items.len(), 5, "{items:#?}");
    assert_eq!(
        items
            .iter()
            .map(|e| e.location.start.line)
            .collect::<Vec<_>>(),
        [4, 5, 6, 7, 10]
    );
    for e in items {
        assert_eq!(e.capability, Capability::HtmlOutput);
        for capture in e.captures.values() {
            assert_eq!(
                capture.text,
                source[capture.location.start.byte_offset..capture.location.end.byte_offset]
            );
        }
        assert!(e.captures.contains_key("content_type"));
    }
    std::fs::remove_dir_all(&root).unwrap();
}
