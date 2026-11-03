mod support;
use mehscan_core::{EvidenceKind, ScanResult};
use std::fs;

fn scan(source: &str) -> ScanResult {
    let root = support::temp_dir("csharp-hash");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("input.cs"), source).unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    result
}

#[test]
fn hash_inventory_records_real_api_operations_without_inventing_password_purpose() {
    let source = r#"
using System.Security.Cryptography;
using Digest = System.Security.Cryptography.SHA256;
class PasswordResetTools {
    byte[] FileChecksum(byte[] contents) { using var hash=MD5.Create(); return hash.ComputeHash(contents); }
    byte[] HashPassword(byte[] password) { return SHA256.HashData(password); }
    byte[] Direct(byte[] data) { return SHA1.HashData(data); }
    byte[] Alias(byte[] data) { return Digest.HashData(data); }
    object Provider() { return new SHA1Managed(); }
    object Dynamic(string algorithm) { return HashAlgorithm.Create(algorithm); }
    object Qualified() { return global::System.Security.Cryptography.MD5.Create(); }
    object ConstructorWithValueName(object SHA1Managed) { return new SHA1Managed(); }
}
"#;
    let result = scan(source);
    let hashes = result
        .evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-hash-algorithm-selection")
        .collect::<Vec<_>>();
    assert_eq!(hashes.len(), 8, "{hashes:#?}");
    for item in &hashes {
        assert_eq!(item.kind, EvidenceKind::SecurityConfiguration);
        assert!(item.symbol_resolution.is_some());
        assert!(
            item.tags
                .iter()
                .all(|tag| !tag.starts_with("recommendation:")
                    && !tag.contains("password")
                    && !tag.contains("reset"))
        );
        for capture in item.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
    assert!(
        hashes
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("FileChecksum"))
    );
    assert!(
        hashes
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("HashPassword"))
    );
    assert!(result.evidence.iter().all(|e| !matches!(
        e.rule_id.as_str(),
        "csharp-password-fast-hash" | "csharp-predictable-password-reset-hash"
    )));
}

#[test]
fn foreign_hash_lookalikes_and_shadowed_api_names_do_not_borrow_crypto_identity() {
    for source in [
        "class SHA1 {public static object Create()=>null;} class C{object F(){return SHA1.Create();}}",
        "using System.Security.Cryptography; class Fake{public object Create()=>null;} class C{object F(Fake SHA1){return SHA1.Create();}}",
        "using System.Security.Cryptography; class Fake{public object Create()=>null;} class C{object F(){var SHA1=new Fake();return SHA1.Create();}}",
        "using Digest=System.Security.Cryptography.SHA256; class Fake{public byte[] HashData(byte[] b)=>b;} class C{byte[] F(Fake Digest,byte[] b){return Digest.HashData(b);}}",
    ] {
        let result = scan(source);
        assert!(
            !result
                .evidence
                .iter()
                .any(|e| e.rule_id == "csharp-hash-algorithm-selection"),
            "{source}\n{:#?}",
            result.evidence
        );
    }
}
