use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

const RULE: &str = "go-reversible-cookie-identity-review";
const ISSUER: &str = r#"package ticket
import (codec "encoding/base64"; web "net/http")
func issue(w web.ResponseWriter, r *web.Request) {
 subject := r.FormValue("record")
 text := codec.RawURLEncoding.EncodeToString([]byte(subject))
 outbound := &web.Cookie{Name:"selection", Value:text}
 web.SetCookie(w, outbound)
}
"#;
const READER: &str = r#"package ticket
import (codec "encoding/base64"; web "net/http"; store "database/sql")
func lookup(r *web.Request) (int, error) {
 cookie, err := r.Cookie("selection")
 if err != nil { return 0, err }
 raw, err := codec.RawURLEncoding.DecodeString(cookie.Value)
 if err != nil { return 0, err }
 subject := string(raw)
 db, err := store.Open("driver", "configured")
 if err != nil { return 0, err }
 var record int
 err = db.QueryRow("SELECT id FROM records WHERE subject = ?", subject).Scan(&record)
 return record, err
}
"#;

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-cookie-identity-{label}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for (name, source) in files {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn alias_bound_issuance_and_decoded_row_lookup_keep_exact_cross_file_evidence() {
    let fixture = Fixture::new("linked", &[("issue.go", ISSUER), ("read.go", READER)]);
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    let evidence = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == RULE)
        .collect::<Vec<_>>();
    assert_eq!(evidence.len(), 1);
    let item = evidence[0];
    assert_eq!(item.kind, EvidenceKind::SensitiveOperation);
    assert_eq!(item.capability, Capability::Authentication);
    assert_eq!(item.captures["cookie_name"].text, "\"selection\"");
    for role in [
        "issuer_input_0",
        "issuer_encoding_0",
        "issuer_cookie_0",
        "issuer_delivery_0",
        "credential_decode",
        "record_lookup",
        "lookup_result",
    ] {
        let c = &item.captures[role];
        let source = fs::read_to_string(fixture.0.join(&c.location.path)).unwrap();
        assert_eq!(
            &source[c.location.start.byte_offset..c.location.end.byte_offset],
            c.text
        );
    }
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|e| e.rule_id == RULE)
            .count(),
        1
    );
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.rule_id == "go-database-query"),
        "SQL evidence remains a separate property"
    );
}

#[test]
fn unused_random_wrapped_mutated_and_mismatched_values_are_not_direct_issuers() {
    let random = ISSUER
        .replace("web \"net/http\"", "web \"net/http\"; \"crypto/rand\"")
        .replace(
            "subject := r.FormValue(\"record\")",
            "nonce := make([]byte,32); if _,err := rand.Read(nonce); err != nil { return }",
        )
        .replace("[]byte(subject)", "nonce");
    let variants = [
        ISSUER.replace("web.SetCookie(w, outbound)", "_ = outbound"),
        random,
        ISSUER.replace("Value:text", "Value:sign(text)"),
        ISSUER.replace(
            "web.SetCookie(w, outbound)",
            "outbound.Value = sign(text); web.SetCookie(w, outbound)",
        ),
        ISSUER.replace(
            "web.SetCookie(w, outbound)",
            "rewrite(outbound); web.SetCookie(w, outbound)",
        ),
        ISSUER.replace("Name:\"selection\"", "Name:\"preference\""),
        ISSUER.replace("RawURLEncoding", "StdEncoding"),
        ISSUER.replace("text := codec", "subject = opaque(); text := codec"),
        ISSUER.replace("text := codec", "codec := localCodec(); text := codec"),
    ];
    for (index, issuer) in variants.iter().enumerate() {
        let fixture = Fixture::new(
            &format!("closed-{index}"),
            &[("issue.go", issuer), ("read.go", READER)],
        );
        let inventory = build_review_inventory(&fixture.0, false).unwrap();
        assert!(
            !inventory.entries.iter().any(|e| e.rule_id == RULE),
            "unsupported issuer variant {index} admitted"
        );
    }
}

#[test]
fn cookie_names_do_not_join_unassociated_packages_or_shadowed_readers() {
    let fixture = Fixture::new(
        "packages",
        &[("one/issue.go", ISSUER), ("two/read.go", READER)],
    );
    assert!(
        !build_review_inventory(&fixture.0, false)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.rule_id == RULE)
    );
    let imported = ISSUER.replace(
        "web \"net/http\"",
        "web \"net/http\"; _ \"example.invalid/two\"",
    );
    let linked = Fixture::new(
        "imported",
        &[("one/issue.go", &imported), ("two/read.go", READER)],
    );
    // Blank imports do not establish an API binding to the consumer package.
    assert!(
        !build_review_inventory(&linked.0, false)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.rule_id == RULE)
    );
    let associated_issuer = ISSUER
        .replace("package ticket", "package one")
        .replace(
            "web \"net/http\"",
            "web \"net/http\"; lookup \"example.invalid/two\"",
        )
        .replace("subject :=", "_, _ = lookup.Lookup(r); subject :=");
    let associated_reader = READER
        .replace("package ticket", "package two")
        .replace("func lookup", "func Lookup");
    let associated = Fixture::new(
        "associated",
        &[
            ("one/issue.go", &associated_issuer),
            ("two/read.go", &associated_reader),
        ],
    );
    assert_eq!(
        build_review_inventory(&associated.0, false)
            .unwrap()
            .entries
            .iter()
            .filter(|e| e.rule_id == RULE)
            .count(),
        1
    );
    for (label, reader) in [
        (
            "shadow",
            READER.replace(
                "raw, err := codec",
                "codec := localCodec(); raw, err := codec",
            ),
        ),
        (
            "rewrite",
            READER.replace(
                "raw, err := codec",
                "cookie.Value = replacement; raw, err := codec",
            ),
        ),
        ("no-scan", READER.replace(".Scan(&record)", "")),
    ] {
        let f = Fixture::new(label, &[("issue.go", ISSUER), ("read.go", &reader)]);
        assert!(
            !build_review_inventory(&f.0, false)
                .unwrap()
                .entries
                .iter()
                .any(|e| e.rule_id == RULE),
            "{label}"
        );
    }
}

#[test]
fn independent_proof_and_unknown_policy_remain_review_obligations() {
    for (label, guard) in [
        ("guarded", "if !verifyIndependentProof(r) { return 0, nil }"),
        ("unknown", "if !policy.Allows(r) { return 0, nil }"),
    ] {
        let reader = READER.replace("var record int", &format!("{guard}\n var record int"));
        let f = Fixture::new(label, &[("issue.go", ISSUER), ("read.go", &reader)]);
        assert_eq!(
            build_review_inventory(&f.0, false)
                .unwrap()
                .entries
                .iter()
                .filter(|e| e.rule_id == RULE)
                .count(),
            1
        );
    }
}
