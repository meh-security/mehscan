use mehscan_core::ScanResult;
use std::fs;
mod support;

fn scan(extension: &str, source: &str) -> ScanResult {
    let root = support::temp_dir("crypto-ownership");
    fs::write(root.join(format!("input.{extension}")), source).unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for fact in &result.evidence {
        for capture in fact.captures.values() {
            assert_eq!(
                &source[capture.location.start.byte_offset..capture.location.end.byte_offset],
                capture.text
            );
        }
    }
    result
}

#[test]
fn java_static_crypto_families_reject_value_receivers() {
    for (canonical, rule) in [
        (
            "java.security.MessageDigest",
            "java-message-digest-selection",
        ),
        ("javax.crypto.Cipher", "java-cipher-transformation"),
        ("javax.crypto.Mac", "java-mac-algorithm-selection"),
        (
            "java.security.Signature",
            "java-signature-algorithm-selection",
        ),
        ("javax.crypto.KeyGenerator", "java-key-generator-selection"),
        (
            "javax.crypto.SecretKeyFactory",
            "java-password-kdf-algorithm-selection",
        ),
    ] {
        let short = canonical.rsplit('.').next().unwrap();
        for body in [
            format!("Object f(Fake {short}){{return {short}.getInstance(\"SHA-1\");}}"),
            format!("Object f(){{Fake {short}=new Fake();return {short}.getInstance(\"SHA-1\");}}"),
            format!("Fake {short};Object f(){{return {short}.getInstance(\"SHA-1\");}}"),
            format!("Object f(Fake javax,Fake java){{return {canonical}.getInstance(\"SHA-1\");}}"),
            format!("Object f(){{return ({short})->{short}.getInstance(\"SHA-1\");}}"),
        ] {
            let source = format!(
                "import {canonical}; class Fake{{Fake security,crypto,{short};Object getInstance(String s){{return s;}}}} class C{{{body}}}"
            );
            let result = scan("java", &source);
            assert!(
                !result.evidence.iter().any(|e| e.rule_id == rule),
                "{source}\n{:#?}",
                result.evidence
            );
        }
    }
}

#[test]
fn java_static_crypto_keeps_compatible_scopes_and_source_order() {
    let source = r#"
import java.security.MessageDigest;
class Fake {Object getInstance(String s){return s;}}
class C {
  Object nativeCall() throws Exception {return MessageDigest.getInstance("SHA-1");}
  Object siblingBlock() throws Exception {{Fake MessageDigest=null;}return MessageDigest.getInstance("SHA-1");}
  Object laterLocal() throws Exception {Object result=MessageDigest.getInstance("SHA-1");Fake MessageDigest=null;return result;}
  Object qualified(Fake MessageDigest) throws Exception {return java.security.MessageDigest.getInstance("SHA-1");}
  Object sdkValue(MessageDigest MessageDigest) throws Exception {return MessageDigest.getInstance("SHA-1");}
  Object sdkLocal() throws Exception {MessageDigest MessageDigest=null;return MessageDigest.getInstance("SHA-1");}
  Object nestedCapture(Fake MessageDigest){return ()->MessageDigest.getInstance("SHA-1");}
  Object nestedField(){return new Object(){Fake MessageDigest;Object f(){return MessageDigest.getInstance("SHA-1");}};}
}
"#;
    let result = scan("java", source);
    let facts = result
        .evidence
        .iter()
        .filter(|e| e.rule_id == "java-message-digest-selection")
        .collect::<Vec<_>>();
    assert_eq!(facts.len(), 6, "{facts:#?}");
}

#[test]
fn java_crypto_constructor_types_do_not_borrow_an_imports_short_name() {
    for (canonical, arguments, rule) in [
        (
            "javax.crypto.spec.SecretKeySpec",
            "new byte[16],\"AES\"",
            "java-hardcoded-secret-key-material",
        ),
        (
            "javax.crypto.spec.PBEKeySpec",
            "password,salt,10,128",
            "java-password-kdf-parameters",
        ),
        (
            "javax.crypto.spec.IvParameterSpec",
            "new byte[16]",
            "java-fixed-iv-or-nonce-material",
        ),
        (
            "javax.crypto.spec.GCMParameterSpec",
            "128,new byte[12]",
            "java-fixed-iv-or-nonce-material",
        ),
    ] {
        let short = canonical.rsplit('.').next().unwrap();
        let source = format!(
            "import {canonical}; class C{{Object f(char[] password,byte[] salt){{return new foreign.{short}({arguments});}}}}"
        );
        assert!(
            !scan("java", &source)
                .evidence
                .iter()
                .any(|e| e.rule_id == rule),
            "{source}"
        );
        for ty in [short, canonical] {
            // Constructor type space remains valid with a same-named value.
            let source = format!(
                "import {canonical}; class C{{Object f(char[] password,byte[] salt,Object {short}){{return new {ty}({arguments});}}}}"
            );
            assert!(
                scan("java", &source)
                    .evidence
                    .iter()
                    .any(|e| e.rule_id == rule),
                "{source}"
            );
        }
    }
}

const GO_PREFIX: &str = "package app\nimport(\"crypto/md5\";\"encoding/hex\";\"net/http\")\n";
const GO_HELPER: &str = "func Md5Sum(value string)string{digest:=md5.New();digest.Write([]byte(value));return hex.EncodeToString(digest.Sum(nil))}\n";

#[test]
fn go_digest_helpers_require_owned_input_hash_and_return() {
    let caller = "func Login(r *http.Request)string{return Md5Sum(r.FormValue(\"password\"))}\n";
    for helper in [
        GO_HELPER.to_string(),
        GO_HELPER.replace("Md5Sum", "EncodeCredential"),
    ] {
        let name = if helper.contains("EncodeCredential") {
            "EncodeCredential"
        } else {
            "Md5Sum"
        };
        let source = format!("{GO_PREFIX}{helper}{}", caller.replace("Md5Sum", name));
        let result = scan("go", &source);
        let fact = result
            .evidence
            .iter()
            .find(|e| e.rule_id == "go-md5-password-hash")
            .expect("owned digest path survives renaming");
        assert!(
            fact.captures["helper_definition"]
                .text
                .contains(&format!("func {name}("))
        );
        assert!(
            result
                .security_paths
                .iter()
                .any(|p| p.cwe_candidates == ["CWE-916"])
        );
    }
    for helper in [
        "func Md5Sum(value string)string{return value}\n".to_string(),
        GO_HELPER.replace("[]byte(value)", "[]byte(\"constant\")"),
        GO_HELPER.replace("return hex.EncodeToString(digest.Sum(nil))", "return value"),
        GO_HELPER.replace("digest.Write", "digest.Reset();digest.Write"),
    ] {
        let source = format!("{GO_PREFIX}{helper}{caller}");
        assert!(
            !scan("go", &source)
                .evidence
                .iter()
                .any(|e| e.rule_id == "go-md5-password-hash"),
            "{source}"
        );
    }
}

#[test]
fn go_digest_helpers_keep_aliases_and_reject_shadowed_or_unrelated_calls() {
    let prefix = GO_PREFIX
        .replace("\"crypto/md5\"", "hash \"crypto/md5\"")
        .replace("\"encoding/hex\"", "encoding \"encoding/hex\"");
    let helper = GO_HELPER
        .replace("md5.New", "hash.New")
        .replace("hex.EncodeToString", "encoding.EncodeToString");
    let source = format!(
        "{prefix}{helper}func Login(r *http.Request)string{{return Md5Sum(r.FormValue(\"password\"))}}\n"
    );
    assert!(
        scan("go", &source)
            .evidence
            .iter()
            .any(|e| e.rule_id == "go-md5-password-hash")
    );
    for caller in [
        "func Login(r *http.Request,Md5Sum func(string)string)string{return Md5Sum(r.FormValue(\"password\"))}\n",
        "func Login(r *http.Request)string{Md5Sum:=func(v string)string{return v};return Md5Sum(r.FormValue(\"password\"))}\n",
        "type Other struct{}\nfunc(o Other)Md5Sum(v string)string{return v}\nfunc Login(r *http.Request,o Other)string{return o.Md5Sum(r.FormValue(\"password\"))}\n",
    ] {
        let source = format!("{GO_PREFIX}{GO_HELPER}{caller}");
        assert!(
            !scan("go", &source)
                .evidence
                .iter()
                .any(|e| e.rule_id == "go-md5-password-hash"),
            "{source}"
        );
    }
    let source = format!(
        "{}{GO_HELPER}func Login(r *http.Request)string{{return Md5Sum(r.FormValue(\"password\"))}}\n",
        GO_PREFIX.replace("crypto/md5", "example/digest")
    );
    assert!(
        !scan("go", &source)
            .evidence
            .iter()
            .any(|e| e.rule_id == "go-md5-password-hash")
    );
}
