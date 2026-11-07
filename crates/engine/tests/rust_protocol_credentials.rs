mod support;
use std::fs;
fn assess(source: &str) -> Vec<(String, String)> {
    let root = support::temp_dir("protocol-credential-obligations");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"protocol_credentials\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, false).unwrap();
    let mut out = Vec::new();
    for r in &jobs.observation_reviews {
        for e in r.evidence.iter().filter(|e| {
            e.tags
                .iter()
                .any(|t| t == "rust-protocol-credential-obligation")
        }) {
            assert!(
                r.review_basis
                    .as_ref()
                    .unwrap()
                    .relationship
                    .starts_with("bounded_rust_")
            );
            for c in e.captures.values() {
                assert_eq!(
                    &source.as_bytes()[c.location.start.byte_offset..c.location.end.byte_offset],
                    c.text.as_bytes()
                );
            }
            out.push((e.enclosing_symbol.clone().unwrap(), e.rule_id.clone()));
        }
    }
    fs::remove_dir_all(root).unwrap();
    out.sort();
    out
}
#[test]
fn conflicting_framing_reads_and_raw_forwarding_preserve_strict_control() {
    let source = r#"
use std::io::Write;
pub fn forward(headers:&http::HeaderMap,out:&mut std::net::TcpStream,wire:&[u8]){let length=headers.get("content-length");let transfer=headers.get("transfer-encoding");out.write_all(wire);}
pub fn strict(headers:&http::HeaderMap,out:&mut std::net::TcpStream,wire:&[u8]){let length=headers.get("content-length");let transfer=headers.get("transfer-encoding");if length.is_some()&&transfer.is_some(){return;}out.write_all(wire);}
pub fn single(headers:&http::HeaderMap,out:&mut std::net::TcpStream,wire:&[u8]){headers.get("content-length");out.write_all(wire);}
pub fn unrelated(headers:&Other,out:&mut std::net::TcpStream,wire:&[u8]){headers.get("content-length");headers.get("transfer-encoding");out.write_all(wire);}
struct Other;impl Other{fn get(&self,_:&str)->Option<&str>{None}}
"#;
    assert_eq!(
        assess(source),
        [
            ("forward".into(), "rust-http-framing-forward-review".into()),
            ("strict".into(), "rust-http-framing-forward-review".into())
        ]
    );
}
#[test]
fn default_credentials_keep_redirect_policy_and_custom_macros_do_not_leak_tokens() {
    let source = r#"
pub fn client(){let mut headers=reqwest::header::HeaderMap::new();headers.insert("x-api-key",reqwest::header::HeaderValue::from_static("marker"));let client=reqwest::Client::builder().default_headers(headers).build();}
pub fn restricted(){let mut headers=reqwest::header::HeaderMap::new();headers.insert("x-api-key",reqwest::header::HeaderValue::from_static("marker"));let client=reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).default_headers(headers).build();}
pub fn innocuous(){let mut headers=reqwest::header::HeaderMap::new();headers.insert("accept",reqwest::header::HeaderValue::from_static("text/plain"));let client=reqwest::Client::builder().default_headers(headers).build();}
"#;
    assert_eq!(
        assess(source),
        [
            (
                "client".into(),
                "rust-default-credential-header-review".into()
            ),
            (
                "restricted".into(),
                "rust-default-credential-header-review".into()
            )
        ]
    );
    assert!(
        assess(
            r#"
macro_rules! println{($f:expr,$v:expr)=>{()}}
pub fn hidden(){let token=jsonwebtoken::encode(&header,&claims,&key).unwrap();println!("{}",token);}
"#
        )
        .is_empty()
    );
}
#[test]
fn generated_token_direct_output_is_separate_from_lengths_and_shadowing() {
    let source = r#"
pub fn disclose(){let token=jsonwebtoken::encode(&header,&claims,&key).unwrap();println!("{}",token);}
pub fn length(){let token=jsonwebtoken::encode(&header,&claims,&key).unwrap();println!("{}",token.len());}
pub fn shadow(){let token=jsonwebtoken::encode(&header,&claims,&key).unwrap();let token="redacted";println!("{}",token);}
pub fn ordinary(token:&str){println!("{}",token);}
"#;
    assert_eq!(
        assess(source),
        [(
            "disclose".into(),
            "rust-generated-credential-output-review".into()
        )]
    );
}

#[test]
fn signature_policy_must_reach_the_same_consuming_verifier() {
    let source = r#"
pub fn insecure(token:&str){let mut validation=jsonwebtoken::Validation::default();validation.insecure_disable_signature_validation();jsonwebtoken::decode::<Claims>(token,&key,&validation);}
pub fn secure(token:&str){let validation=jsonwebtoken::Validation::default();jsonwebtoken::decode::<Claims>(token,&key,&validation);}
pub fn different(token:&str){let mut first=jsonwebtoken::Validation::default();first.insecure_disable_signature_validation();let second=jsonwebtoken::Validation::default();jsonwebtoken::decode::<Claims>(token,&key,&second);}
pub fn blocking(){let mut headers=reqwest::header::HeaderMap::new();headers.insert("x-api-key",reqwest::header::HeaderValue::from_static("marker"));reqwest::blocking::Client::builder().default_headers(headers).build();}
"#;
    assert_eq!(
        assess(source),
        [
            (
                "blocking".into(),
                "rust-default-credential-header-review".into()
            ),
            (
                "insecure".into(),
                "rust-jwt-verification-policy-review".into()
            )
        ]
    );
}
