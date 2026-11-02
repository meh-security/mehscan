use std::{
    collections::BTreeSet,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

fn scan(extension: &str, source: &str) -> mehscan_core::ScanResult {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("mehscan-jwt-key-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join(format!("input.{extension}")), source).unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    result
}

fn signing_symbols(result: &mehscan_core::ScanResult) -> BTreeSet<&str> {
    result
        .evidence
        .iter()
        .filter(|e| e.rule_id.ends_with("-jwt-hardcoded-signing-key"))
        .map(|e| e.enclosing_symbol.as_deref().unwrap())
        .collect()
}

#[test]
fn keys_follow_the_actual_binding_without_borrowing_other_functions_or_shadows() {
    let source = r#"
import jwt from 'jsonwebtoken';
const key = 'fixed-module-key-material';
function actual(payload){const key='fixed-local-key-material';return jwt.sign(payload,key);}
function global(payload){return jwt.sign(payload,key);}
function parameter(payload,key){return jwt.sign(payload,key);}
function destructured(payload,{key}){return jwt.sign(payload,key);}
function unrelated(payload){const key=loadRuntimeKey();return jwt.sign(payload,key);}
function alias(payload){const bytes='fixed-key-material';const copy=bytes;return jwt.sign(payload,copy);}
function short(payload){const arbitraryName='tiny';return jwt.sign(payload,arbitraryName);}
function mutated(payload){let key='fixed-key-material';key=loadRuntimeKey();return jwt.sign(payload,key);}
function beforeWrite(payload){let key='fixed-key-material';const token=jwt.sign(payload,key);key=loadRuntimeKey();return token;}
function late(payload){const token=jwt.sign(payload,key);const key='late-local-key-material';return token;}
function block(payload){const key='fixed-key-material';{const key=loadRuntimeKey();return jwt.sign(payload,key);}}
function caught(payload){try{fail();}catch(key){return jwt.sign(payload,key);}}
function loop(payload,keys){for(const key of keys){jwt.sign(payload,key);}}
function overwrittenParameter(payload,key){var key='fixed-key-material';return jwt.sign(payload,key);}
function template(payload,runtime){const key=`fixed-prefix-${runtime}`;return jwt.sign(payload,key);}
function buffer(payload){return jwt.sign(payload,Buffer.from('fixed-key-material','utf8'));}
function dynamicEncoding(payload,encoding){return jwt.sign(payload,Buffer.from('fixed-key-material',encoding));}
function sdkShadow(payload,jwt){return jwt.sign(payload,key);}
function localSdkShadow(payload){const jwt=otherModule();return jwt.sign(payload,key);}
function closure(payload){return jwt.sign(payload,laterKey);}
const laterKey='captured-fixed-key-material';
"#;
    for extension in ["js", "ts", "tsx"] {
        let result = scan(extension, source);
        assert_eq!(
            signing_symbols(&result),
            [
                "actual",
                "global",
                "alias",
                "short",
                "beforeWrite",
                "overwrittenParameter",
                "buffer",
                "closure"
            ]
            .into_iter()
            .collect(),
            "{extension}\n{:#?}",
            signing_symbols(&result)
        );
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.rule_id.ends_with("-jwt-token-generation")
                    && e.enclosing_symbol.as_deref() == Some("parameter"))
        );
        assert!(
            result
                .evidence
                .iter()
                .filter(|e| e.rule_id.ends_with("-jwt-without-expiry"))
                .all(|e| e.kind == mehscan_core::EvidenceKind::Resource)
        );
        for e in result.evidence.iter().filter(|e| {
            e.rule_id.ends_with("-jwt-hardcoded-signing-key")
                || e.rule_id.ends_with("-hardcoded-jwt-key")
        }) {
            for c in e.captures.values() {
                assert_eq!(
                    &source[c.location.start.byte_offset..c.location.end.byte_offset],
                    c.text
                );
            }
        }
        let ids = result
            .evidence
            .iter()
            .map(|e| &e.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), result.evidence.len());
    }
}

#[test]
fn sdk_producers_and_captured_mutations_are_resolved_in_their_own_scope() {
    for source in [
        "const jwt=require('jsonwebtoken');function f(payload){return jwt.sign(payload,'fixed-key-material',{expiresIn:'1h',algorithm:'HS256'});}",
        "const {sign:issue}=require('jsonwebtoken');function f(payload){return issue(payload,'fixed-key-material');}",
        "import {createRequire} from 'node:module';const require=createRequire(import.meta.url);const jwt=require('jsonwebtoken');function f(payload){return jwt.sign(payload,'fixed-key-material');}",
        "import jwt from 'jsonwebtoken';function f(payload){var key='fixed-key-material';var key;return jwt.sign(payload,key);}",
    ] {
        let result = scan("js", source);
        assert_eq!(
            signing_symbols(&result),
            ["f"].into_iter().collect(),
            "{source}\n{:#?}",
            result.evidence
        );
    }
    for source in [
        "function f(require,payload){const jwt=require('jsonwebtoken');return jwt.sign(payload,'fixed-key-material');}",
        "import jwt from 'jsonwebtoken';let key='fixed-key-material';function change(){key=loadRuntimeKey();}function f(payload){return jwt.sign(payload,key);}",
        "import jwt from 'jsonwebtoken';jwt.sign=otherSigner;function f(payload){return jwt.sign(payload,'fixed-key-material');}",
        "import jwt from 'jsonwebtoken';function f(payload,Buffer){return jwt.sign(payload,Buffer.from('fixed-key-material'));}",
    ] {
        let result = scan("js", source);
        assert!(signing_symbols(&result).is_empty(), "{source}");
    }
}

#[test]
fn sdk_key_proof_does_not_remove_syntactic_decoder_identity_relationships() {
    for extension in ["js", "ts", "tsx"] {
        let result = scan(
            extension,
            "import * as security from './token-utils';\nfunction subject(token){const decoded=security.decode(token);return decoded?.data?.subject;}",
        );
        let sink = result
            .evidence
            .iter()
            .find(|e| e.rule_id.ends_with("-jwt-decode-as-identity"))
            .expect("the local decoder use remains an investigation lead");
        assert!(signing_symbols(&result).is_empty());
        assert!(result.security_paths.iter().any(|path| {
            path.sink_evidence_id == sink.id
                && path.state == mehscan_core::SecurityPathState::Unknown
        }));
        for source in [
            "import * as security from './token-utils';function subject(token){const decoded=security.decode(token);return decoded;}",
            "import * as security from './token-utils';function subject(token){security.verify(token);const decoded=security.decode(token);return decoded?.data?.subject;}",
        ] {
            assert!(
                !scan(extension, source)
                    .evidence
                    .iter()
                    .any(|e| e.rule_id.ends_with("-jwt-decode-as-identity"))
            );
        }
    }
}
