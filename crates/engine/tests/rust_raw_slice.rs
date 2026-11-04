mod support;
use mehscan_core::{Capability, SecurityPathState};
use std::fs;

#[test]
fn safe_null_field_construction_requires_a_nonnull_raw_slice_boundary() {
    let root = support::temp_dir("rust-raw-slice");
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "unprotected",
            "",
            "std::slice::from_raw_parts",
            "",
            Some(SecurityPathState::Unknown),
        ),
        (
            "guarded",
            "if self.raw.address.is_null() { return &[]; }",
            "std::slice::from_raw_parts",
            "",
            Some(SecurityPathState::Protected),
        ),
        (
            "wrong_field",
            "if self.raw.other.is_null() { return &[]; }",
            "std::slice::from_raw_parts",
            "",
            Some(SecurityPathState::Unknown),
        ),
        (
            "wrong_length_property",
            "if self.raw.used == 0 { return &[]; }",
            "std::slice::from_raw_parts",
            "",
            Some(SecurityPathState::Unknown),
        ),
        (
            "conditional_return",
            "if self.raw.address.is_null() { if enabled() { return &[]; } }",
            "std::slice::from_raw_parts",
            "",
            Some(SecurityPathState::Unknown),
        ),
        (
            "closure_return",
            "if self.raw.address.is_null() { let exit = || -> &'static [u8] { return &[]; }; }",
            "std::slice::from_raw_parts",
            "",
            Some(SecurityPathState::Unknown),
        ),
        (
            "opaque_call_after_guard",
            "if self.raw.address.is_null() { return &[]; } foreign_mutation(self);",
            "std::slice::from_raw_parts",
            "",
            Some(SecurityPathState::Unknown),
        ),
        (
            "unsafe_accessor",
            "",
            "std::slice::from_raw_parts",
            "unsafe",
            None,
        ),
        (
            "foreign_function",
            "",
            "project::slice::from_raw_parts",
            "",
            None,
        ),
    ];
    for (name, guard, consumer, unsafe_accessor, _) in cases {
        fs::write(root.join(format!("{name}.rs")), format!(r#"
            #[derive(Clone, Copy)]
            struct Raw {{ address: *mut u8, other: *mut u8, used: usize }}
            struct View {{ raw: Raw }}
            trait Import {{ unsafe fn ingest(raw: *mut Raw) -> Self; }}
            impl Import for View {{ unsafe fn ingest(raw: *mut Raw) -> View {{ View {{ raw: *raw }} }} }}
            impl View {{
                pub fn empty() -> View {{ unsafe {{ Import::ingest(&mut Raw {{
                    address: std::ptr::null_mut(), other: std::ptr::null_mut(), used: 0,
                }} as *mut _) }} }}
                pub {unsafe_accessor} fn bytes(&mut self) -> &[u8] {{
                    {guard}
                    unsafe {{ {consumer}(self.raw.address as *const u8, self.raw.used) }}
                }}
            }}
            fn enabled() -> bool {{ false }}
            fn foreign_mutation(value:&mut View) {{ value.raw.address=std::ptr::null_mut(); }}
            mod project {{ pub mod slice {{ pub fn from_raw_parts<'a>(_: *const u8,_:usize)->&'a [u8] {{ &[] }} }} }}
        "#)).unwrap();
    }
    fs::write(
        root.join("sentinel.rs"),
        r#"
        struct View { address:*mut u8 }
        impl View {
            fn empty()->Self { Self { address:std::ptr::NonNull::dangling().as_ptr() } }
            fn bytes(&self)->&[u8] { unsafe {std::slice::from_raw_parts(self.address,0)} }
        }
    "#,
    )
    .unwrap();
    fs::write(
        root.join("local.rs"),
        r#"
        struct View { address:*mut u8 }
        impl View {
            fn empty()->Self { Self { address:std::ptr::null_mut() } }
            fn bytes(&self)->&[u8] { unsafe {std::slice::from_raw_parts(self.address,0)} }
        }
    "#,
    )
    .unwrap();
    for (name, override_call, expected) in [
        ("imported_api", "", true),
        ("local_callable_shadow", "let range = project_range;", false),
        (
            "constant_callable_shadow",
            "const range:fn(*const u8,usize)->&'static [u8]=project_range;",
            false,
        ),
        (
            "conditional_replacement",
            "if flag() { self.address=std::ptr::NonNull::dangling().as_ptr(); }",
            true,
        ),
        (
            "replaced_field",
            "self.address = std::ptr::NonNull::dangling().as_ptr();",
            false,
        ),
    ] {
        let consumer = if name.ends_with("callable_shadow") {
            "range"
        } else {
            "range::<u8>"
        };
        fs::write(root.join(format!("{name}.rs")),format!(r#"
            use std::ptr::null_mut as zero;
            use core::slice::from_raw_parts as range;
            struct View {{ address:*mut u8 }}
            impl View {{
                fn empty()->Self {{ Self {{ address:zero::<u8>() }} }}
                fn bytes(&mut self)->&[u8] {{ {override_call} unsafe {{{consumer}(self.address,0)}} }}
            }}
            fn project_range(_: *const u8,_:usize)->&'static [u8] {{ &[] }}
            fn flag()->bool {{ false }}
        "#)).unwrap();
        let scan = mehscan_engine::scan_path(&root.join(format!("{name}.rs"))).unwrap();
        assert_eq!(
            scan.security_paths
                .iter()
                .filter(|p| p.capability == Capability::RustRawSliceConstruction)
                .count(),
            usize::from(expected),
            "{name}"
        );
    }
    fs::write(root.join("looped.rs"), r#"
        struct View { address:*mut u8 }
        impl View {
            fn empty()->Self { Self { address:std::ptr::null_mut() } }
            fn bytes(&mut self)->&[u8] {
                if self.address.is_null() { return &[]; }
                for _ in 0..2 { let _=unsafe {std::slice::from_raw_parts(self.address,0)}; self.address=std::ptr::null_mut(); }
                &[]
            }
        }
    "#).unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let paths = scan
        .security_paths
        .iter()
        .filter(|p| p.capability == Capability::RustRawSliceConstruction)
        .collect::<Vec<_>>();
    for (name, _, _, _, expected) in cases {
        let selected = paths
            .iter()
            .filter(|p| {
                scan.evidence
                    .iter()
                    .any(|e| e.id == p.sink_evidence_id && e.location.path == format!("{name}.rs"))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected.len(),
            usize::from(expected.is_some()),
            "{name}: {paths:?}"
        );
        if let Some(expected) = expected {
            assert_eq!(selected[0].state, expected, "{name}");
        }
    }
    assert!(!paths.iter().any(|p| {
        scan.evidence
            .iter()
            .any(|e| e.id == p.sink_evidence_id && e.location.path == "sentinel.rs")
    }));
    let local = paths
        .iter()
        .find(|p| {
            scan.evidence
                .iter()
                .any(|e| e.id == p.sink_evidence_id && e.location.path == "local.rs")
        })
        .unwrap();
    assert_eq!(
        local.state,
        SecurityPathState::Unknown,
        "zero length still requires a non-null pointer"
    );
    let looped = paths
        .iter()
        .find(|p| {
            scan.evidence
                .iter()
                .any(|e| e.id == p.sink_evidence_id && e.location.path == "looped.rs")
        })
        .unwrap();
    assert_eq!(looped.state, SecurityPathState::Unknown);
    assert!(
        !paths
            .iter()
            .any(|p| scan.evidence.iter().any(|e| e.id == p.sink_evidence_id
                && ["local_callable_shadow.rs", "replaced_field.rs"]
                    .contains(&e.location.path.as_str())))
    );
    assert_eq!(
        scan.evidence.len(),
        scan.evidence
            .iter()
            .map(|e| &e.id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    for e in &scan.evidence {
        for c in e.captures.values() {
            let source = fs::read(root.join(&c.location.path)).unwrap();
            assert_eq!(
                &source[c.location.start.byte_offset..c.location.end.byte_offset],
                c.text.as_bytes()
            );
        }
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(20), false).unwrap();
    let reviews = jobs
        .reviews
        .iter()
        .filter(|r| r.candidate.capability == Capability::RustRawSliceConstruction)
        .collect::<Vec<_>>();
    assert_eq!(
        reviews.len(),
        paths
            .iter()
            .filter(|p| p.state == SecurityPathState::Unknown)
            .count()
    );
    assert!(reviews.iter().all(|r| {
        r.open_questions
            .iter()
            .any(|q| q.contains("concrete null field state"))
    }));
    fs::remove_dir_all(root).unwrap();
}
