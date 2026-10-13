//! GitHub upload-sarif compatible line hints; these are not native issue identity.
//! Algorithm reference: github/codeql-action src/fingerprints.ts (checked 2026-10-11).
use std::collections::{BTreeMap, BTreeSet};

const WINDOW: usize = 100;

/// Hash selected one-based lines, preserving the occurrence suffix for *all*
/// lines in the file. Uses JavaScript UTF-16 units and wrapping 64-bit arithmetic.
/// No filesystem access: callers must supply the original, bound source text.
pub fn github_line_hashes(source: &str, selected: &BTreeSet<usize>) -> BTreeMap<usize, String> {
    let mut state = LineHasher {
        window: [0; WINDOW],
        starts: [None; WINDOW],
        index: 0,
        raw: 0,
        first_mod: 37_u64.wrapping_pow(WINDOW as u32),
        line: 0,
        line_start: true,
        previous_cr: false,
        counts: BTreeMap::new(),
        selected,
        result: BTreeMap::new(),
    };
    for unit in source.encode_utf16().chain(std::iter::once(65535)) {
        state.process(unit);
    }
    for _ in 0..WINDOW {
        state.output();
        state.update(0);
    }
    state.result
}

struct LineHasher<'a> {
    window: [u16; WINDOW],
    starts: [Option<usize>; WINDOW],
    index: usize,
    raw: u64,
    first_mod: u64,
    line: usize,
    line_start: bool,
    previous_cr: bool,
    counts: BTreeMap<u64, usize>,
    selected: &'a BTreeSet<usize>,
    result: BTreeMap<usize, String>,
}

impl LineHasher<'_> {
    fn output(&mut self) {
        if let Some(line) = self.starts[self.index].take() {
            let count = self.counts.entry(self.raw).or_default();
            *count += 1;
            if self.selected.contains(&line) {
                self.result.insert(line, format!("{:x}:{count}", self.raw));
            }
        }
    }

    fn update(&mut self, unit: u16) {
        self.raw = self
            .raw
            .wrapping_mul(37)
            .wrapping_add(u64::from(unit))
            .wrapping_sub(
                self.first_mod
                    .wrapping_mul(u64::from(self.window[self.index])),
            );
        self.window[self.index] = unit;
        self.index = (self.index + 1) % WINDOW;
    }

    fn process(&mut self, mut unit: u16) {
        if unit == 32 || unit == 9 || (self.previous_cr && unit == 10) {
            self.previous_cr = false;
            return;
        }
        self.previous_cr = unit == 13;
        if self.previous_cr {
            unit = 10;
        }
        self.output();
        if self.line_start {
            self.line += 1;
            self.starts[self.index] = Some(self.line);
        }
        self.line_start = unit == 10;
        self.update(unit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_published_vectors_include_eof_and_normalize_line_endings() {
        // Expected values from github/codeql-action src/fingerprints.test.ts.
        assert_eq!(
            github_line_hashes("", &BTreeSet::from([1]))[&1],
            "c129715d7a2bc9a3:1"
        );
        let expected = [
            "e9496ae3ebfced30:1",
            "fb7c023a8b9ccb3f:1",
            "ce8ba1a563dcdaca:1",
            "e20e36e16fcb0cc8:1",
            "b3edc88f2938467e:1",
            "c8e28b0b4002a3a0:1",
            "c129715d7a2bc9a3:1",
        ];
        for ending in ["\n", "\r", "\r\n"] {
            let source = [
                " hello; \t",
                "world!!!",
                "",
                "",
                "  \t\tGreetings",
                " End",
                "",
            ]
            .join(ending);
            let hashes = github_line_hashes(&source, &(1..=7).collect());
            assert_eq!(
                hashes.values().map(String::as_str).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn selected_lines_keep_duplicate_counts_from_unselected_lines() {
        let source = "Lorem ipsum dolor sit amet.\n".repeat(10);
        let hashes = github_line_hashes(&source, &BTreeSet::from([2, 6, 11, 12]));
        assert_eq!(hashes[&2], "a7f2ff13bc495cf2:2");
        assert_eq!(hashes[&6], "a7f2ff13bc495cf2:6");
        assert_eq!(hashes[&11], "c129715d7a2bc9a3:1");
        assert!(!hashes.contains_key(&12));
    }

    #[test]
    fn unicode_uses_utf16_and_preserves_non_tab_whitespace() {
        // Independent polynomial evaluation of the first window.
        let source = "🙂\u{a0}x\n";
        let expected = [0xd83d_u64, 0xde42, 0xa0, 120, 10, 65535]
            .into_iter()
            .chain(std::iter::repeat_n(0, 94))
            .fold(0_u64, |hash, unit| hash.wrapping_mul(37).wrapping_add(unit));
        assert_eq!(
            github_line_hashes(source, &BTreeSet::from([1]))[&1],
            format!("{expected:x}:1")
        );
        assert_ne!(
            github_line_hashes(source, &BTreeSet::from([1])),
            github_line_hashes("🙂 x\n", &BTreeSet::from([1]))
        );
    }
}
