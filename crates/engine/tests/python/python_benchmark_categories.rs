use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use mehscan_core::Capability;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Metrics {
    tp: usize,
    fn_: usize,
    fp: usize,
    tn: usize,
}

struct CategoryExpectation {
    name: &'static str,
    capabilities: &'static [Capability],
    cwe: &'static str,
    observations: Metrics,
    paths: Metrics,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn test_name(path: &str) -> Option<String> {
    Path::new(path).file_stem()?.to_str().map(str::to_string)
}

fn score<'a>(rows: impl Iterator<Item = (&'a str, bool)>, findings: &BTreeSet<String>) -> Metrics {
    rows.fold(Metrics::default(), |mut metrics, (name, vulnerable)| {
        match (vulnerable, findings.contains(name)) {
            (true, true) => metrics.tp += 1,
            (true, false) => metrics.fn_ += 1,
            (false, true) => metrics.fp += 1,
            (false, false) => metrics.tn += 1,
        }
        metrics
    })
}

fn category_rows<'a>(rows: &'a [(String, String, bool)], name: &str) -> Vec<(&'a str, bool)> {
    rows.iter()
        .filter(|(_, category, _)| category == name)
        .map(|(test, _, vulnerable)| (test.as_str(), *vulnerable))
        .collect()
}

#[test]
#[ignore = "requires the optional local BenchmarkPython corpus"]
fn optional_full_python_category_metrics_match_when_requested() {
    use Capability::*;
    let corpus = workspace_root().join("apps/python/BenchmarkPython");
    let labels_path = corpus.join("expectedresults-0.1.csv");
    assert!(labels_path.is_file(), "missing {}", labels_path.display());
    let labels = fs::read_to_string(labels_path).expect("labels should be readable");
    let rows = labels
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split(',');
            Some((
                fields.next()?.trim().to_string(),
                fields.next()?.trim().to_string(),
                fields.next()?.trim() == "true",
            ))
        })
        .collect::<Vec<_>>();
    let result = mehscan_engine::scan_path(corpus).expect("benchmark should scan");

    let expectations = [
        CategoryExpectation {
            name: "cmdi",
            capabilities: &[ProcessExecution],
            cwe: "CWE-78",
            observations: Metrics {
                tp: 13,
                fn_: 0,
                fp: 7,
                tn: 0,
            },
            paths: Metrics {
                tp: 0,
                fn_: 13,
                fp: 0,
                tn: 7,
            },
        },
        CategoryExpectation {
            name: "codeinj",
            capabilities: &[DynamicCodeExecution],
            cwe: "CWE-94",
            observations: Metrics {
                tp: 20,
                fn_: 0,
                fp: 33,
                tn: 0,
            },
            paths: Metrics {
                tp: 0,
                fn_: 20,
                fp: 2,
                tn: 31,
            },
        },
        CategoryExpectation {
            name: "deserialization",
            capabilities: &[Deserialization],
            cwe: "CWE-502",
            observations: Metrics {
                tp: 18,
                fn_: 0,
                fp: 12,
                tn: 24,
            },
            paths: Metrics {
                tp: 0,
                fn_: 18,
                fp: 1,
                tn: 35,
            },
        },
        CategoryExpectation {
            name: "hash",
            capabilities: &[CryptographicHash],
            cwe: "CWE-328",
            observations: Metrics {
                tp: 34,
                fn_: 37,
                fp: 35,
                tn: 45,
            },
            paths: Metrics {
                tp: 0,
                fn_: 71,
                fp: 0,
                tn: 80,
            },
        },
        CategoryExpectation {
            name: "ldapi",
            capabilities: &[LdapQuery],
            cwe: "CWE-90",
            observations: Metrics {
                tp: 0,
                fn_: 16,
                fp: 0,
                tn: 13,
            },
            paths: Metrics {
                tp: 0,
                fn_: 16,
                fp: 0,
                tn: 13,
            },
        },
        CategoryExpectation {
            name: "pathtraver",
            capabilities: &[FilesystemRead, FilesystemWrite],
            cwe: "CWE-22",
            observations: Metrics {
                tp: 46,
                fn_: 19,
                fp: 57,
                tn: 46,
            },
            paths: Metrics {
                tp: 2,
                fn_: 63,
                fp: 0,
                tn: 103,
            },
        },
        CategoryExpectation {
            name: "redirect",
            capabilities: &[Redirect],
            cwe: "CWE-601",
            observations: Metrics {
                tp: 13,
                fn_: 0,
                fp: 21,
                tn: 0,
            },
            paths: Metrics {
                tp: 1,
                fn_: 12,
                fp: 0,
                tn: 21,
            },
        },
        CategoryExpectation {
            name: "securecookie",
            capabilities: &[CookieConfiguration],
            cwe: "CWE-614",
            observations: Metrics {
                tp: 0,
                fn_: 24,
                fp: 0,
                tn: 15,
            },
            paths: Metrics {
                tp: 0,
                fn_: 24,
                fp: 0,
                tn: 15,
            },
        },
        CategoryExpectation {
            name: "sqli",
            capabilities: &[DatabaseQuery],
            cwe: "CWE-89",
            observations: Metrics {
                tp: 5,
                fn_: 0,
                fp: 11,
                tn: 0,
            },
            paths: Metrics {
                tp: 0,
                fn_: 5,
                fp: 0,
                tn: 11,
            },
        },
        CategoryExpectation {
            name: "trustbound",
            capabilities: &[],
            cwe: "CWE-501",
            observations: Metrics {
                tp: 0,
                fn_: 18,
                fp: 0,
                tn: 19,
            },
            paths: Metrics {
                tp: 0,
                fn_: 18,
                fp: 0,
                tn: 19,
            },
        },
        CategoryExpectation {
            name: "weakrand",
            capabilities: &[RandomGeneration],
            cwe: "CWE-330",
            observations: Metrics {
                tp: 0,
                fn_: 99,
                fp: 0,
                tn: 227,
            },
            paths: Metrics {
                tp: 0,
                fn_: 99,
                fp: 0,
                tn: 227,
            },
        },
        CategoryExpectation {
            name: "xpathi",
            capabilities: &[],
            cwe: "CWE-643",
            observations: Metrics {
                tp: 0,
                fn_: 51,
                fp: 0,
                tn: 135,
            },
            paths: Metrics {
                tp: 0,
                fn_: 51,
                fp: 0,
                tn: 135,
            },
        },
        CategoryExpectation {
            name: "xss",
            capabilities: &[HtmlOutput],
            cwe: "CWE-79",
            observations: Metrics {
                tp: 3,
                fn_: 28,
                fp: 2,
                tn: 56,
            },
            paths: Metrics {
                tp: 0,
                fn_: 31,
                fp: 0,
                tn: 58,
            },
        },
        CategoryExpectation {
            name: "xxe",
            capabilities: &[XmlParsing],
            cwe: "CWE-611",
            observations: Metrics {
                tp: 0,
                fn_: 8,
                fp: 0,
                tn: 20,
            },
            paths: Metrics {
                tp: 0,
                fn_: 8,
                fp: 0,
                tn: 20,
            },
        },
    ];

    for expectation in expectations {
        let observations = result
            .evidence
            .iter()
            .filter(|item| expectation.capabilities.contains(&item.capability))
            .filter_map(|item| test_name(&item.location.path))
            .collect::<BTreeSet<_>>();
        let paths = result
            .security_paths
            .iter()
            .filter(|path| path.cwe_candidates.iter().any(|cwe| cwe == expectation.cwe))
            .filter_map(|path| test_name(&path.steps.last()?.location.path))
            .collect::<BTreeSet<_>>();
        let category = category_rows(&rows, expectation.name);
        assert_eq!(
            score(category.iter().copied(), &observations),
            expectation.observations,
            "{} observation metrics changed",
            expectation.name
        );
        assert_eq!(
            score(category.into_iter(), &paths),
            expectation.paths,
            "{} path metrics changed",
            expectation.name
        );
    }
}
