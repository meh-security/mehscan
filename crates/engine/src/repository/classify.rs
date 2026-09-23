use std::path::Path;

use mehscan_core::Language;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileClass {
    Supported(Language),
    EmbeddedJavascriptTemplate,
    Razor,
    WebForms,
    SecretOnly,
    UnsupportedSource,
    Ignored,
}

#[cfg(test)]
pub(crate) fn classify_path(path: &Path) -> FileClass {
    classify_path_with_options(path, false)
}

pub(crate) fn classify_path_with_options(path: &Path, include_nonproduction: bool) -> FileClass {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name == ".mehscan-secrets-allowlist" {
        return FileClass::Ignored;
    }
    if name == ".env"
        || name.starts_with(".env.")
        || matches!(name.as_str(), "dockerfile" | "containerfile")
    {
        return FileClass::SecretOnly;
    }
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return FileClass::Ignored;
    };
    let class = match extension.to_ascii_lowercase().as_str() {
        "c" => FileClass::Supported(Language::C),
        // C and C++ share the .h suffix. Without compilation metadata the C++
        // grammar is the safer syntax superset. Keep this documented fallback
        // until compilation metadata can classify headers by translation unit.
        "h" | "hh" | "hpp" | "hxx" | "cc" | "cpp" | "cxx" | "c++" => {
            FileClass::Supported(Language::Cpp)
        }
        "cs" => FileClass::Supported(Language::Csharp),
        "cshtml" | "razor" => FileClass::Razor,
        "aspx" | "ascx" => FileClass::WebForms,
        "java" => FileClass::Supported(Language::Java),
        "kt" | "kts" => FileClass::Supported(Language::Kotlin),
        "js" | "jsx" | "mjs" | "cjs" => FileClass::Supported(Language::Javascript),
        "ts" | "mts" | "cts" => FileClass::Supported(Language::Typescript),
        "tsx" => FileClass::Supported(Language::Tsx),
        "ejs" => FileClass::EmbeddedJavascriptTemplate,
        "py" | "pyi" | "py3" | "pyw" => FileClass::Supported(Language::Python),
        "go" => FileClass::Supported(Language::Go),
        "rs" => FileClass::Supported(Language::Rust),
        "php" | "phtml" | "php5" | "php7" | "php8" => FileClass::Supported(Language::Php),
        "json" | "json5" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "config"
        | "properties" | "xml" | "env" | "tf" | "tfvars" | "hcl" | "md" | "markdown" | "txt"
        | "sql" | "graphql" | "sh" | "bash" | "zsh" | "ps1" => FileClass::SecretOnly,
        "rb" | "scala" | "swift" | "ex" | "exs" | "dart" | "lua" | "sol" => {
            FileClass::UnsupportedSource
        }
        _ => FileClass::Ignored,
    };
    if !include_nonproduction
        && matches!(
            class,
            FileClass::Supported(_)
                | FileClass::EmbeddedJavascriptTemplate
                | FileClass::Razor
                | FileClass::WebForms
        )
        && is_sast_excluded_source(path)
    {
        FileClass::SecretOnly
    } else {
        class
    }
}

pub(crate) fn is_sast_excluded_source(path: &Path) -> bool {
    let components = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let kotlin_source = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "kt" | "kts"));
    let conventional_kotlin_set = |name: &str, suffix: &str| {
        name.strip_suffix(suffix).is_some_and(|prefix| {
            matches!(
                prefix,
                "common"
                    | "jvm"
                    | "android"
                    | "ios"
                    | "iosarm64"
                    | "iosx64"
                    | "iossimulatorarm64"
                    | "js"
                    | "wasmjs"
                    | "wasmwasi"
                    | "native"
                    | "apple"
                    | "linux"
                    | "linuxx64"
                    | "linuxarm64"
                    | "macos"
                    | "macosx64"
                    | "macosarm64"
                    | "mingwx64"
                    | "watchos"
                    | "tvos"
            )
        })
    };
    if kotlin_source
        && components.windows(3).any(|parts| {
            parts[0] == "src"
                && parts[2] == "kotlin"
                && (conventional_kotlin_set(&parts[1], "test")
                    || matches!(
                        parts[1].as_str(),
                        "androidunittest" | "androidinstrumentedtest"
                    ))
        })
    {
        return true;
    }
    let jvm_main = components
        .windows(3)
        .position(|parts| {
            parts[0] == "src"
                && (parts[1] == "main"
                    || kotlin_source && conventional_kotlin_set(&parts[1], "main"))
                && matches!(parts[2].as_str(), "kotlin" | "java")
        })
        .map(|index| index + 2);
    let in_nonproduction_directory = components.iter().enumerate().any(|(index, component)| {
        // Below a JVM production source root these names can be namespace
        // segments. Top-level examples and all test/generated roles still apply.
        if matches!(component.as_str(), "samples" | "examples")
            && jvm_main.is_some_and(|root| index > root)
        {
            return false;
        }
        matches!(
            component.as_str(),
            "test"
                | "tests"
                | "unit_test"
                | "unit_tests"
                | "unit-test"
                | "unit-tests"
                | "unittest"
                | "unittests"
                | "integration_test"
                | "integration_tests"
                | "integration-test"
                | "integration-tests"
                | "test_utils"
                | "test_crates"
                | "__tests__"
                | "spec"
                | "specs"
                | "fixture"
                | "fixtures"
                | "testdata"
                | "examples"
                | "samples"
                | "benches"
                | "benchmark"
                | "benchmarks"
                | "fuzz"
                | "oss-fuzz"
                | "__mocks__"
                | "migrations"
        ) || component.starts_with("test_")
            || component.starts_with("test-")
            || component.starts_with("test.")
            || component.ends_with("_test")
            || component.ends_with("_tests")
            || component.ends_with("-test")
            || component.ends_with("-tests")
            || component.ends_with(".test")
            || component.ends_with(".tests")
    });
    if in_nonproduction_directory && !is_next_app_route_module(path) {
        return true;
    }

    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    lower.contains(".spec.")
        || lower.contains(".test.")
        || lower.ends_with("_test.go")
        || ((lower.ends_with(".py") || lower.ends_with(".pyw"))
            && (lower.starts_with("test_")
                || lower.ends_with("_test.py")
                || lower.ends_with("_test.pyw")
                || matches!(lower.as_str(), "tests.py" | "conftest.py")))
        || (lower.starts_with("test") && lower.ends_with(".java"))
        || name.ends_with("Test.java")
        || name.ends_with("Tests.java")
        || name.ends_with("Test.kt")
        || name.ends_with("Tests.kt")
        || lower.ends_with(".generated.kt")
        || name.ends_with("Test.cs")
        || name.ends_with("Tests.cs")
        || name.ends_with("Test.php")
        || name.ends_with("Tests.php")
        || lower.ends_with(".generated.php")
        || lower.ends_with(".d.ts")
        || lower.ends_with(".d.mts")
        || lower.ends_with(".d.cts")
        || lower.contains(".min.js")
        || lower.contains(".min.mjs")
        || lower.contains(".min.cjs")
        || lower.contains(".bundle.js")
        || lower.contains(".bundle.mjs")
        || lower.contains(".bundle.cjs")
        || lower.ends_with(".pb.go")
        || lower.ends_with(".generated.cs")
        || lower.ends_with(".designer.cs")
        || lower.ends_with(".g.cs")
}

fn is_next_app_route_module(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    normalized.starts_with("src/app/")
        && matches!(
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("route.js" | "route.jsx" | "route.ts" | "route.tsx")
        )
}

/// Detects JavaScript distribution artifacts whose names do not carry the
/// usual `.min` or `.bundle` marker. The size and long-line gates avoid
/// classifying ordinary authored modules from a source-map comment alone.
pub(crate) fn is_generated_javascript_source(path: &Path, source: &str) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "js" | "jsx" | "mjs" | "cjs")
        || source.len() < 64 * 1024
        || source.lines().map(str::len).max().unwrap_or(0) < 32 * 1024
    {
        return false;
    }

    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    source.contains("sourceMappingURL=")
        || name.contains(".prod.js")
        || name.contains(".prod.mjs")
        || name.contains(".prod.cjs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_priority_languages() {
        assert_eq!(
            classify_path(Path::new("a.cs")),
            FileClass::Supported(Language::Csharp)
        );
        assert_eq!(
            classify_path(Path::new("a.TSX")),
            FileClass::Supported(Language::Tsx)
        );
        assert_eq!(classify_path(Path::new("Index.cshtml")), FileClass::Razor);
        assert_eq!(
            classify_path(Path::new("Pages/Index.razor")),
            FileClass::Razor
        );
        assert_eq!(
            classify_path(Path::new("views/profile.ejs")),
            FileClass::EmbeddedJavascriptTemplate
        );
        assert_eq!(
            classify_path(Path::new("Default.aspx")),
            FileClass::WebForms
        );
        assert_eq!(classify_path(Path::new("Menu.ascx")), FileClass::WebForms);
        assert_eq!(
            classify_path(Path::new("a.rs")),
            FileClass::Supported(Language::Rust)
        );
        assert_eq!(
            classify_path(Path::new("native.c")),
            FileClass::Supported(Language::C)
        );
        assert_eq!(
            classify_path(Path::new("native.cpp")),
            FileClass::Supported(Language::Cpp)
        );
        assert_eq!(
            classify_path(Path::new("native.h")),
            FileClass::Supported(Language::Cpp)
        );
        assert_eq!(
            classify_path(Path::new("launcher.pyw")),
            FileClass::Supported(Language::Python)
        );
        assert_eq!(classify_path(Path::new("README.md")), FileClass::SecretOnly);
        assert_eq!(
            classify_path(Path::new(".env.local")),
            FileClass::SecretOnly
        );
        assert_eq!(
            classify_path(Path::new(".mehscan-secrets-allowlist")),
            FileClass::Ignored
        );
        for path in [
            "a.json",
            "a.yaml",
            "a.toml",
            "a.properties",
            "a.xml",
            "a.tfvars",
            "a.md",
            "a.txt",
            "a.ps1",
            "Dockerfile",
        ] {
            assert_eq!(classify_path(Path::new(path)), FileClass::SecretOnly);
        }
    }

    #[test]
    fn routes_tests_and_generated_sources_to_secret_only_scanning() {
        for path in [
            "tests/unit/login.ts",
            "apps/unit_tests/xmlsec_unit_tests.c",
            "apps/unit-tests/xmlsec-unit-tests.cpp",
            "tests/integration_tests/crypto.c",
            "tests/integration-tests/crypto.cpp",
            "test_utils/test_main.c",
            "test_crates/example/src/lib.rs",
            "kitty_tests/parser.py",
            "parser_tests/native.c",
            "test_helpers/process.go",
            "src/login.spec.ts",
            "src/login.test.js",
            "pkg/login_test.go",
            "src/test_login.py",
            "src/login_test.py",
            "src/tests.py",
            "src/conftest.py",
            "src/migrations/0001_initial.py",
            "src/LoginTest.java",
            "src/TestLogin.java",
            "src/LoginTests.cs",
            "tests/Views/Index.cshtml",
            "tests/Pages/Index.razor",
            "types/index.d.ts",
            "types/index.d.mts",
            "types/index.d.cts",
            "public/app.min.js",
            "internal/api/messages.pb.go",
            "tests/native_test.c",
            "fuzz/parser.cpp",
            "apps/oss-fuzz/parser.c",
            "Form.Designer.cs",
            "Generated.g.cs",
            "benches/parser.rs",
            "fuzz/fuzz_targets/parser.rs",
            "src/__mocks__/client.ts",
        ] {
            assert_eq!(
                classify_path(Path::new(path)),
                FileClass::SecretOnly,
                "{path}"
            );
        }
        assert_eq!(
            classify_path(Path::new("src/login.ts")),
            FileClass::Supported(Language::Typescript)
        );
        assert_eq!(
            classify_path(Path::new("apps/unit_testsupport/parser.c")),
            FileClass::Supported(Language::C),
            "test-like filename substrings are not directory exclusions"
        );
        assert_eq!(
            classify_path(Path::new("apps/contest/parser.c")),
            FileClass::Supported(Language::C),
            "ordinary directory names ending in the letters test remain scanned"
        );
        assert_eq!(
            classify_path(Path::new("apps/unitary/parser.cpp")),
            FileClass::Supported(Language::Cpp),
            "ordinary production directory names remain scanned"
        );
        assert_eq!(
            classify_path(Path::new("src/app/api/webhooks/test/route.ts")),
            FileClass::Supported(Language::Typescript),
            "an App Router URL segment named test is production code"
        );
        assert_eq!(
            classify_path(Path::new("src/app/api/webhooks/test/handler.test.ts")),
            FileClass::SecretOnly,
            "test files inside an App Router directory stay excluded"
        );
        assert_eq!(
            classify_path_with_options(Path::new("src/tests.py"), true),
            FileClass::Supported(Language::Python)
        );
        assert_eq!(
            classify_path_with_options(Path::new("src/migrations/0001_initial.py"), true),
            FileClass::Supported(Language::Python)
        );
        assert_eq!(
            classify_path_with_options(Path::new("apps/unit_tests/xmlsec_unit_tests.c"), true),
            FileClass::Supported(Language::C)
        );
    }

    #[test]
    fn detects_only_strong_unnamed_javascript_build_outputs() {
        let padding = "x".repeat(70 * 1024);
        let mapped = format!("(()=>{{/*{padding}*/}})();\n//# sourceMappingURL=app.js.map");
        assert!(is_generated_javascript_source(
            Path::new("wwwroot/Scripts/app.js"),
            &mapped
        ));

        let production = format!("/** @license */\nconst runtime='{padding}';");
        assert!(is_generated_javascript_source(
            Path::new("wwwroot/Scripts/vue.global.prod.js"),
            &production
        ));

        let ordinary = "export function load(url) { return fetch(url); }\n";
        assert!(!is_generated_javascript_source(
            Path::new("wwwroot/Scripts/application.js"),
            ordinary
        ));
        let large_authored = format!("const embedded = '{padding}';\nexport {{ embedded }};\n");
        assert!(!is_generated_javascript_source(
            Path::new("wwwroot/Scripts/application.js"),
            &large_authored
        ));
        assert!(!is_generated_javascript_source(
            Path::new("wwwroot/Scripts/application.ts"),
            &mapped
        ));
    }

    #[test]
    fn jvm_production_namespaces_do_not_hide_sample_packages() {
        for (path, language) in [
            (
                "src/main/kotlin/org/springframework/samples/Owner.kt",
                Language::Kotlin,
            ),
            (
                "app/src/main/kotlin/io/ktor/examples/App.kt",
                Language::Kotlin,
            ),
            (
                "src/main/java/org/springframework/samples/Owner.java",
                Language::Java,
            ),
        ] {
            assert_eq!(
                classify_path(Path::new(path)),
                FileClass::Supported(language),
                "{path}"
            );
        }
        for path in [
            "samples/app/src/main/kotlin/App.kt",
            "examples/src/main/java/App.java",
            "src/test/kotlin/org/samples/Owner.kt",
            "src/main/kotlin/tests/App.kt",
        ] {
            assert_eq!(
                classify_path(Path::new(path)),
                FileClass::SecretOnly,
                "{path}"
            );
        }
    }

    #[test]
    fn conventional_kotlin_multiplatform_sets_keep_test_and_namespace_roles() {
        for set in [
            "commonMain",
            "jvmMain",
            "androidMain",
            "iosArm64Main",
            "iosSimulatorArm64Main",
            "jsMain",
            "nativeMain",
            "wasmJsMain",
        ] {
            let source = format!("app/src/{set}/kotlin/org/examples/App.kt");
            assert_eq!(
                classify_path(Path::new(&source)),
                FileClass::Supported(Language::Kotlin)
            );
            let outer = format!("examples/app/src/{set}/kotlin/App.kt");
            assert_eq!(classify_path(Path::new(&outer)), FileClass::SecretOnly);
        }
        for set in [
            "commonTest",
            "jvmTest",
            "androidTest",
            "androidUnitTest",
            "androidInstrumentedTest",
            "iosArm64Test",
            "jsTest",
            "nativeTest",
            "wasmJsTest",
        ] {
            let source = format!("app/src/{set}/kotlin/org/App.kt");
            assert_eq!(classify_path(Path::new(&source)), FileClass::SecretOnly);
            assert_eq!(
                classify_path_with_options(Path::new(&source), true),
                FileClass::Supported(Language::Kotlin)
            );
        }
        assert_eq!(
            classify_path(Path::new("src/latest/kotlin/App.kt")),
            FileClass::Supported(Language::Kotlin)
        );
        assert_eq!(
            classify_path(Path::new("src/domain/kotlin/examples/App.kt")),
            FileClass::SecretOnly
        );
        assert_eq!(
            classify_path(Path::new("src/commonMain/js/examples/App.js")),
            FileClass::SecretOnly
        );
    }
}
