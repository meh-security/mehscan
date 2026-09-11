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
        "cs" => FileClass::Supported(Language::Csharp),
        "cshtml" => FileClass::Razor,
        "aspx" | "ascx" => FileClass::WebForms,
        "java" => FileClass::Supported(Language::Java),
        "js" | "jsx" | "mjs" | "cjs" => FileClass::Supported(Language::Javascript),
        "ts" | "mts" | "cts" => FileClass::Supported(Language::Typescript),
        "tsx" => FileClass::Supported(Language::Tsx),
        "ejs" => FileClass::EmbeddedJavascriptTemplate,
        "py" | "pyi" | "py3" | "pyw" => FileClass::Supported(Language::Python),
        "go" => FileClass::Supported(Language::Go),
        "rs" => FileClass::Supported(Language::Rust),
        "json" | "json5" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "config"
        | "properties" | "xml" | "env" | "tf" | "tfvars" | "hcl" | "md" | "markdown" | "txt"
        | "sql" | "graphql" | "sh" | "bash" | "zsh" | "ps1" => FileClass::SecretOnly,
        "php" | "kt" | "kts" | "rb" | "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "scala"
        | "swift" | "ex" | "exs" | "dart" | "lua" | "sol" => FileClass::UnsupportedSource,
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
    let in_nonproduction_directory = path.components().any(|component| {
        let component = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            component.as_str(),
            "test"
                | "tests"
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
                | "__mocks__"
                | "migrations"
        )
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
        || name.ends_with("Test.cs")
        || name.ends_with("Tests.cs")
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
            "test_crates/example/src/lib.rs",
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
            "types/index.d.ts",
            "types/index.d.mts",
            "types/index.d.cts",
            "public/app.min.js",
            "internal/api/messages.pb.go",
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
}
