#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacySerializerFamily {
    BinaryFormatter,
    FrameworkOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeApplicability {
    Active,
    NonExecuting,
    Unknown,
}

#[derive(Clone, Debug)]
struct DotnetProject {
    directory: String,
    targets: Vec<TargetFramework>,
    web_sdk: bool,
    windows_desktop: bool,
    binary_formatter_package: bool,
    binary_formatter_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetFramework {
    Framework,
    Modern { major: u32 },
    Other,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DotnetProjectContext {
    projects: Vec<DotnetProject>,
}

impl DotnetProjectContext {
    pub(crate) fn from_project_files<'a>(files: impl Iterator<Item = (&'a str, &'a str)>) -> Self {
        let mut projects = files
            .map(|(path, source)| DotnetProject {
                directory: path
                    .rsplit_once('/')
                    .map(|(directory, _)| directory.to_string())
                    .unwrap_or_default(),
                targets: target_frameworks(source),
                web_sdk: project_sdk(source)
                    .is_some_and(|sdk| sdk.eq_ignore_ascii_case("Microsoft.NET.Sdk.Web")),
                windows_desktop: element_is_true(source, "UseWPF")
                    || element_is_true(source, "UseWindowsForms"),
                binary_formatter_package: package_references(source)
                    .iter()
                    .any(|package| package == "system.runtime.serialization.formatters"),
                binary_formatter_enabled: element_values(
                    source,
                    "EnableUnsafeBinaryFormatterSerialization",
                )
                .iter()
                .any(|value| value.eq_ignore_ascii_case("true")),
            })
            .collect::<Vec<_>>();
        projects.sort_by(|left, right| {
            right
                .directory
                .len()
                .cmp(&left.directory.len())
                .then_with(|| left.directory.cmp(&right.directory))
        });
        Self { projects }
    }

    pub(crate) fn applicability(
        &self,
        path: &str,
        family: LegacySerializerFamily,
    ) -> RuntimeApplicability {
        let Some(project) = self.projects.iter().find(|project| {
            project.directory.is_empty()
                || path == project.directory
                || path
                    .strip_prefix(&project.directory)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) else {
            return RuntimeApplicability::Unknown;
        };
        if project.targets.is_empty() || project.targets.contains(&TargetFramework::Other) {
            return RuntimeApplicability::Unknown;
        }
        match family {
            LegacySerializerFamily::BinaryFormatter => {
                classify_targets(&project.targets, |target| match target {
                    TargetFramework::Framework => RuntimeApplicability::Active,
                    TargetFramework::Modern { major: 0..=4 } => RuntimeApplicability::Active,
                    TargetFramework::Modern { major: 5..=7 } => {
                        if project.binary_formatter_enabled || !project.web_sdk {
                            RuntimeApplicability::Active
                        } else {
                            RuntimeApplicability::NonExecuting
                        }
                    }
                    TargetFramework::Modern { major: 8 } => {
                        if project.binary_formatter_enabled || project.windows_desktop {
                            RuntimeApplicability::Active
                        } else {
                            RuntimeApplicability::NonExecuting
                        }
                    }
                    TargetFramework::Modern { major: 9.. } => {
                        if project.binary_formatter_package && project.binary_formatter_enabled {
                            RuntimeApplicability::Active
                        } else {
                            RuntimeApplicability::NonExecuting
                        }
                    }
                    TargetFramework::Other => RuntimeApplicability::Unknown,
                })
            }
            LegacySerializerFamily::FrameworkOnly => {
                classify_targets(&project.targets, |target| match target {
                    TargetFramework::Framework => RuntimeApplicability::Active,
                    TargetFramework::Modern { .. } => RuntimeApplicability::NonExecuting,
                    TargetFramework::Other => RuntimeApplicability::Unknown,
                })
            }
        }
    }
}

fn element_is_true(source: &str, name: &str) -> bool {
    element_values(source, name)
        .iter()
        .any(|value| value.eq_ignore_ascii_case("true"))
}

fn project_sdk(source: &str) -> Option<&str> {
    let project = source.split('<').find_map(|fragment| {
        let fragment = fragment.trim_start();
        fragment.strip_prefix("Project")
    })?;
    attribute_value(project, "Sdk")
}

fn classify_targets(
    targets: &[TargetFramework],
    classify: impl Fn(TargetFramework) -> RuntimeApplicability,
) -> RuntimeApplicability {
    let mut states = targets.iter().copied().map(classify);
    let Some(first) = states.next() else {
        return RuntimeApplicability::Unknown;
    };
    if states.all(|state| state == first) {
        first
    } else {
        RuntimeApplicability::Unknown
    }
}

fn target_frameworks(source: &str) -> Vec<TargetFramework> {
    element_values(source, "TargetFramework")
        .into_iter()
        .chain(element_values(source, "TargetFrameworks"))
        .flat_map(|value| {
            value
                .split(';')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(classify_target)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn classify_target(target: &str) -> TargetFramework {
    let target = target.trim().to_ascii_lowercase();
    if target.starts_with("net4") && !target.contains('.') {
        return TargetFramework::Framework;
    }
    if let Some(version) = target.strip_prefix("net")
        && let Some((major, _)) = version.split_once('.')
        && let Ok(major) = major.parse::<u32>()
    {
        return TargetFramework::Modern { major };
    }
    if let Some(version) = target.strip_prefix("netcoreapp")
        && let Some((major, _)) = version.split_once('.')
        && let Ok(major) = major.parse::<u32>()
    {
        return TargetFramework::Modern { major };
    }
    TargetFramework::Other
}

fn element_values(source: &str, name: &str) -> Vec<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut values = Vec::new();
    let mut remaining = source;
    while let Some(start) = remaining.find(&open) {
        let tail = &remaining[start + open.len()..];
        let Some(end) = tail.find(&close) else {
            break;
        };
        values.push(tail[..end].trim().to_string());
        remaining = &tail[end + close.len()..];
    }
    values
}

fn package_references(source: &str) -> Vec<String> {
    source
        .split('<')
        .filter_map(|fragment| {
            let fragment = fragment.trim_start();
            let attributes = fragment.strip_prefix("PackageReference")?;
            attribute_value(attributes, "Include")
                .or_else(|| attribute_value(attributes, "Update"))
                .map(|value| value.to_ascii_lowercase())
        })
        .collect()
}

fn attribute_value<'a>(attributes: &'a str, name: &str) -> Option<&'a str> {
    for quote in ['"', '\''] {
        let marker = format!("{name}={quote}");
        let Some(start) = attributes.find(&marker) else {
            continue;
        };
        let tail = &attributes[start + marker.len()..];
        if let Some(end) = tail.find(quote) {
            return Some(&tail[..end]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_framework_modern_and_binary_compatibility_targets() {
        let framework = DotnetProjectContext::from_project_files([(
            "Legacy/Legacy.csproj",
            "<Project><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup></Project>",
        )]
        .into_iter());
        assert_eq!(
            framework.applicability("Legacy/Code.cs", LegacySerializerFamily::FrameworkOnly),
            RuntimeApplicability::Active
        );

        let modern = DotnetProjectContext::from_project_files([(
            "Modern/Modern.csproj",
            "<Project><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>",
        )]
        .into_iter());
        assert_eq!(
            modern.applicability("Modern/Code.cs", LegacySerializerFamily::BinaryFormatter),
            RuntimeApplicability::NonExecuting
        );

        let compatibility = DotnetProjectContext::from_project_files([(
            "Compat/Compat.csproj",
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework><EnableUnsafeBinaryFormatterSerialization>true</EnableUnsafeBinaryFormatterSerialization></PropertyGroup><ItemGroup><PackageReference Include=\"System.Runtime.Serialization.Formatters\" /></ItemGroup></Project>",
        )]
        .into_iter());
        assert_eq!(
            compatibility.applicability("Compat/Code.cs", LegacySerializerFamily::BinaryFormatter),
            RuntimeApplicability::Active
        );

        let net8_default = DotnetProjectContext::from_project_files([(
            "Net8/Net8.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>",
        )]
        .into_iter());
        assert_eq!(
            net8_default.applicability("Net8/Code.cs", LegacySerializerFamily::BinaryFormatter),
            RuntimeApplicability::NonExecuting
        );

        let net8_wpf = DotnetProjectContext::from_project_files([(
            "Desktop/Desktop.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0-windows</TargetFramework><UseWPF>true</UseWPF></PropertyGroup></Project>",
        )]
        .into_iter());
        assert_eq!(
            net8_wpf.applicability("Desktop/Code.cs", LegacySerializerFamily::BinaryFormatter),
            RuntimeApplicability::Active
        );

        let net7_web = DotnetProjectContext::from_project_files([(
            "Web/Web.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"><PropertyGroup><TargetFramework>net7.0</TargetFramework></PropertyGroup></Project>",
        )]
        .into_iter());
        assert_eq!(
            net7_web.applicability("Web/Code.cs", LegacySerializerFamily::BinaryFormatter),
            RuntimeApplicability::NonExecuting
        );
    }
}
