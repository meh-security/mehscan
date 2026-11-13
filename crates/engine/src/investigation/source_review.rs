//! Original-source assignments and source-validated model questions. No taint proof.
use super::*;
use sha2::{Digest, Sha256};

const MODEL_RULE: &str = "model-discovered-security-question";
const MAX_WINDOW_BYTES: usize = 48 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceWindow {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub id: String,
    pub windows: Vec<SourceWindow>,
    pub review_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: String,
    pub source_fingerprint: String,
    pub inventory_fingerprint: String,
    pub selected_review_ids: Vec<String>,
    #[serde(default)]
    pub include_supporting_source: bool,
    #[serde(default)]
    pub excluded_sources: Vec<ExcludedSource>,
    pub assignments: Vec<Assignment>,
    pub limitations: Vec<String>,
    pub plan_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExcludedSource {
    pub path: String,
    pub reason: String,
    pub review_ids: Vec<String>,
    pub source_sha256: String,
    pub line_count: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub quote: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub key: String,
    pub assignment_id: String,
    pub capability: Capability,
    pub cwes: Vec<String>,
    pub question: String,
    pub mechanism: String,
    pub consequence: String,
    pub priority: String,
    pub anchor: Citation,
    pub evidence: Vec<Citation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub plan: Plan,
    pub inspected: Vec<SourceWindow>,
    pub proposals: Vec<Proposal>,
    #[serde(default)]
    pub assessment_evidence: Vec<Citation>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Binding {
    pub source_fingerprint: String,
    pub questions: Vec<Proposal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_sources: Vec<SourceWindow>,
}

fn hash(value: &impl Serialize) -> Result<String, EngineError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|e| EngineError(e.to_string()))?)
    ))
}
fn eligible(file: &SourceFile) -> bool {
    !is_review_material_path(&file.path)
        && !is_nonproduction_review_context_path(&file.path)
        && (file.language.is_some()
            || is_investigation_template(&file.path)
            || matches!(
                file.path
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str(),
                "razor"
                    | "cshtml"
                    | "vue"
                    | "ejs"
                    | "aspx"
                    | "ascx"
                    | "jsp"
                    | "erb"
                    | "html"
                    | "htm"
            ))
}

// Ignore the migration segment only for source-review planning. The common
// repository scanner policy and any other nonproduction segment stay intact.
fn migration_path(path: &str) -> bool {
    path.split('/')
        .any(|part| part.eq_ignore_ascii_case("migrations"))
}

fn nonproduction_without_migrations(path: &str) -> bool {
    let sanitized = path
        .split('/')
        .filter(|part| !part.eq_ignore_ascii_case("migrations"))
        .collect::<Vec<_>>()
        .join("/");
    let lower = sanitized.to_ascii_lowercase();
    let sanitized = if lower.ends_with(".designer.cs") {
        format!(
            "{}.cs",
            &sanitized[..sanitized.len() - ".designer.cs".len()]
        )
    } else {
        sanitized
    };
    is_review_material_path(&sanitized) || is_sast_excluded_source(Path::new(&sanitized))
}

// Large EF snapshots use a conventional model builder. Fall back to the AST
// whenever another apparent method declaration is present.
fn conventional_generated_model(source: &str) -> bool {
    let mut found = false;
    for line in source.lines() {
        for prefix in line.split('(').take(line.matches('(').count()) {
            let mut words = prefix.split_whitespace().rev();
            let Some(name) = words.next() else { continue };
            let Some(return_type) = words.next() else {
                continue;
            };
            let identifier = |s: &str| {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            };
            if !identifier(name)
                || !return_type
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_?.<>[],".contains(&b))
            {
                continue;
            }
            if matches!(name, "BuildModel" | "BuildTargetModel") && return_type == "void" {
                found = true;
            } else {
                return false;
            }
        }
    }
    found
}

fn schema_migration(file: &SourceFile) -> bool {
    if !file.path.to_ascii_lowercase().ends_with(".cs") {
        return false;
    }
    let lower = file.source.to_ascii_lowercase();
    let generated = lower.contains("<auto-generated")
        && (file.path.to_ascii_lowercase().ends_with(".designer.cs")
            || file.path.to_ascii_lowercase().ends_with("modelsnapshot.cs"));
    if !migration_path(&file.path) && !generated {
        return false;
    }
    if generated && conventional_generated_model(&file.source) {
        return true;
    }
    let Ok(document) = StrDoc::try_new(file.source.as_str(), SupportLang::CSharp) else {
        return false;
    };
    let ast = AstGrep::doc(document);
    if generated {
        let mut found = false;
        for node in ast.root().dfs() {
            if node.is_missing() || node.kind().as_ref() == "ERROR" {
                return false;
            }
            if node.kind().as_ref() == "method_declaration" {
                if !node.field("name").is_some_and(|name| {
                    matches!(name.text().as_ref(), "BuildTargetModel" | "BuildModel")
                }) {
                    return false;
                }
                found = true;
            }
        }
        return found;
    }
    if !generated
        && !ast
            .root()
            .dfs()
            .any(|n| n.kind().as_ref() == "base_list" && n.text().contains("Migration"))
    {
        return false;
    }
    let mut found_method = false;
    for node in ast.root().dfs() {
        if node.is_missing() {
            return false;
        }
        match node.kind().as_ref() {
            "ERROR"
            | "if_statement"
            | "switch_statement"
            | "for_statement"
            | "for_each_statement"
            | "while_statement"
            | "do_statement"
            | "try_statement"
            | "throw_statement"
            | "local_declaration_statement"
            | "assignment_expression"
            | "object_creation_expression" => return false,
            "method_declaration" => {
                let Some(name) = node.field("name") else {
                    return false;
                };
                if !matches!(name.text().as_ref(), "Up" | "Down") {
                    return false;
                }
                found_method = true;
            }
            "invocation_expression" => {
                let Some(function) = node.field("function") else {
                    return false;
                };
                let name = function.text();
                let name = name.trim();
                let migration_call = [
                    "migrationBuilder.AddColumn",
                    "migrationBuilder.AlterColumn",
                    "migrationBuilder.DropColumn",
                    "migrationBuilder.CreateTable",
                    "migrationBuilder.DropTable",
                    "migrationBuilder.RenameTable",
                    "migrationBuilder.RenameColumn",
                    "migrationBuilder.CreateIndex",
                    "migrationBuilder.DropIndex",
                    "migrationBuilder.AddForeignKey",
                    "migrationBuilder.DropForeignKey",
                    "table.Column",
                    "table.PrimaryKey",
                    "table.ForeignKey",
                ]
                .iter()
                .any(|allowed| name == *allowed || name.starts_with(&format!("{allowed}<")));
                let annotation = name.ends_with(".Annotation")
                    && function
                        .dfs()
                        .any(|part| part.kind().as_ref() == "invocation_expression");
                if !(migration_call || annotation) {
                    return false;
                }
            }
            _ => {}
        }
    }
    found_method
}

fn passive_data_shape(file: &SourceFile) -> bool {
    if file.language != Some(Language::Csharp) {
        return false;
    }
    let path = file.path.to_ascii_lowercase();
    let parts: Vec<_> = path.split('/').collect();
    let stem = parts
        .last()
        .unwrap_or(&"")
        .strip_suffix(".cs")
        .unwrap_or("");
    let shape = parts.iter().any(|part| {
        matches!(
            *part,
            "models"
                | "model"
                | "entities"
                | "entity"
                | "dto"
                | "dtos"
                | "settings"
                | "options"
                | "constants"
                | "exceptions"
        )
    }) || [
        "model",
        "entity",
        "dto",
        "settings",
        "options",
        "constants",
        "exception",
    ]
    .iter()
    .any(|suffix| stem.ends_with(suffix));
    let lower = file.source.to_ascii_lowercase();
    if [
        "ivalidatableobject",
        "validationattribute",
        "iserializable",
        "ideserializationcallback",
        "onserializ",
        "ondeserializ",
        "authorizeattribute",
        "validator",
    ]
    .iter()
    .any(|word| lower.contains(word))
    {
        return false;
    }
    let Ok(doc) = StrDoc::try_new(file.source.as_str(), SupportLang::CSharp) else {
        return false;
    };
    let ast = AstGrep::doc(doc);
    let mut has_const = false;
    let mut only_const = true;
    for node in ast.root().dfs() {
        match node.kind().as_ref() {
            "field_declaration" => {
                if node.text().split_whitespace().any(|word| word == "const") {
                    has_const = true;
                } else {
                    only_const = false;
                }
            }
            "property_declaration"
            | "event_declaration"
            | "event_field_declaration"
            | "constructor_declaration" => only_const = false,
            _ => {}
        }
    }
    if !shape && !(has_const && only_const) {
        return false;
    }
    let mut shape_found = false;
    for node in ast.root().dfs() {
        if node.is_missing() {
            return false;
        }
        let kind = node.kind();
        let in_constructor = || {
            node.ancestors()
                .any(|p| p.kind().as_ref() == "constructor_declaration")
        };
        match kind.as_ref() {
            "ERROR"
            | "method_declaration"
            | "destructor_declaration"
            | "event_declaration"
            | "event_field_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "local_function_statement"
            | "arrow_expression_clause"
            | "implicit_object_creation_expression"
            | "anonymous_object_creation_expression"
            | "if_statement"
            | "switch_statement"
            | "for_statement"
            | "for_each_statement"
            | "while_statement"
            | "do_statement"
            | "try_statement"
            | "throw_statement"
            | "await_expression"
            | "lambda_expression"
            | "binary_expression"
            | "conditional_expression"
            | "element_access_expression" => return false,
            "invocation_expression" => {
                if !node
                    .field("function")
                    .is_some_and(|function| function.text() == "nameof")
                {
                    return false;
                }
            }
            "object_creation_expression" => {
                let compact: String = node.text().chars().filter(|c| !c.is_whitespace()).collect();
                let candidate = compact
                    .strip_prefix("new")
                    .unwrap_or("")
                    .strip_prefix("System.Collections.Generic.")
                    .unwrap_or_else(|| compact.strip_prefix("new").unwrap_or(""));
                if !(candidate.ends_with(">()")
                    && ["List<", "HashSet<", "Dictionary<"]
                        .iter()
                        .any(|prefix| candidate.starts_with(prefix)))
                {
                    return false;
                }
            }
            "constructor_initializer" => {
                if !node.text().trim_start().starts_with(": base(")
                    || node.dfs().any(|child| {
                        matches!(
                            child.kind().as_ref(),
                            "identifier"
                                | "member_access_expression"
                                | "invocation_expression"
                                | "object_creation_expression"
                                | "binary_expression"
                                | "conditional_expression"
                        )
                    })
                {
                    return false;
                }
            }
            "class_declaration" | "record_declaration" | "struct_declaration" => shape_found = true,
            "attribute"
                if node.text().to_ascii_lowercase().contains("authoriz")
                    || node.text().to_ascii_lowercase().contains("permission") =>
            {
                return false;
            }
            "block" if !in_constructor() => return false,
            "assignment_expression" => {
                if node
                    .ancestors()
                    .any(|parent| parent.kind().as_ref() == "attribute")
                {
                    continue;
                }
                if !in_constructor() {
                    return false;
                }
                let (Some(left), Some(right)) = (node.field("left"), node.field("right")) else {
                    return false;
                };
                if !matches!(
                    left.kind().as_ref(),
                    "identifier" | "member_access_expression"
                ) || !matches!(
                    right.kind().as_ref(),
                    "identifier"
                        | "member_access_expression"
                        | "null_literal"
                        | "string_literal"
                        | "integer_literal"
                        | "boolean_literal"
                ) {
                    return false;
                }
                let text = left.text();
                if left.kind().as_ref() == "member_access_expression" && !text.starts_with("this.")
                {
                    return false;
                }
                let expression = node.text();
                if !expression
                    .strip_prefix(text.as_ref())
                    .and_then(|s| s.strip_suffix(right.text().as_ref()))
                    .is_some_and(|operator| operator.trim() == "=")
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    shape_found
}

fn passive_entity_mapping(file: &SourceFile) -> bool {
    if file.language != Some(Language::Csharp) || !file.source.contains("IEntityTypeConfiguration")
    {
        return false;
    }
    let Ok(doc) = StrDoc::try_new(file.source.as_str(), SupportLang::CSharp) else {
        return false;
    };
    let ast = AstGrep::doc(doc);
    let mut configure = false;
    for node in ast.root().dfs() {
        if node.is_missing() {
            return false;
        }
        match node.kind().as_ref() {
            "ERROR"
            | "if_statement"
            | "switch_statement"
            | "for_statement"
            | "for_each_statement"
            | "while_statement"
            | "do_statement"
            | "try_statement"
            | "throw_statement"
            | "assignment_expression"
            | "object_creation_expression"
            | "implicit_object_creation_expression"
            | "local_declaration_statement" => return false,
            "method_declaration" => {
                if !node
                    .field("name")
                    .is_some_and(|name| name.text() == "Configure")
                {
                    return false;
                }
                configure = true;
            }
            "invocation_expression" => {
                let Some(function) = node.field("function") else {
                    return false;
                };
                if function.text() == "nameof" {
                    continue;
                }
                let Some(name) = function.field("name") else {
                    return false;
                };
                let name = name.text();
                if !matches!(
                    name.split('<').next().unwrap_or(""),
                    "ToTable"
                        | "HasKey"
                        | "HasIndex"
                        | "Property"
                        | "HasColumnName"
                        | "HasColumnType"
                        | "HasMaxLength"
                        | "IsRequired"
                        | "IsUnique"
                        | "HasDatabaseName"
                        | "HasName"
                        | "HasAnnotation"
                        | "HasDefaultValue"
                        | "HasDefaultValueSql"
                        | "HasPrecision"
                        | "IsUnicode"
                        | "ValueGeneratedOnAdd"
                        | "ValueGeneratedNever"
                        | "HasOne"
                        | "WithMany"
                        | "WithOne"
                        | "HasForeignKey"
                        | "HasPrincipalKey"
                        | "OnDelete"
                        | "HasConstraintName"
                        | "Navigation"
                        | "HasCheckConstraint"
                        | "IsDescending"
                        | "HasFilter"
                ) {
                    return false;
                }
            }
            _ => {}
        }
    }
    configure
}
fn source_window(
    file: &SourceFile,
    first: usize,
    last: usize,
) -> Result<SourceWindow, EngineError> {
    let rows: Vec<_> = file.source.lines().collect();
    if first == 0 || first > last || last > rows.len() || last - first >= 400 {
        return Err(EngineError("invalid source review interval".into()));
    }
    let text = rows[first - 1..last].join("\n");
    if text.len() > 64 * 1024 {
        return Err(EngineError("source review interval exceeds 64 KiB".into()));
    }
    Ok(SourceWindow {
        path: file.path.clone(),
        start_line: first,
        end_line: last,
        source_sha256: format!("{:x}", Sha256::digest(file.source.as_bytes())),
        text,
    })
}

fn supporting_reason(file: &SourceFile, parse_failed: bool) -> Option<&'static str> {
    let parts: Vec<_> = file.path.split('/').map(str::to_ascii_lowercase).collect();
    if parts
        .iter()
        .take(parts.len().saturating_sub(1))
        .any(|part| {
            part.starts_with("seeder")
                || matches!(
                    part.as_str(),
                    "seed"
                        | "seeds"
                        | "seeder"
                        | "seeders"
                        | "seeding"
                        | "benchmark"
                        | "benchmarks"
                        | "perf"
                        | "performance"
                )
        })
    {
        return Some("seed or performance source");
    }
    if file.language != Some(Language::Csharp) || parse_failed {
        return None;
    }
    let document = StrDoc::try_new(file.source.as_str(), SupportLang::CSharp).ok()?;
    let ast = AstGrep::doc(document);
    let root = ast.root();
    let mut declarations = false;
    for node in root.dfs() {
        let kind = node.kind();
        match kind.as_ref() {
            "ERROR"
            | "class_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "delegate_declaration"
            | "global_statement"
            | "block"
            | "arrow_expression_clause"
            | "field_declaration"
            | "invocation_expression"
            | "object_creation_expression"
            | "assignment_expression" => return None,
            "interface_declaration" | "enum_declaration" => declarations = true,
            "equals_value_clause"
                if !node
                    .ancestors()
                    .any(|parent| parent.kind().as_ref() == "enum_member_declaration") =>
            {
                return None;
            }
            _ => {}
        }
        if node.is_missing() {
            return None;
        }
    }
    declarations.then_some("declaration-only C# interfaces and enums")
}

pub fn plan(root: &Path, inventory: &ReviewInventory, ids: &[String]) -> Result<Plan, EngineError> {
    plan_with_options(root, inventory, ids, false)
}

pub fn plan_with_options(
    root: &Path,
    inventory: &ReviewInventory,
    ids: &[String],
    include_supporting_source: bool,
) -> Result<Plan, EngineError> {
    validate_review_inventory_for_collection(root, inventory)?;
    let sources = RepositorySources::load(root)?;
    let requested: BTreeSet<_> = ids.iter().collect();
    if requested
        .iter()
        .any(|id| !inventory.entries.iter().any(|e| &e.review_id == *id))
    {
        return Err(EngineError("unknown source assignment claim".into()));
    }
    let scope = inventory.scan.impact_scope.as_ref();
    let mut assignments = Vec::new();
    let mut pending: Vec<SourceWindow> = Vec::new();
    let mut directory = String::new();
    let mut bytes = 0;
    let mut limitations = Vec::new();
    let mut excluded_sources = Vec::new();
    let parse_failed_files: BTreeSet<_> = inventory
        .scan
        .coverage
        .files
        .iter()
        .filter(|file| file.status == mehscan_core::FileStatus::ParseFailed)
        .map(|file| file.path.as_str())
        .collect();
    let flush = |pending: &mut Vec<SourceWindow>,
                 assignments: &mut Vec<Assignment>|
     -> Result<(), EngineError> {
        if pending.is_empty() {
            return Ok(());
        }
        let review_ids = inventory
            .entries
            .iter()
            .filter(|e| {
                requested.contains(&e.review_id)
                    && pending
                        .iter()
                        .any(|w| w.path == e.path && w.start_line <= e.line && e.line <= w.end_line)
            })
            .map(|e| e.review_id.clone())
            .collect();
        let windows = std::mem::take(pending);
        assignments.push(Assignment {
            id: hash(&windows)?,
            windows,
            review_ids,
        });
        Ok(())
    };
    for file in sources.files.values() {
        if scope.is_some_and(|s| {
            !s.changed_files.iter().any(|c| c.path == file.path)
                && !s.included_files.iter().any(|c| c.path == file.path)
        }) {
            continue;
        }
        let is_migration = migration_path(&file.path);
        let generated_path = file.path.to_ascii_lowercase().ends_with(".designer.cs")
            || file.path.to_ascii_lowercase().ends_with("modelsnapshot.cs");
        let sql = file.path.to_ascii_lowercase().ends_with(".sql");
        if (is_migration || sql || generated_path) && nonproduction_without_migrations(&file.path) {
            continue;
        }
        let schema_only = (is_migration || generated_path) && schema_migration(file);
        let reason = if sql {
            Some("SQL source available by targeted lookup")
        } else if schema_only {
            Some("schema-only migration available by targeted lookup")
        } else if eligible(file) && passive_entity_mapping(file) {
            Some("schema-only entity mapping available by targeted lookup")
        } else if !include_supporting_source && eligible(file) {
            supporting_reason(file, parse_failed_files.contains(file.path.as_str())).or_else(|| {
                passive_data_shape(file)
                    .then_some("passive C# data shape available by targeted lookup")
            })
        } else {
            None
        };
        if let Some(reason) = reason {
            let review_ids = inventory
                .entries
                .iter()
                .filter(|e| requested.contains(&e.review_id) && e.path == file.path)
                .map(|e| e.review_id.clone())
                .collect();
            excluded_sources.push(ExcludedSource {
                path: file.path.clone(),
                reason: reason.into(),
                review_ids,
                source_sha256: format!("{:x}", Sha256::digest(file.source.as_bytes())),
                line_count: file.source.lines().count(),
            });
            continue;
        }
        if !eligible(file) && !(is_migration && file.path.to_ascii_lowercase().ends_with(".cs")) {
            continue;
        }
        if parse_failed_files.contains(file.path.as_str()) {
            limitations.push(format!(
                "{}: native scanning reported incomplete parsing; source remains assigned. Use exact source reads and scoped text references if AST navigation fails.",
                file.path
            ));
        }
        let parent = file.path.rsplit_once('/').map_or("", |p| p.0);
        let rows: Vec<_> = file.source.lines().collect();
        let mut first = 1;
        while first <= rows.len() {
            let mut last = first;
            let mut size = rows[first - 1].len();
            if size > MAX_WINDOW_BYTES {
                limitations.push(format!(
                    "{}:{first}: line exceeds source assignment budget",
                    file.path
                ));
                first += 1;
                continue;
            }
            while last < rows.len()
                && last - first < 399
                && size + rows[last].len() + 1 <= MAX_WINDOW_BYTES
            {
                size += rows[last].len() + 1;
                last += 1;
            }
            if directory != parent || bytes + size > MAX_WINDOW_BYTES || pending.len() >= 8 {
                flush(&mut pending, &mut assignments)?;
                bytes = 0;
                directory = parent.into();
            }
            pending.push(source_window(file, first, last)?);
            bytes += size;
            first = last + 1;
        }
    }
    flush(&mut pending, &mut assignments)?;
    for id in ids {
        if !assignments.iter().any(|a| a.review_ids.contains(id))
            && !excluded_sources.iter().any(|e| e.review_ids.contains(id))
        {
            limitations.push(format!(
                "native claim {id} has no eligible source assignment; retain native review"
            ));
        }
    }
    let mut selected_review_ids = ids.to_vec();
    selected_review_ids.sort();
    selected_review_ids.dedup();
    let mut plan = Plan {
        schema_version: "1".into(),
        source_fingerprint: inventory.source_fingerprint.clone(),
        selected_review_ids,
        include_supporting_source,
        excluded_sources,
        inventory_fingerprint: inventory.input_fingerprint()?,
        assignments,
        limitations,
        plan_id: String::new(),
    };
    plan.plan_id = hash(&plan)?;
    Ok(plan)
}

fn validate_window(window: &SourceWindow, sources: &RepositorySources) -> Result<(), EngineError> {
    let original = source_window(
        sources.file(&window.path)?,
        window.start_line,
        window.end_line,
    )?;
    if &original != window {
        return Err(EngineError(
            "source review source changed or window was fabricated".into(),
        ));
    }
    Ok(())
}

fn load_delivered_text(
    root: &Path,
    sources: &mut RepositorySources,
    windows: &[SourceWindow],
) -> Result<(), EngineError> {
    for window in windows {
        if !sources.files.contains_key(&window.path) {
            let (_, file) = read_text_source_file(root, &window.path)?;
            if file.path != window.path {
                return Err(EngineError(
                    "source dependency path is not canonical".into(),
                ));
            }
            sources.files.insert(file.path.clone(), file);
        }
        validate_window(window, sources)?;
    }
    Ok(())
}
fn validate_citation(c: &Citation, visible: &[&SourceWindow]) -> Result<(), EngineError> {
    if c.quote.trim().is_empty()
        || c.quote.len() > MAX_SOURCE_BYTES
        || c.start_line == 0
        || c.end_line < c.start_line
        || c.end_line - c.start_line >= MAX_SOURCE_LINES
    {
        return Err(EngineError(
            "source question requires a bounded nonempty citation".into(),
        ));
    }
    let mut lines = BTreeMap::new();
    for window in visible.iter().filter(|w| w.path == c.path) {
        for (offset, line) in window.text.split('\n').enumerate() {
            let number = window.start_line + offset;
            if c.start_line <= number && number <= c.end_line {
                lines.insert(number, line);
            }
        }
    }
    let text = (c.start_line..=c.end_line)
        .map(|line| lines.get(&line).copied())
        .collect::<Option<Vec<_>>>()
        .map(|rows| rows.join("\n"));
    let valid = text.is_some_and(|text| text.contains(&c.quote.replace("\r\n", "\n")));
    if !valid {
        return Err(EngineError(
            "source question cites unseen or mismatched source".into(),
        ));
    }
    Ok(())
}
fn question_evidence(
    question: &Proposal,
    sources: &RepositorySources,
) -> Result<Evidence, EngineError> {
    for value in [
        &question.key,
        &question.question,
        &question.mechanism,
        &question.consequence,
    ] {
        if value.trim().is_empty() || value.len() > 1600 || value.contains('\0') {
            return Err(EngineError(
                "source question lacks a bounded mechanism, consequence or question".into(),
            ));
        }
    }
    if question.cwes.is_empty()
        || question.cwes.len() > 5
        || question.cwes.iter().any(|c| {
            !c.strip_prefix("CWE-").is_some_and(|v| {
                !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && !v.starts_with('0')
            })
        })
        || !matches!(question.priority.as_str(), "value" | "comprehensive")
    {
        return Err(EngineError("invalid source question classification".into()));
    }
    let file = sources.file(&question.anchor.path)?;
    // Validate again when loading a saved inventory, before line arithmetic.
    let window = source_window(file, question.anchor.start_line, question.anchor.end_line)?;
    validate_citation(&question.anchor, &[&window])?;
    for citation in &question.evidence {
        let file = sources.file(&citation.path)?;
        let window = source_window(file, citation.start_line, citation.end_line)?;
        validate_citation(citation, &[&window])?;
    }
    let lines: Vec<_> = file.source.split_inclusive('\n').collect();
    let start = lines
        .iter()
        .take(question.anchor.start_line - 1)
        .map(|s| s.len())
        .sum();
    let end = lines
        .iter()
        .take(question.anchor.end_line)
        .map(|s| s.len())
        .sum();
    let location = location_from_offsets(&file.path, &file.source, start, end);
    // Identity describes a question at an operation, not a shared-file verdict.
    let id = format!(
        "ev-model-{}",
        hash(&(
            question.capability,
            &question.cwes,
            &question.question,
            &location
        ))?
    );
    Ok(Evidence {
        enclosing_symbol: Some(format!("source question {id}")),
        id,
        kind: EvidenceKind::SensitiveOperation,
        capability: question.capability,
        location: location.clone(),
        captures: BTreeMap::from([(
            "operation".into(),
            Capture {
                text: file.source[start..end].into(),
                location: location.clone(),
            },
        )]),
        cwe_candidates: question.cwes.clone(),
        tags: vec![
            "model-discovered-question".into(),
            format!("source-review-priority:{}", question.priority),
        ],
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Textual,
            engine: "mehscan source-validated model question 1".into(),
            rule_version: 1,
        },
        context: EvidenceContext {
            operand_facts: vec![mehscan_core::OperandFact {
                role: "discovery_question".into(),
                kind: mehscan_core::OperandFactKind::OperandBoundary,
                location,
                value: question.question.clone(),
                remaining_checks: vec![
                    "model_proposal_not_native_flow_proof".into(),
                    question.mechanism.clone(),
                    question.consequence.clone(),
                ],
            }],
            ..Default::default()
        },
        symbol_resolution: None,
        rule_id: MODEL_RULE.into(),
        related_evidence: vec![],
    })
}

pub fn validate_admission(
    root: &Path,
    base: &ReviewInventory,
    input: &Admission,
) -> Result<Vec<Evidence>, EngineError> {
    validate_review_inventory_for_collection(root, base)?;
    let expected = plan_with_options(
        root,
        base,
        &input.plan.selected_review_ids,
        input.plan.include_supporting_source,
    )?;
    if input.plan != expected {
        return Err(EngineError("source plan is stale or altered".into()));
    }
    let mut sources = RepositorySources::load(root)?;
    load_delivered_text(root, &mut sources, &input.inspected)?;
    for w in input
        .plan
        .assignments
        .iter()
        .flat_map(|a| &a.windows)
        .chain(&input.inspected)
    {
        validate_window(w, &sources)?;
    }
    let all_visible: Vec<_> = input
        .plan
        .assignments
        .iter()
        .flat_map(|a| a.windows.iter())
        .chain(&input.inspected)
        .collect();
    for citation in &input.assessment_evidence {
        validate_citation(citation, &all_visible)?;
    }
    if input.proposals.len() > 1000 {
        return Err(EngineError("too many source questions".into()));
    }
    let mut evidence_items = Vec::new();
    let mut keys = BTreeSet::new();
    for q in &input.proposals {
        let assignment = input
            .plan
            .assignments
            .iter()
            .find(|a| a.id == q.assignment_id)
            .ok_or_else(|| EngineError("unknown source assignment".into()))?;
        let assigned: Vec<_> = assignment.windows.iter().collect();
        validate_citation(&q.anchor, &assigned).map_err(|_| {
            EngineError(
                "new source question is outside or mismatches its assigned source range".into(),
            )
        })?;
        let visible: Vec<_> = assignment.windows.iter().chain(&input.inspected).collect();
        validate_citation(&q.anchor, &visible)?;
        if q.evidence.is_empty() || q.evidence.len() > 8 {
            return Err(EngineError(
                "source question requires inspected supporting evidence".into(),
            ));
        }
        for c in &q.evidence {
            validate_citation(c, &visible)?;
        }
        let key = format!("{}:{}", q.assignment_id, q.key);
        if !keys.insert(key) {
            return Err(EngineError("duplicate source proposal key".into()));
        }
        evidence_items.push(question_evidence(q, &sources)?);
    }
    Ok(evidence_items)
}

pub fn admit(
    root: &Path,
    base: &ReviewInventory,
    input: &Admission,
) -> Result<(ReviewInventory, BTreeMap<String, String>), EngineError> {
    let evidence_items = validate_admission(root, base, input)?;
    let sources = RepositorySources::load(root)?;
    let mut scan = base.scan.clone();
    let mut additional_sources = BTreeMap::new();
    for window in base
        .source_inputs
        .as_ref()
        .into_iter()
        .flat_map(|b| &b.additional_sources)
        .chain(&input.inspected)
    {
        if !sources.files.contains_key(&window.path) {
            additional_sources.insert(
                (window.path.clone(), window.start_line, window.end_line),
                window.clone(),
            );
        }
    }
    let mut questions = base
        .source_inputs
        .as_ref()
        .map_or_else(Vec::new, |b| b.questions.clone());
    let mut mapping = BTreeMap::new();
    for (q, evidence) in input.proposals.iter().zip(evidence_items) {
        mapping.insert(
            format!("{}:{}", q.assignment_id, q.key),
            evidence.id.clone(),
        );
        if !scan.evidence.iter().any(|e| e.id == evidence.id) {
            scan.evidence.push(evidence);
            questions.push(q.clone());
        }
    }
    let mut entries = Vec::new();
    let job = build_path_review_jobs_internal(
        root,
        None,
        Some(0),
        0,
        base.include_review_material,
        None,
        Some(scan.clone()),
        None,
        Some(&mut entries),
        Some(sources),
        0,
    )?;
    let mut inventory = ReviewInventory {
        scan,
        entries,
        identity_catalog: job.identity_catalog,
        admission_audit: job.review_coverage.admission_audit,
        source_inputs: Some(Binding {
            source_fingerprint: base.source_fingerprint.clone(),
            questions,
            additional_sources: additional_sources.into_values().collect(),
        }),
        ..base.clone()
    };
    if let Some(catalog) = &base.identity_catalog {
        bind_inventory_repository(
            &mut inventory,
            catalog.repository.repository_key.clone(),
            catalog.repository.source_repository_key.clone(),
        )?;
    }
    for value in mapping.values_mut() {
        *value = inventory
            .entries
            .iter()
            .find(|e| e.identity.as_ref().is_some_and(|i| i.anchor_id == *value))
            .ok_or_else(|| EngineError("source question was not admitted to review".into()))?
            .review_id
            .clone();
    }
    Ok((inventory, mapping))
}

pub(super) fn validate_binding(
    root: &Path,
    inventory: &ReviewInventory,
) -> Result<(), EngineError> {
    if let Some(binding) = &inventory.source_inputs {
        if binding.source_fingerprint != inventory.source_fingerprint {
            return Err(EngineError("source discovery binding changed".into()));
        }
        if binding.questions.is_empty() && binding.additional_sources.is_empty() {
            if inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.rule_id == MODEL_RULE)
            {
                return Err(EngineError(
                    "model question evidence differs from its source binding".into(),
                ));
            }
            return Ok(());
        }
        let mut sources = RepositorySources::load_snapshot(root)?;
        load_delivered_text(root, &mut sources, &binding.additional_sources)?;
        let expected: BTreeMap<_, _> = binding
            .questions
            .iter()
            .map(|q| question_evidence(q, &sources).map(|e| (e.id.clone(), e)))
            .collect::<Result<_, _>>()?;
        let actual: BTreeMap<_, _> = inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.rule_id == MODEL_RULE)
            .map(|e| (e.id.clone(), e.clone()))
            .collect();
        if actual != expected {
            return Err(EngineError(
                "model question evidence differs from its source binding".into(),
            ));
        }
    } else if inventory
        .scan
        .evidence
        .iter()
        .any(|e| e.rule_id == MODEL_RULE)
    {
        return Err(EngineError(
            "model questions require a native source binding".into(),
        ));
    }
    Ok(())
}

pub(super) fn question(items: &[Evidence]) -> Option<String> {
    items
        .iter()
        .find(|e| e.rule_id == MODEL_RULE)
        .and_then(|e| {
            e.context
                .operand_facts
                .iter()
                .find(|f| f.role == "discovery_question")
        })
        .map(|f| f.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("mehscan-evidence-{}-{nonce}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn all_languages_admit_delivered_evidence_with_manifest_context() {
        let fixture = Fixture::new();
        let root = &fixture.0;
        // These are intake tests, not assertions that these functions are unsafe.
        let code = [
            (
                "operation.c",
                "// café",
                "void handle(char *input) { review_operation(input); }",
            ),
            (
                "operation.cpp",
                "// café",
                "void handle(char *input) { review_operation(input); }",
            ),
            (
                "operation.h",
                "// café",
                "void handle(char *input) { review_operation(input); }",
            ),
            (
                "Operation.cs",
                "// café",
                "class Operation { void Handle(string input) { ReviewOperation(input); } }",
            ),
            (
                "Operation.java",
                "// café",
                "class Operation { void handle(String input) { reviewOperation(input); } }",
            ),
            (
                "operation.kt",
                "// café",
                "fun handle(input: String) { reviewOperation(input) }",
            ),
            (
                "operation.js",
                "// café",
                "function handle(input) { reviewOperation(input); }",
            ),
            (
                "operation.ts",
                "// café",
                "function handle(input: string) { reviewOperation(input); }",
            ),
            (
                "operation.tsx",
                "// café",
                "function Handle(input: string) { return <div>{reviewOperation(input)}</div>; }",
            ),
            (
                "operation.py",
                "# café",
                "def handle(value): review_operation(value)",
            ),
            (
                "operation.go",
                "package operation // café",
                "func handle(value string) { reviewOperation(value) }",
            ),
            (
                "operation.rs",
                "// café",
                "fn handle(value: &str) { review_operation(value); }",
            ),
            (
                "operation.php",
                "<?php // café",
                "function handle($value) { reviewOperation($value); }",
            ),
            (
                "Page.razor",
                "@* café *@",
                "@code { void Handle(string input) { ReviewOperation(input); } }",
            ),
            (
                "Page.svelte",
                "<!-- café -->",
                "<script>function handle(value) { reviewOperation(value); }</script>",
            ),
            ("Page.jinja2", "{# café #}", "{{ review_operation(value) }}"),
        ];
        let manifests = [
            (
                "Operation.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
            ),
            ("Directory.Build.props", "<Project />\n"),
            (
                "pom.xml",
                "<project><modelVersion>4.0.0</modelVersion></project>\n",
            ),
            ("build.gradle.kts", "plugins { }\n"),
            ("package.json", "{}\n"),
            ("tsconfig.json", "{}\n"),
            (
                "pyproject.toml",
                "[project]\nname = \"evidence-fixture\"\nversion = \"1.0.0\"\n",
            ),
            ("go.mod", "module example.test/evidence\n"),
            (
                "Cargo.toml",
                "[package]\nname = \"evidence-fixture\"\nversion = \"1.0.0\"\n",
            ),
            ("composer.json", "{}\n"),
            (
                "CMakeLists.txt",
                "cmake_minimum_required(VERSION 3.16)\nproject(evidence)\n",
            ),
            ("compile_commands.json", "[]\n"),
            ("context.reviewdata", "{}\n"),
        ];
        for (name, comment, statement) in code {
            fs::write(root.join(name), format!("{comment}\r\n{statement}\r\n")).unwrap();
        }
        for (name, text) in manifests {
            fs::write(root.join(name), text).unwrap();
        }
        let base = build_review_inventory(root, false).unwrap();
        let plan = plan(root, &base, &[]).unwrap();
        let mut proposals = Vec::new();
        for (name, _, statement) in code {
            let assignment = plan
                .assignments
                .iter()
                .find(|a| a.windows.iter().any(|w| w.path == name))
                .unwrap_or_else(|| panic!("source assignment missing for {name}"));
            let read = get_source(root, name, 2, 2).unwrap();
            assert_eq!(read.results.text.trim_end_matches(['\r', '\n']), statement);
            let anchor = Citation {
                path: name.into(),
                start_line: 2,
                end_line: 2,
                quote: statement.into(),
            };
            proposals.push(Proposal {
                key: name.into(), assignment_id: assignment.id.clone(),
                capability: Capability::Authorization, cwes: vec!["CWE-862".into()],
                question: "Does the relevant actor have authority before this effect?".into(),
                mechanism: "An operation needs its effective check-to-effect relationship reviewed.".into(),
                consequence: "A protected effect may be reachable without the required authority.".into(),
                priority: "value".into(), anchor: anchor.clone(), evidence: vec![anchor],
            });
        }
        let inspected = manifests
            .iter()
            .map(|(name, _)| {
                let (_, file) = read_text_source_file(root, name).unwrap();
                source_window(&file, 1, 1).unwrap()
            })
            .collect::<Vec<_>>();
        for q in &mut proposals {
            q.evidence.push(Citation {
                path: "context.reviewdata".into(),
                start_line: 1,
                end_line: 1,
                quote: "{}".into(),
            });
        }
        let input = Admission {
            plan,
            inspected,
            proposals,
            assessment_evidence: vec![],
        };
        let (inventory, mapping) = admit(root, &base, &input).unwrap();
        assert_eq!(mapping.len(), code.len());
        assert_eq!(mapping.values().collect::<BTreeSet<_>>().len(), code.len());
        validate_review_inventory_for_collection(root, &inventory).unwrap();
        // Even an edit outside the cited first line invalidates its file receipt.
        fs::write(root.join("context.reviewdata"), "{}\nchanged dependency\n").unwrap();
        assert!(validate_review_inventory_for_collection(root, &inventory).is_err());
    }

    #[test]
    fn text_intake_rejects_binary_content_independently_of_extension() {
        let fixture = Fixture::new();
        for name in ["bad.py", "bad.rs", "bad.cs", "bad.ts", "bad.reviewdata"] {
            fs::write(fixture.0.join(name), b"text\0binary\n").unwrap();
            assert!(get_source(&fixture.0, name, 1, 1).is_err(), "{name}");
        }
        let sources = RepositorySources::load(&fixture.0).unwrap();
        assert!(sources.files.is_empty());
    }

    #[test]
    fn supporting_source_classification_is_conservative() {
        let file = |path: &str, source: &str| SourceFile {
            path: path.into(),
            language: Some(Language::Csharp),
            source: source.into(),
        };
        assert!(supporting_reason(&file("src/Contracts.cs", "namespace App; public interface IStore { string Get(int id); } public enum Mode { A = 1, B = 2 }"), false).is_some());
        assert!(
            supporting_reason(
                &file(
                    "src/Contracts.cs",
                    "public interface IStore { int Get() => 1; }"
                ),
                false
            )
            .is_none()
        );
        assert!(
            supporting_reason(
                &file(
                    "src/Contracts.cs",
                    "public interface IStore { int Get() { return 1; } }"
                ),
                false
            )
            .is_none()
        );
        assert!(
            supporting_reason(
                &file(
                    "src/Contracts.cs",
                    "public interface IStore { void Get(); } public class Store { }"
                ),
                false
            )
            .is_none()
        );
        assert!(
            supporting_reason(
                &file(
                    "src/Contracts.cs",
                    "public interface IStore { void Get(); }"
                ),
                true
            )
            .is_none()
        );
        assert!(
            supporting_reason(&file("src/Seeds/Populate.cs", "class Program {}"), false).is_some()
        );
        assert!(
            supporting_reason(
                &file("src/SeederApi/Populate.cs", "class Program {}"),
                false
            )
            .is_some()
        );
        assert!(
            supporting_reason(
                &file(
                    "src/Contracts.cs",
                    "public interface IStore { static readonly string Value = Load(); }"
                ),
                false
            )
            .is_none()
        );
        assert!(
            supporting_reason(
                &file("src/Performance/Measure.cs", "class Program {}"),
                false
            )
            .is_some()
        );
        assert!(
            supporting_reason(
                &file("src/PerformanceService.cs", "class Program {}"),
                false
            )
            .is_none()
        );
    }
}
