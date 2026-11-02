use super::*;

type CsNode<'a> = Node<'a, StrDoc<SupportLang>>;
type ScopeKey = (usize, usize);

struct LocalType {
    qualified: String,
    bases: Vec<String>,
}

/// Syntax navigation only. Type predicates, alias bounds and per-use checks
/// remain in the caller; a matching name alone is never a cached identity.
pub(super) struct SinkIndex<'a> {
    events: BTreeMap<ScopeKey, BTreeMap<String, Vec<CsNode<'a>>>>,
    declarations: BTreeMap<String, Vec<CsNode<'a>>>,
    fields: BTreeMap<ScopeKey, BTreeMap<String, Vec<CsNode<'a>>>>,
    values: BTreeMap<String, Vec<(CsNode<'a>, CsNode<'a>)>>,
    types: BTreeMap<ScopeKey, LocalType>,
    bases: BTreeMap<ScopeKey, Vec<ScopeKey>>,
    members: BTreeMap<ScopeKey, std::collections::BTreeSet<String>>,
}

fn is_type(node: &CsNode<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "class_declaration" | "struct_declaration" | "record_declaration"
    )
}

fn member_type<'a>(node: &CsNode<'a>) -> Option<CsNode<'a>> {
    node.field("type").or_else(|| {
        node.children()
            .find(|node| node.kind().as_ref() == "variable_declaration")
            .and_then(|node| node.field("type"))
    })
}

fn qualified_type(root: &CsNode<'_>, node: &CsNode<'_>) -> String {
    let mut names = node
        .ancestors()
        .filter(|n| {
            is_type(n)
                || matches!(
                    n.kind().as_ref(),
                    "namespace_declaration" | "file_scoped_namespace_declaration"
                )
        })
        .filter_map(|n| n.field("name").map(|name| compact(&name.text())))
        .collect::<Vec<_>>();
    names.reverse();
    if names.is_empty() {
        if let Some(namespace) = root
            .children()
            .find(|n| n.kind().as_ref() == "file_scoped_namespace_declaration")
            .and_then(|n| n.field("name"))
        {
            names.push(compact(&namespace.text()));
        }
    }
    if let Some(name) = node.field("name") {
        names.push(compact(&name.text()));
    }
    names.join(".")
}

fn type_owner(node: &CsNode<'_>) -> Option<ScopeKey> {
    node.ancestors()
        .find(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration" | "struct_declaration" | "record_declaration"
            )
        })
        .map(|node| (node.range().start, node.range().end))
}

impl<'a> SinkIndex<'a> {
    pub(super) fn new(root: &CsNode<'a>) -> Self {
        let mut index = Self {
            events: BTreeMap::new(),
            declarations: BTreeMap::new(),
            fields: BTreeMap::new(),
            values: BTreeMap::new(),
            types: BTreeMap::new(),
            bases: BTreeMap::new(),
            members: BTreeMap::new(),
        };
        for node in root.dfs() {
            if is_type(&node) {
                let bases = node
                    .children()
                    .find(|n| n.kind().as_ref() == "base_list")
                    .into_iter()
                    .flat_map(|n| {
                        n.children()
                            .filter(|n| n.is_named())
                            .map(|n| compact(&n.text()))
                            .collect::<Vec<_>>()
                    })
                    .collect();
                index.types.insert(
                    (node.range().start, node.range().end),
                    LocalType {
                        qualified: qualified_type(root, &node),
                        bases,
                    },
                );
            }
            if matches!(
                node.kind().as_ref(),
                "property_declaration" | "event_declaration" | "method_declaration"
            ) {
                if let (Some(owner), Some(name)) = (type_owner(&node), node.field("name")) {
                    if node.kind().as_ref() == "property_declaration" {
                        index
                            .fields
                            .entry(owner)
                            .or_default()
                            .entry(name.text().into_owned())
                            .or_default()
                            .push(node.clone());
                    }
                    index
                        .members
                        .entry(owner)
                        .or_default()
                        .insert(name.text().into_owned());
                }
            }
            let name = match node.kind().as_ref() {
                "parameter" | "variable_declarator" => node.field("name"),
                "assignment_expression" => node.field("left"),
                _ => continue,
            };
            let Some(name) = name else { continue };
            let name = name.text().trim().to_string();
            if node.kind().as_ref() == "variable_declarator" {
                index
                    .declarations
                    .entry(name.clone())
                    .or_default()
                    .push(node.clone());
                let field = node
                    .parent()
                    .and_then(|n| n.parent())
                    .filter(|n| n.kind().as_ref() == "field_declaration");
                if let Some(field) = field {
                    if let Some(owner) = type_owner(&field) {
                        index.members.entry(owner).or_default().insert(name.clone());
                        index
                            .fields
                            .entry(owner)
                            .or_default()
                            .entry(name)
                            .or_default()
                            .push(field);
                    }
                    continue;
                }
            }
            if node.kind().as_ref() == "variable_declarator" {
                if let Some(value) = node
                    .field("value")
                    .or_else(|| node.children().filter(|child| child.is_named()).last())
                {
                    index
                        .values
                        .entry(name.clone())
                        .or_default()
                        .push((node.clone(), value));
                }
            } else if node.kind().as_ref() == "assignment_expression"
                && assignment_operator(&node) == "="
            {
                if let Some(value) = node.field("right") {
                    index
                        .values
                        .entry(name.clone())
                        .or_default()
                        .push((node.clone(), value));
                }
            }
            let scope = scope_range(&node, root);
            index
                .events
                .entry((scope.start, scope.end))
                .or_default()
                .entry(name)
                .or_default()
                .push(node);
        }
        let mut names = BTreeMap::<String, Vec<ScopeKey>>::new();
        for (key, ty) in &index.types {
            names.entry(ty.qualified.clone()).or_default().push(*key);
        }
        for (key, ty) in &index.types {
            let mut bases = Vec::new();
            for base in &ty.bases {
                // Generic and aliased bases require a richer type contract.
                if base.contains('<') || base.contains("::") && !base.starts_with("global::") {
                    continue;
                }
                let candidates = if let Some(global) = base.strip_prefix("global::") {
                    vec![global.to_string()]
                } else {
                    let mut prefix = ty
                        .qualified
                        .rsplit_once('.')
                        .map_or("", |(prefix, _)| prefix);
                    let mut candidates = Vec::new();
                    while !prefix.is_empty() {
                        candidates.push(format!("{prefix}.{base}"));
                        prefix = prefix.rsplit_once('.').map_or("", |(prefix, _)| prefix);
                    }
                    candidates.push(base.clone());
                    candidates
                };
                for candidate in candidates {
                    if let Some(matches) = names.get(&candidate) {
                        if let [base] = matches.as_slice() {
                            bases.push(*base);
                        }
                        break;
                    }
                }
            }
            index.bases.insert(*key, bases);
        }
        index
    }

    pub(super) fn events(&self, scope: &Range<usize>, name: &str) -> &[CsNode<'a>] {
        self.events
            .get(&(scope.start, scope.end))
            .and_then(|events| events.get(name))
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn field_has_type(
        &self,
        site: &CsNode<'_>,
        name: &str,
        predicate: fn(&str) -> bool,
    ) -> bool {
        let Some(owner) = type_owner(site) else {
            return false;
        };
        let mut level = vec![owner];
        let mut seen = std::collections::BTreeSet::new();
        for depth in 0..8 {
            level.retain(|owner| seen.insert(*owner));
            let found = level
                .iter()
                .filter(|owner| {
                    self.members
                        .get(owner)
                        .is_some_and(|members| members.contains(name))
                })
                .collect::<Vec<_>>();
            if !found.is_empty() {
                let [owner] = found.as_slice() else {
                    return false;
                };
                let Some(fields) = self.fields.get(owner).and_then(|fields| fields.get(name))
                else {
                    return false;
                };
                let [field] = fields.as_slice() else {
                    return false;
                };
                if depth > 0
                    && !field.children().any(|n| {
                        n.kind().as_ref() == "modifier"
                            && matches!(n.text().as_ref(), "protected" | "public" | "internal")
                    })
                {
                    return false;
                }
                return member_type(field).is_some_and(|ty| predicate(ty.text().as_ref()));
            }
            level = level
                .iter()
                .flat_map(|owner| self.bases.get(owner).into_iter().flatten().copied())
                .collect();
            if level.is_empty() {
                break;
            }
        }
        let explicit_this = site
            .field("left")
            .and_then(|left| left.field("expression"))
            .is_some_and(|receiver| receiver.text().trim() == "this");
        if explicit_this {
            return false;
        }
        for outer in site.ancestors().filter(is_type).skip(1) {
            let key = (outer.range().start, outer.range().end);
            if !self
                .members
                .get(&key)
                .is_some_and(|members| members.contains(name))
            {
                continue;
            }
            let Some(fields) = self.fields.get(&key).and_then(|fields| fields.get(name)) else {
                return false;
            };
            let [field] = fields.as_slice() else {
                return false;
            };
            return field
                .children()
                .any(|node| node.kind().as_ref() == "modifier" && node.text() == "static")
                && member_type(field).is_some_and(|ty| predicate(ty.text().as_ref()));
        }
        false
    }

    pub(super) fn declarations_before(
        &self,
        name: &str,
        scope: Range<usize>,
        before: usize,
    ) -> impl Iterator<Item = &CsNode<'a>> {
        let entries = self.declarations.get(name).map_or(&[][..], Vec::as_slice);
        let start = entries.partition_point(|node| node.range().start < scope.start);
        let end = entries.partition_point(|node| node.range().start < before.min(scope.end));
        entries[start..end]
            .iter()
            .filter(move |node| node.range().end <= scope.end)
    }

    pub(super) fn latest_value(
        &self,
        name: &str,
        scope: &Range<usize>,
        before: usize,
    ) -> Option<CsNode<'a>> {
        let entries = self.values.get(name)?;
        let end = entries.partition_point(|(node, _)| node.range().start < before.min(scope.end));
        entries[..end]
            .iter()
            .rev()
            .take_while(|(node, _)| node.range().start >= scope.start)
            .find(|(node, _)| node.range().end <= scope.end)
            .map(|(_, value)| value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;

    #[test]
    fn typed_receivers_keep_fields_locals_aliases_and_sibling_scopes_separate() {
        let ast = SupportLang::CSharp.ast_grep(
            r#"
using System.Data.Common;
using Dapper;
class Other { public void Query(string q) {} }
class Foreign { DbConnection db; }
class Lookalike {
    Other db { get; }
    void F(string q) { db.Query(q); }
}
class Actual {
    DbConnection db;
    void F(string q) { db.Query(q); }
    void Shadow(string q) { var db = Unknown(); db.Query(q); }
    void Alias(string q) { var alias = db; alias.Query(q); }
    void Siblings(string q) {
        { Other db = Unknown(); db.Query(q); }
        db.Query(q);
    }
}
class Empty {
    Other db { get; }
    void F(string q) {
        { DbConnection db = Unknown(); db.Query(q); }
        db.Query(q);
    }
}
class Property { DbConnection db { get; } void F(string q) { db.Query(q); } }
class Base { protected DbConnection inherited; private DbConnection hidden; }
class Derived : Base {
    void Inherited(string q) { inherited.Query(q); }
    void Inaccessible(string q) { hidden.Query(q); }
}
class Hides : Base {
    Other inherited { get; }
    void F(string q) { inherited.Query(q); }
}
class Outer {
    static DbConnection shared;
    DbConnection instance;
    class Inner {
        void F(string q) { shared.Query(q); instance.Query(q); }
    }
}
namespace One {
    class Parent { protected DbConnection scoped; }
    class Child : Parent { void F(string q) { scoped.Query(q); } }
}
namespace Two {
    class Parent { protected Other scoped; }
    class Child : Parent { void F(string q) { scoped.Query(q); } }
}
"#,
        );
        let root = ast.root();
        assert!(!root.dfs().any(|node| node.is_error() || node.is_missing()));
        let index = SinkIndex::new(&root);
        let results: Vec<_> = root
            .dfs()
            .filter(|node| node.kind().as_ref() == "invocation_expression")
            .filter_map(|node| {
                let (receiver, method, _) = typed_instance_call(&node)?;
                (method == "Query")
                    .then(|| receiver_is_database_connection(&root, &index, &node, &receiver))
            })
            .collect();
        assert_eq!(
            results,
            [
                false, true, false, true, false, true, true, false, true, true, false, false, true,
                false, true, false
            ]
        );
    }
}
