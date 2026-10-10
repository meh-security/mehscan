//! Exact template excerpts with a cooked-string source map, not Angular flow.
use super::*;
use registry::{Declaration, Registry};

pub(super) struct Template {
    pub path: String,
    source: String,
    pub text: String,
    offsets: Vec<usize>,
    pub producer: Option<ReviewNeighborhoodFact>,
}

#[derive(Clone)]
pub(super) struct Binding {
    pub start: usize,
    pub end: usize,
    pub tag: String,
    pub property: String,
    pub expression: String,
}

impl Binding {
    pub fn output(&self) -> bool {
        matches!(
            self.property.to_ascii_lowercase().as_str(),
            "innerhtml"
                | "srcdoc"
                | "href"
                | "src"
                | "attr.href"
                | "attr.src"
                | "style"
                | "style.background-image"
                | "textcontent"
                | "innertext"
                | "text"
        )
    }
}

impl Template {
    pub fn load(
        registry: &Registry,
        sources: &RepositorySources,
        decl: &Declaration,
    ) -> Option<Self> {
        let inline = registry.property(decl, "template");
        let external = registry.property(decl, "templateUrl");
        if inline.is_some() == external.is_some() {
            return None;
        }
        let file = sources.file(&decl.path).ok()?;
        let (mut value, is_external) = inline
            .map(|n| (n, false))
            .or_else(|| external.map(|n| (n, true)))?;
        let mut producer = None;
        if value.kind().as_ref() == "identifier" {
            let name = value.text().to_string();
            let root = registry.documents[&decl.path].root();
            let constants: Vec<_> = root
                .children()
                .flat_map(|n| {
                    if n.kind().as_ref() == "export_statement" {
                        n.children().collect::<Vec<_>>()
                    } else {
                        vec![n]
                    }
                })
                .filter(|n| {
                    n.kind().as_ref() == "lexical_declaration"
                        && n.text().trim_start().starts_with("const ")
                })
                .flat_map(|n| n.children().collect::<Vec<_>>())
                .filter(|n| {
                    n.kind().as_ref() == "variable_declarator"
                        && n.field("name").is_some_and(|n| n.text() == name)
                })
                .collect();
            if constants.len() != 1 {
                return None;
            }
            producer = Some(
                registry::bounded_fact(
                    file,
                    &constants[0],
                    "frontend_template_constant_context",
                    &name,
                )
                .0,
            );
            value = constants[0].field("value")?;
        }
        if is_external {
            let name = static_literal(&value)?;
            let (path, source) = external_template(sources, &decl.path, &name)?;
            let offsets = (0..=source.len()).collect();
            return Some(Self {
                path,
                text: source.clone(),
                source,
                offsets,
                producer,
            });
        }
        if !matches!(value.kind().as_ref(), "string" | "template_string")
            || !valid(&value)
            || value
                .dfs()
                .any(|n| n.kind().as_ref() == "template_substitution")
        {
            return None;
        }
        let raw = value.text();
        let (text, offsets) = cook(&raw[1..raw.len() - 1], value.range().start + 1)?;
        Some(Self {
            path: decl.path.clone(),
            source: file.source.clone(),
            text,
            offsets,
            producer,
        })
    }

    pub fn fact(
        &self,
        start: usize,
        end: usize,
        role: &str,
        name: &str,
    ) -> Option<ReviewNeighborhoodFact> {
        let start = *self.offsets.get(start)?;
        let end = *self.offsets.get(end)?;
        if end < start || end - start > MAX_FACT_BYTES {
            return None;
        }
        Some(ReviewNeighborhoodFact {
            role: role.into(),
            symbol: name.into(),
            location: location_from_offsets(&self.path, &self.source, start, end),
            excerpt: self.source[start..end].into(),
            evidence_id: None,
            provenance: textual_provenance(
                "explicit Angular template; source-mapped bounded navigation, not reaching-value, actor or sanitization proof 2",
            ),
        })
    }

    pub fn bindings(&self) -> Vec<Binding> {
        bindings(&self.text)
    }

    pub fn aliases(&self, names: &BTreeSet<String>) -> Vec<(String, ReviewNeighborhoodFact)> {
        let mut result = Vec::new();
        let mut position = 0;
        while position < self.text.len() {
            let tail = &self.text[position..];
            // Declarations inside comments, quoted attributes or interpolated
            // strings are not template aliases.
            if tail.starts_with("<!--") {
                position += tail.find("-->").map_or(tail.len(), |n| n + 3);
                continue;
            }
            if tail.starts_with('<')
                && let Some(end) = tag_end(&self.text, position)
            {
                position = end;
                continue;
            }
            if tail.starts_with("{{") {
                position += tail.find("}}").map_or(tail.len(), |n| n + 2);
                continue;
            }
            let start = position;
            position += tail.chars().next().unwrap().len_utf8();
            if !tail.starts_with("@let ") {
                continue;
            }
            let Some(length) = self.text[start..].find(';') else {
                continue;
            };
            let end = start + length + 1;
            position = end;
            let statement = &self.text[start + 5..end - 1];
            let Some((name, expression)) = statement.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if is_plain_identifier(name)
                && names.iter().any(|n| mentions_binding(expression, n))
                && let Some(fact) = self.fact(start, end, "frontend_template_alias_context", name)
            {
                result.push((name.into(), fact));
            }
        }
        result
    }
}

// Map each decoded byte back to its actual source character. All supplied
// excerpts remain original code, including escapes; no synthesized HTML.
fn cook(raw: &str, base: usize) -> Option<(String, Vec<usize>)> {
    let mut text = String::new();
    let mut offsets = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let start = i;
        let mut ch = raw[i..].chars().next()?;
        i += ch.len_utf8();
        if ch == '\\' {
            ch = raw[i..].chars().next()?;
            i += ch.len_utf8();
            ch = match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\'' | '"' | '`' | '\\' => ch,
                '\n' => continue,
                'u' | 'x' => {
                    let digits = if ch == 'u' { 4 } else { 2 };
                    let end = i + digits;
                    let code = u32::from_str_radix(raw.get(i..end)?, 16).ok()?;
                    i = end;
                    char::from_u32(code)?
                }
                _ => return None,
            };
        }
        offsets.extend(std::iter::repeat_n(base + start, ch.len_utf8()));
        text.push(ch);
    }
    offsets.push(base + raw.len());
    Some((text, offsets))
}

pub(super) fn pipe_names(expression: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut quote = None;
    let chars: Vec<_> = expression.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(delimiter) = quote {
            if ch == '\\' {
                i += 1
            } else if ch == delimiter {
                quote = None
            }
        } else if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch)
        } else if ch == '|'
            && chars.get(i + 1) != Some(&'|')
            && i.checked_sub(1).and_then(|p| chars.get(p)) != Some(&'|')
        {
            i += 1;
            while chars.get(i).is_some_and(|c| c.is_whitespace()) {
                i += 1
            }
            let start = i;
            while chars
                .get(i)
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$'))
            {
                i += 1
            }
            let name: String = chars[start..i].iter().collect();
            if is_plain_identifier(&name) {
                names.insert(name);
            }
            continue;
        }
        i += 1;
    }
    names
}

pub(super) fn bindings(source: &str) -> Vec<Binding> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if source[i..].starts_with("<!--") {
            i = source[i + 4..]
                .find("-->")
                .map_or(bytes.len(), |n| i + 4 + n + 3);
            continue;
        }
        if source[i..].starts_with("{{") {
            if let Some(n) = source[i + 2..].find("}}") {
                let end = i + 2 + n + 2;
                result.push(Binding {
                    start: i,
                    end,
                    tag: String::new(),
                    property: "text".into(),
                    expression: source[i + 2..end - 2].into(),
                });
                i = end;
                continue;
            }
        }
        if bytes[i] != b'<' {
            i += source[i..].chars().next().unwrap().len_utf8();
            continue;
        }
        let start = i;
        i += 1;
        let name_start = i;
        while bytes
            .get(i)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b':' | b'_'))
        {
            i += 1
        }
        if i == name_start {
            continue;
        }
        let tag = source[name_start..i].to_string();
        let Some(end) = tag_end(source, start) else {
            break;
        };
        while i < end {
            if matches!(bytes[i], b'\'' | b'"') {
                let quote = bytes[i];
                i += 1;
                while i < end && bytes[i] != quote {
                    i += 1
                }
                i += usize::from(i < end);
                continue;
            }
            if bytes[i] != b'[' || i == 0 || !bytes[i - 1].is_ascii_whitespace() {
                i += source[i..].chars().next().unwrap().len_utf8();
                continue;
            }
            let Some(close) = source[i..end].find(']') else {
                break;
            };
            let property = source[i + 1..i + close].to_string();
            i += close + 1;
            while i < end && bytes[i].is_ascii_whitespace() {
                i += 1
            }
            if bytes.get(i) != Some(&b'=') {
                continue;
            }
            i += 1;
            while i < end && bytes[i].is_ascii_whitespace() {
                i += 1
            }
            if !matches!(bytes.get(i), Some(b'\'' | b'"')) {
                continue;
            }
            let quote = bytes[i];
            i += 1;
            let value_start = i;
            while i < end && bytes[i] != quote {
                i += 1
            }
            if i == end {
                break;
            }
            result.push(Binding {
                start,
                end,
                tag: tag.clone(),
                property,
                expression: source[value_start..i].into(),
            });
            i += 1;
        }
        i = end;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinguishes_pipes_from_strings_and_boolean_or() {
        assert_eq!(
            pipe_names("a || b | trust: 'x|fake' | encode"),
            BTreeSet::from(["trust".into(), "encode".into()])
        );
        assert!(pipe_names("'content | trust' || value").is_empty());
    }
    #[test]
    fn maps_cooked_unicode_and_quotes_to_original_source() {
        let raw = r#"é<div [innerHTML]=\"html\"></div>"#;
        let (text, offsets) = cook(raw, 0).unwrap();
        let binding = &bindings(&text)[0];
        assert_eq!(
            &raw[offsets[binding.start]..offsets[binding.end]],
            r#"<div [innerHTML]=\"html\">"#
        );
        assert_eq!(cook(r#"\u00e9\n"#, 10).unwrap().0, "é\n");
    }
}
