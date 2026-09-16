use std::collections::BTreeMap;
use std::ops::Range;

use mehscan_core::{Availability, AvailabilityState, Language};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConditionalRegion {
    range: Range<usize>,
    availability: Availability,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ConditionalRegions {
    regions: Vec<ConditionalRegion>,
}

#[derive(Clone, Debug)]
struct Frame {
    parent: Availability,
    covered: Truth,
    current: Availability,
    branch_start: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Truth {
    True,
    False,
    Unknown,
}

impl ConditionalRegions {
    pub(crate) fn from_source(
        language: Language,
        source: &str,
        build_symbols: &BTreeMap<String, bool>,
    ) -> Self {
        if !matches!(language, Language::C | Language::Cpp | Language::Csharp) {
            return Self::default();
        }
        let mut regions = Vec::new();
        let mut stack: Vec<Frame> = Vec::new();
        for (line_start, line_end) in line_spans(source) {
            let line = source[line_start..line_end].trim();
            let Some(directive) = line.strip_prefix('#').map(str::trim_start) else {
                continue;
            };
            let (name, expression) = split_directive(directive);
            match name {
                "if" | "ifdef" | "ifndef" => {
                    let parent = stack
                        .last()
                        .map(|frame| frame.current.clone())
                        .unwrap_or_else(always);
                    let truth = directive_truth(name, expression, build_symbols);
                    stack.push(Frame {
                        current: combine(&parent, truth, expression),
                        parent,
                        covered: truth,
                        branch_start: line_end,
                    });
                }
                "elif" => {
                    let Some(frame) = stack.last_mut() else {
                        continue;
                    };
                    close_branch(&mut regions, frame, line_start);
                    let condition = evaluate(expression, build_symbols);
                    let eligible = and(not(frame.covered), condition);
                    frame.covered = or(frame.covered, condition);
                    frame.current = combine(&frame.parent, eligible, expression);
                    frame.branch_start = line_end;
                }
                "else" => {
                    let Some(frame) = stack.last_mut() else {
                        continue;
                    };
                    close_branch(&mut regions, frame, line_start);
                    let eligible = not(frame.covered);
                    frame.covered = Truth::True;
                    frame.current = combine(&frame.parent, eligible, "else");
                    frame.branch_start = line_end;
                }
                "endif" => {
                    let Some(frame) = stack.pop() else {
                        continue;
                    };
                    push_region(&mut regions, frame.branch_start..line_start, frame.current);
                }
                _ => {}
            }
        }
        for frame in stack {
            let mut availability = frame.current;
            availability.state = AvailabilityState::Unknown;
            push_region(&mut regions, frame.branch_start..source.len(), availability);
        }
        regions.sort_by_key(|region| (region.range.start, region.range.end));
        Self { regions }
    }

    pub(crate) fn availability_for(&self, range: Range<usize>) -> Availability {
        self.regions
            .iter()
            .filter(|region| contains(&region.range, &range))
            .min_by_key(|region| region.range.end - region.range.start)
            .map(|region| region.availability.clone())
            .unwrap_or_else(always)
    }
}

fn close_branch(regions: &mut Vec<ConditionalRegion>, frame: &Frame, end: usize) {
    push_region(regions, frame.branch_start..end, frame.current.clone());
}

fn push_region(
    regions: &mut Vec<ConditionalRegion>,
    range: Range<usize>,
    availability: Availability,
) {
    if range.start < range.end {
        regions.push(ConditionalRegion {
            range,
            availability,
        });
    }
}

fn combine(parent: &Availability, truth: Truth, condition: &str) -> Availability {
    let condition = condition.trim();
    let child_condition = (!condition.is_empty()).then(|| condition.to_string());
    match parent.state {
        AvailabilityState::Excluded => parent.clone(),
        AvailabilityState::Unknown => Availability {
            state: AvailabilityState::Unknown,
            condition: join_conditions(parent.condition.as_deref(), child_condition.as_deref()),
        },
        AvailabilityState::Conditional => match truth {
            Truth::False => Availability {
                state: AvailabilityState::Excluded,
                condition: join_conditions(parent.condition.as_deref(), child_condition.as_deref()),
            },
            Truth::True | Truth::Unknown => Availability {
                state: AvailabilityState::Conditional,
                condition: join_conditions(parent.condition.as_deref(), child_condition.as_deref()),
            },
        },
        AvailabilityState::Always => Availability {
            state: match truth {
                Truth::True => AvailabilityState::Always,
                Truth::False => AvailabilityState::Excluded,
                Truth::Unknown => AvailabilityState::Conditional,
            },
            condition: child_condition,
        },
    }
}

fn directive_truth(name: &str, expression: &str, build_symbols: &BTreeMap<String, bool>) -> Truth {
    match name {
        "ifdef" => symbol_truth(expression, build_symbols),
        "ifndef" => not(symbol_truth(expression, build_symbols)),
        _ => evaluate(expression, build_symbols),
    }
}

fn evaluate(expression: &str, build_symbols: &BTreeMap<String, bool>) -> Truth {
    let mut expression = expression.trim();
    while expression.starts_with('(') && expression.ends_with(')') && expression.len() >= 2 {
        expression = expression[1..expression.len() - 1].trim();
    }
    if let Some(inner) = expression.strip_prefix('!') {
        return not(evaluate(inner, build_symbols));
    }
    match expression {
        "true" | "True" | "1" => Truth::True,
        "false" | "False" | "0" => Truth::False,
        _ => symbol_truth(expression, build_symbols),
    }
}

fn symbol_truth(symbol: &str, build_symbols: &BTreeMap<String, bool>) -> Truth {
    let symbol = symbol.trim();
    let symbol = symbol
        .strip_prefix("defined(")
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(symbol)
        .trim();
    match build_symbols.get(symbol) {
        Some(true) => Truth::True,
        Some(false) => Truth::False,
        None => Truth::Unknown,
    }
}

fn and(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Unknown,
    }
}

fn or(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Unknown,
    }
}

fn not(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
    }
}

fn always() -> Availability {
    Availability {
        state: AvailabilityState::Always,
        condition: None,
    }
}

fn join_conditions(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(format!("({left}) && ({right})")),
        (Some(value), None) | (None, Some(value)) => Some(value.to_string()),
        (None, None) => None,
    }
}

fn contains(outer: &Range<usize>, inner: &Range<usize>) -> bool {
    outer.start <= inner.start && outer.end >= inner.end
}

fn split_directive(directive: &str) -> (&str, &str) {
    directive
        .split_once(char::is_whitespace)
        .map_or((directive, ""), |(name, expression)| {
            (name, expression.trim())
        })
}

fn line_spans(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            spans.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < source.len() {
        spans.push((start, source.len()));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range_of(source: &str, needle: &str) -> Range<usize> {
        let start = source.find(needle).expect("needle should exist");
        start..start + needle.len()
    }

    #[test]
    fn classifies_known_and_symbol_dependent_regions() {
        let source = "#if false\nexcluded();\n#endif\n#if true\nalways_call();\n#endif\n#if DEBUG\nconditional();\n#endif\n";
        let regions = ConditionalRegions::from_source(Language::Csharp, source, &BTreeMap::new());
        assert_eq!(
            regions.availability_for(range_of(source, "excluded()")),
            Availability {
                state: AvailabilityState::Excluded,
                condition: Some("false".to_string())
            }
        );
        assert_eq!(
            regions
                .availability_for(range_of(source, "always_call()"))
                .state,
            AvailabilityState::Always
        );
        assert_eq!(
            regions.availability_for(range_of(source, "conditional()")),
            Availability {
                state: AvailabilityState::Conditional,
                condition: Some("DEBUG".to_string())
            }
        );
    }

    #[test]
    fn resolves_else_after_known_condition() {
        let source = "#if false\na();\n#else\nb();\n#endif\n";
        let regions = ConditionalRegions::from_source(Language::Csharp, source, &BTreeMap::new());
        assert_eq!(
            regions.availability_for(range_of(source, "a()")).state,
            AvailabilityState::Excluded
        );
        assert_eq!(
            regions.availability_for(range_of(source, "b()")).state,
            AvailabilityState::Always
        );
    }

    #[test]
    fn honors_only_explicitly_supplied_build_symbols() {
        let source = "#if DEBUG\ndebug_call();\n#endif\n";
        let mut symbols = BTreeMap::new();
        symbols.insert("DEBUG".to_string(), true);
        let regions = ConditionalRegions::from_source(Language::Csharp, source, &symbols);
        assert_eq!(
            regions
                .availability_for(range_of(source, "debug_call()"))
                .state,
            AvailabilityState::Always
        );
    }

    #[test]
    fn honors_c_family_ifdef_and_undefine_facts() {
        let source = "#ifdef MAGMA_ENABLE_FIXES\nfixed();\n#else\nvulnerable();\n#endif\n";
        let symbols = BTreeMap::from([("MAGMA_ENABLE_FIXES".to_string(), false)]);
        let regions = ConditionalRegions::from_source(Language::C, source, &symbols);
        assert_eq!(
            regions.availability_for(range_of(source, "fixed()")).state,
            AvailabilityState::Excluded
        );
        assert_eq!(
            regions
                .availability_for(range_of(source, "vulnerable()"))
                .state,
            AvailabilityState::Always
        );
    }
}
