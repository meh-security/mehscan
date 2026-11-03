use super::*;
use std::ops::Range;

type Region = (Range<usize>, mehscan_core::SourceConfiguration);

struct Regions {
    items: Vec<Region>,
    max_ends: Vec<usize>,
}

impl Regions {
    fn new(mut items: Vec<Region>) -> Self {
        items.sort_by_key(|(range, _)| (range.start, std::cmp::Reverse(range.end)));
        let mut max_ends = vec![0; items.len()];
        fn prepare(items: &[Region], max_ends: &mut [usize], lo: usize, hi: usize) -> usize {
            if lo == hi {
                return 0;
            }
            let middle = (lo + hi) / 2;
            let end = items[middle]
                .0
                .end
                .max(prepare(items, max_ends, lo, middle))
                .max(prepare(items, max_ends, middle + 1, hi));
            max_ends[middle] = end;
            end
        }
        prepare(&items, &mut max_ends, 0, items.len());
        Self { items, max_ends }
    }

    fn containing(&self, range: Range<usize>) -> Containing<'_> {
        Containing {
            regions: self,
            range,
            pending: vec![(0, self.items.len())],
        }
    }
}

struct Containing<'a> {
    regions: &'a Regions,
    range: Range<usize>,
    pending: Vec<(usize, usize)>,
}

impl<'a> Iterator for Containing<'a> {
    type Item = (usize, &'a mehscan_core::SourceConfiguration);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((lo, hi)) = self.pending.pop() {
            if lo == hi {
                continue;
            }
            let middle = (lo + hi) / 2;
            if self.regions.max_ends[middle] < self.range.end {
                continue;
            }
            let (region, configuration) = &self.regions.items[middle];
            if region.start <= self.range.start {
                self.pending.push((middle + 1, hi));
            }
            self.pending.push((lo, middle));
            if region.start <= self.range.start && self.range.end <= region.end {
                return Some((middle, configuration));
            }
        }
        None
    }
}

#[derive(Default)]
pub(super) struct Selection {
    files: BTreeMap<String, mehscan_core::SourceConfiguration>,
    regions: BTreeMap<String, Regions>,
}

impl Selection {
    pub(super) fn build(
        sources: &RepositorySources,
        files: &BTreeMap<String, mehscan_core::SourceConfiguration>,
        include_tests: bool,
    ) -> Self {
        let mut selection = Self {
            files: files.clone(),
            ..Self::default()
        };
        for file in sources.files.values().filter(|file| {
            file.language == Some(Language::Rust)
                && file.source.len() <= MAX_REVIEW_CONTEXT_INDEX_FILE_BYTES
        }) {
            if selection.excluded_file(&file.path) {
                continue;
            }
            let regions =
                crate::code::rust_modules::review_regions(&file.path, &file.source, include_tests);
            if !regions.is_empty() {
                selection
                    .regions
                    .insert(file.path.clone(), Regions::new(regions));
            }
        }
        selection
    }

    pub(super) fn excluded_file(&self, path: &str) -> bool {
        self.files.get(path).is_some_and(|configuration| {
            configuration.availability.state == mehscan_core::AvailabilityState::Excluded
        })
    }

    pub(super) fn excluded(&self, path: &str, range: Range<usize>) -> bool {
        self.excluded_file(path)
            || self.regions.get(path).is_some_and(|regions| {
                regions.containing(range).any(|(_, configuration)| {
                    configuration.availability.state == mehscan_core::AvailabilityState::Excluded
                })
            })
    }

    pub(super) fn annotate(&self, fact: &mut Evidence) {
        let mut locations = vec![(fact.location.clone(), true)];
        locations.extend(fact.captures.iter().map(|(role, capture)| {
            // Supplementary revocation leads do not gate the exchange chain.
            let required = !role.starts_with("security_state_writer")
                && !role.starts_with("security_state_caller");
            (capture.location.clone(), required)
        }));
        let mut files = BTreeSet::new();
        let mut applied = BTreeSet::new();
        for (location, required) in locations {
            if files.insert((location.path.clone(), required)) {
                if let Some(configuration) = self.files.get(&location.path) {
                    apply(configuration, &mut fact.context, required);
                }
            }
            if let Some(regions) = self.regions.get(&location.path) {
                for (index, configuration) in
                    regions.containing(location.start.byte_offset..location.end.byte_offset)
                {
                    if applied.insert((location.path.clone(), index, required)) {
                        apply(configuration, &mut fact.context, required);
                    }
                }
            }
        }
    }
}

fn apply(
    configuration: &mehscan_core::SourceConfiguration,
    context: &mut EvidenceContext,
    required: bool,
) {
    if required {
        configuration.apply_to(context);
    } else {
        mehscan_core::SourceConfiguration {
            availability: mehscan_core::Availability {
                state: mehscan_core::AvailabilityState::Always,
                condition: None,
            },
            dependencies: configuration.dependencies.clone(),
        }
        .apply_to(context);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_regions_match_exhaustive_containment_for_nested_duplicate_and_crossing_ranges() {
        let ranges = [0..5000, 10..50, 20..25, 20..25, 300..600, 400..700]
            .into_iter()
            .chain((0..1024).map(|i| (i * 4)..(i * 4 + 2)));
        let items: Vec<_> = ranges
            .enumerate()
            .map(|(index, range)| {
                (
                    range,
                    mehscan_core::SourceConfiguration {
                        availability: mehscan_core::Availability {
                            state: mehscan_core::AvailabilityState::Conditional,
                            condition: Some(index.to_string()),
                        },
                        dependencies: Vec::new(),
                    },
                )
            })
            .collect();
        let regions = Regions::new(items.clone());
        for start in (0..4200).step_by(7) {
            for length in [0, 1, 4, 32, 257] {
                let end = start + length;
                let mut expected: Vec<_> = items
                    .iter()
                    .filter(|(range, _)| range.start <= start && end <= range.end)
                    .map(|(_, configuration)| configuration.availability.condition.clone())
                    .collect();
                let mut actual: Vec<_> = regions
                    .containing(start..end)
                    .map(|(_, configuration)| configuration.availability.condition.clone())
                    .collect();
                expected.sort();
                actual.sort();
                assert_eq!(actual, expected, "{start}..{end}");
            }
        }
    }
}
