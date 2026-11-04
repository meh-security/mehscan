use std::ops::Range;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct RegionIndex {
    entries: Vec<(Range<usize>, usize)>,
    positions: Vec<usize>,
    max_end: Vec<usize>,
    leaves: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containing_regions_preserve_overlap_ties_boundaries_and_activation_order() {
        let ranges = vec![
            0..100,
            10..20,
            15..25,
            10..20,
            30..40,
            45..55,
            5..95,
            90..110,
        ];
        let mut index = RegionIndex::new(ranges.clone(), 0);
        for active in 0..=ranges.len() {
            for start in 0..=110 {
                for end in start..=110 {
                    let expected = ranges[..active]
                        .iter()
                        .enumerate()
                        .filter(|(_, outer)| outer.start <= start && end <= outer.end)
                        .min_by_key(|(_, outer)| outer.len())
                        .map(|(order, _)| order);
                    assert_eq!(
                        index.containing(start..end),
                        expected,
                        "active={active} query={start}..{end}"
                    );
                }
            }
            if active < ranges.len() {
                index.activate(active);
            }
        }
    }
}

impl RegionIndex {
    /// The topology includes pending Rust ranges, but only the initial prefix
    /// is active. Later attributes must not influence earlier conditions.
    pub(super) fn new(ranges: Vec<Range<usize>>, active: usize) -> Self {
        if ranges.is_empty() {
            return Self::default();
        }
        let mut entries = ranges
            .into_iter()
            .enumerate()
            .map(|(order, range)| (range, order))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(range, order)| (range.start, range.end, *order));
        let leaves = entries.len().next_power_of_two();
        let mut positions = vec![0; entries.len()];
        let mut max_end = vec![0; 2 * leaves];
        for (position, (range, order)) in entries.iter().enumerate() {
            positions[*order] = position;
            if *order < active {
                max_end[leaves + position] = range.end;
            }
        }
        for node in (1..leaves).rev() {
            max_end[node] = max_end[2 * node].max(max_end[2 * node + 1]);
        }
        Self {
            entries,
            positions,
            max_end,
            leaves,
        }
    }

    pub(super) fn activate(&mut self, order: usize) {
        let position = self.positions[order];
        let mut node = self.leaves + position;
        self.max_end[node] = self.entries[position].0.end;
        while node > 1 {
            node /= 2;
            self.max_end[node] = self.max_end[2 * node].max(self.max_end[2 * node + 1]);
        }
    }

    pub(super) fn containing(&self, range: Range<usize>) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let limit = self
            .entries
            .partition_point(|(entry, _)| entry.start <= range.start);
        let mut best = None;
        self.search(1, 0, self.leaves, limit, range.end, &mut best);
        best.map(|(_, order)| order)
    }

    fn search(
        &self,
        node: usize,
        start: usize,
        end: usize,
        limit: usize,
        required_end: usize,
        best: &mut Option<(usize, usize)>,
    ) {
        if start >= limit || self.max_end[node] == 0 || self.max_end[node] < required_end {
            return;
        }
        if end - start == 1 {
            let (range, order) = &self.entries[start];
            let candidate = (range.len(), *order);
            if best.is_none_or(|previous| candidate < previous) {
                *best = Some(candidate);
            }
            return;
        }
        let middle = start + (end - start) / 2;
        self.search(2 * node, start, middle, limit, required_end, best);
        self.search(2 * node + 1, middle, end, limit, required_end, best);
    }
}
