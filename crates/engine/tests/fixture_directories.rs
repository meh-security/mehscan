mod support;

#[test]
fn simultaneous_fixtures_with_the_same_label_own_distinct_directories() {
    let directories = std::thread::scope(|scope| {
        let threads = (0..32)
            .map(|_| scope.spawn(|| support::temp_dir("parallel-fixture")))
            .collect::<Vec<_>>();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        directories
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        directories.len()
    );
    for (index, path) in directories.iter().enumerate() {
        std::fs::write(path.join("owned"), index.to_string()).unwrap();
    }
    for (index, path) in directories.iter().enumerate() {
        assert_eq!(
            std::fs::read_to_string(path.join("owned")).unwrap(),
            index.to_string()
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
