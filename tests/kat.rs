//! Runs every pinned known-answer vector (ACVP ML-KEM + X-Wing draft-06).

use hybridkem::kat::{run_all, verify_checksums};
use std::path::Path;

fn vectors() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors"))
}

#[test]
fn vector_files_match_pinned_checksums() {
    assert_eq!(verify_checksums(vectors()).unwrap(), 3);
}

#[test]
fn all_known_answer_tests_pass() {
    let outcomes = run_all(vectors()).unwrap();
    for o in &outcomes {
        assert!(
            o.ok(),
            "{} {} {}: {:?}",
            o.suite,
            o.target,
            o.function,
            o.failures
        );
    }
    let total = |suite: &str, function: &str| -> usize {
        outcomes
            .iter()
            .filter(|o| o.suite == suite && o.function == function)
            .map(|o| o.total())
            .sum()
    };
    // Counts are those of the pinned files; a change here means the vectors changed.
    assert_eq!(total("ACVP keyGen", "keyGen"), 75);
    assert_eq!(total("ACVP encapDecap", "encapsulation"), 75);
    assert_eq!(total("ACVP encapDecap", "decapsulation"), 30);
    assert_eq!(total("ACVP encapDecap", "encapsulationKeyCheck"), 30);
    assert_eq!(total("ACVP encapDecap", "decapsulationKeyCheck"), 30);
    assert_eq!(total("X-Wing draft-06", "keygen+encaps+decaps"), 3);
    for set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        assert!(outcomes.iter().any(|o| o.target == set));
    }
}
