//! `kat`, `bench` and `ct-test`: run the library's harnesses and format their results.

use hybridkem::bench::{handshake_table, kem_table, time_algorithm, time_handshake};
use hybridkem::dudect::{Target, Verdict};
use hybridkem::kat::{run_all, KatOutcome};
use hybridkem::kem::Algorithm;
use hybridkem::noise::Pattern;
use hybridkem::Result;
use std::fmt::Write as _;
use std::path::Path;

/// Format KAT outcomes as an aligned table plus a total line.
pub fn format_kat(outcomes: &[KatOutcome]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<18} {:<12} {:<24} {:>7}",
        "suite", "target", "function", "result"
    );
    for o in outcomes {
        let status = if o.ok() {
            format!("{}/{}", o.passed, o.total())
        } else {
            format!("FAIL {}/{}", o.passed, o.total())
        };
        let _ = writeln!(
            out,
            "{:<18} {:<12} {:<24} {:>7}",
            o.suite, o.target, o.function, status
        );
        for f in &o.failures {
            let _ = writeln!(out, "    {f}");
        }
    }
    let passed: usize = outcomes.iter().map(|o| o.passed).sum();
    let total: usize = outcomes.iter().map(KatOutcome::total).sum();
    let _ = writeln!(out, "total: {passed}/{total} vectors passed");
    out
}

/// Verify checksums and run every KAT suite. Returns the report and whether all passed.
pub fn kat(dir: &Path) -> Result<(String, bool)> {
    let outcomes = run_all(dir)?;
    let ok = outcomes.iter().all(KatOutcome::ok);
    let mut text = format!(
        "checksums: all files in {}/SHA256SUMS verified\n",
        dir.display()
    );
    text.push_str(&format_kat(&outcomes));
    Ok((text, ok))
}

/// Time every algorithm and the main handshake configurations.
pub fn bench(iterations: usize) -> String {
    let rows: Vec<_> = Algorithm::ALL
        .iter()
        .map(|&a| time_algorithm(a, iterations))
        .collect();
    let handshakes: Vec<_> = [
        (Algorithm::X25519, Pattern::IK),
        (Algorithm::MlKem768, Pattern::IK),
        (Algorithm::XWing, Pattern::IK),
        (Algorithm::XWing, Pattern::XX),
        (Algorithm::X25519MlKem1024, Pattern::IK),
    ]
    .iter()
    .map(|&(a, p)| time_handshake(a, p, iterations.div_ceil(4).max(1)))
    .collect();
    let mut out = format!(
        "median of {iterations} runs per operation (handshakes: {})\n\n",
        iterations.div_ceil(4).max(1)
    );
    out.push_str(&kem_table(&rows));
    out.push('\n');
    out.push_str(&handshake_table(&handshakes));
    out
}

/// Run dudect targets. Returns the report and whether every result matched expectations
/// (no leak on real targets, a leak on the positive control).
pub fn ct_test(targets: &[Target], samples: usize, seed: u64) -> (String, bool) {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<38} {:>8} {:>13} {:>8}  verdict",
        "target", "samples", "median ns 0/1", "max |t|"
    );
    let mut as_expected = true;
    for &t in targets {
        let r = t.run(samples, seed);
        let expected = if t.expect_leak() {
            r.verdict == Verdict::Leak
        } else {
            r.verdict != Verdict::Leak
        };
        as_expected &= expected;
        let _ = writeln!(
            out,
            "{:<38} {:>8} {:>13} {:>8.2}  {}{}",
            t.id(),
            r.samples.0 + r.samples.1,
            format!("{}/{}", r.median_ns.0, r.median_ns.1),
            r.max_t,
            r.verdict.label(),
            if t.expect_leak() {
                " (expected: control must leak)"
            } else {
                ""
            }
        );
    }
    let _ = writeln!(
        out,
        "\n|t| < 4.5: no leak detected at this sample size; |t| >= 10: leak. A pass is evidence, not proof."
    );
    (out, as_expected)
}
