//! Known-answer test runners for the pinned vector files under `vectors/`.
//!
//! * NIST ACVP-Server `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`
//!   (`internalProjection.json`, which carries the expected answers alongside the inputs).
//! * The X-Wing draft's `spec/test-vectors.json`.
//!
//! [`verify_checksums`] re-hashes every file against `vectors/SHA256SUMS` before use, so a
//! silently edited vector cannot make a broken implementation look correct.

use crate::error::{Error, Result};
use crate::hybrid::{HybridDecapsulationKey, HybridEncapsulationKey, XWingCombiner};
use crate::mlkem::{
    DecapsulationKey, EncapsulationKey, MlKem1024, MlKem512, MlKem768, ParameterSet,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The result of running one group of vectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KatOutcome {
    /// Vector source, e.g. `"ACVP keyGen"`.
    pub suite: String,
    /// Parameter set or algorithm name.
    pub target: String,
    /// What was exercised, e.g. `"encapsulation"`.
    pub function: String,
    /// Number of vectors that matched.
    pub passed: usize,
    /// Descriptions of vectors that did not match.
    pub failures: Vec<String>,
}

impl KatOutcome {
    fn new(suite: &str, target: &str, function: &str) -> Self {
        Self {
            suite: suite.to_string(),
            target: target.to_string(),
            function: function.to_string(),
            passed: 0,
            failures: Vec::new(),
        }
    }

    fn record(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if ok {
            self.passed += 1;
        } else {
            self.failures.push(what());
        }
    }

    /// Total vectors run.
    pub fn total(&self) -> usize {
        self.passed + self.failures.len()
    }

    /// True when every vector matched.
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }
}

#[derive(Deserialize)]
struct AcvpFile {
    mode: String,
    revision: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<AcvpGroup>,
}

#[derive(Deserialize)]
struct AcvpGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(default)]
    function: Option<String>,
    tests: Vec<AcvpTest>,
}

#[derive(Deserialize)]
struct AcvpTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: Option<String>,
    z: Option<String>,
    ek: Option<String>,
    dk: Option<String>,
    c: Option<String>,
    k: Option<String>,
    m: Option<String>,
    #[serde(rename = "testPassed")]
    test_passed: Option<bool>,
}

fn unhex(field: &Option<String>, name: &str, tc: u32) -> Result<Vec<u8>> {
    let s = field
        .as_deref()
        .ok_or_else(|| Error::Parse(format!("tcId {tc}: missing field {name}")))?;
    hex::decode(s).map_err(|e| Error::Parse(format!("tcId {tc}: field {name}: {e}")))
}

fn unhex32(field: &Option<String>, name: &str, tc: u32) -> Result<[u8; 32]> {
    unhex(field, name, tc)?
        .try_into()
        .map_err(|_| Error::Parse(format!("tcId {tc}: field {name} is not 32 bytes")))
}

fn parse_acvp(json: &str, mode: &str) -> Result<AcvpFile> {
    let file: AcvpFile = serde_json::from_str(json).map_err(|e| Error::Parse(e.to_string()))?;
    if file.mode != mode || file.revision != "FIPS203" {
        return Err(Error::Parse(format!(
            "expected ACVP mode {mode}/FIPS203, found {}/{}",
            file.mode, file.revision
        )));
    }
    Ok(file)
}

fn keygen_group<P: ParameterSet>(group: &AcvpGroup) -> Result<KatOutcome> {
    let mut out = KatOutcome::new("ACVP keyGen", P::NAME, "keyGen");
    for t in &group.tests {
        let dk = DecapsulationKey::<P>::generate_deterministic(
            &unhex32(&t.d, "d", t.tc_id)?,
            &unhex32(&t.z, "z", t.tc_id)?,
        );
        let ok = dk.encapsulation_key().as_bytes() == unhex(&t.ek, "ek", t.tc_id)?.as_slice()
            && *dk.to_bytes() == unhex(&t.dk, "dk", t.tc_id)?;
        out.record(ok, || format!("tcId {}: ek/dk mismatch", t.tc_id));
    }
    Ok(out)
}

fn encap_decap_group<P: ParameterSet>(group: &AcvpGroup, function: &str) -> Result<KatOutcome> {
    let mut out = KatOutcome::new("ACVP encapDecap", P::NAME, function);
    for t in &group.tests {
        let tc = t.tc_id;
        let ok = match function {
            "encapsulation" => {
                let ek = EncapsulationKey::<P>::from_bytes(&unhex(&t.ek, "ek", tc)?)?;
                let (c, k) = ek.encapsulate_deterministic(&unhex32(&t.m, "m", tc)?);
                c.as_bytes() == unhex(&t.c, "c", tc)?.as_slice()
                    && k.as_bytes()[..] == unhex(&t.k, "k", tc)?[..]
            }
            "decapsulation" => {
                let dk = DecapsulationKey::<P>::from_bytes(&unhex(&t.dk, "dk", tc)?)?;
                let k = dk.decapsulate(&unhex(&t.c, "c", tc)?)?;
                k.as_bytes()[..] == unhex(&t.k, "k", tc)?[..]
            }
            "encapsulationKeyCheck" => {
                let accepted = EncapsulationKey::<P>::from_bytes(&unhex(&t.ek, "ek", tc)?).is_ok();
                Some(accepted) == t.test_passed
            }
            "decapsulationKeyCheck" => {
                let accepted = DecapsulationKey::<P>::from_bytes(&unhex(&t.dk, "dk", tc)?).is_ok();
                Some(accepted) == t.test_passed
            }
            other => return Err(Error::Parse(format!("unsupported ACVP function {other:?}"))),
        };
        out.record(ok, || format!("tcId {tc}: {function} mismatch"));
    }
    Ok(out)
}

fn dispatch<F>(parameter_set: &str, f: F) -> Result<KatOutcome>
where
    F: FnOnce(&str) -> Option<Result<KatOutcome>>,
{
    f(parameter_set).unwrap_or_else(|| {
        Err(Error::Parse(format!(
            "unknown parameter set {parameter_set:?}"
        )))
    })
}

macro_rules! by_param {
    ($ps:expr, $func:ident $(, $arg:expr)*) => {
        dispatch($ps, |ps| match ps {
            "ML-KEM-512" => Some($func::<MlKem512>($($arg),*)),
            "ML-KEM-768" => Some($func::<MlKem768>($($arg),*)),
            "ML-KEM-1024" => Some($func::<MlKem1024>($($arg),*)),
            _ => None,
        })
    };
}

/// Run every group of an ACVP `ML-KEM-keyGen-FIPS203` internal-projection file.
pub fn run_acvp_keygen(json: &str) -> Result<Vec<KatOutcome>> {
    let file = parse_acvp(json, "keyGen")?;
    file.test_groups
        .iter()
        .map(|g| by_param!(g.parameter_set.as_str(), keygen_group, g))
        .collect()
}

/// Run every group of an ACVP `ML-KEM-encapDecap-FIPS203` internal-projection file.
pub fn run_acvp_encap_decap(json: &str) -> Result<Vec<KatOutcome>> {
    let file = parse_acvp(json, "encapDecap")?;
    file.test_groups
        .iter()
        .map(|g| {
            let function = g
                .function
                .as_deref()
                .ok_or_else(|| Error::Parse("encapDecap group without function".into()))?;
            by_param!(g.parameter_set.as_str(), encap_decap_group, g, function)
        })
        .collect()
}

#[derive(Deserialize)]
struct XWingVector {
    seed: String,
    eseed: String,
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

/// Run the X-Wing draft-06 vectors: key generation from `seed`, deterministic encapsulation
/// with `eseed`, and decapsulation.
pub fn run_xwing(json: &str) -> Result<KatOutcome> {
    let vectors: Vec<XWingVector> =
        serde_json::from_str(json).map_err(|e| Error::Parse(e.to_string()))?;
    let mut out = KatOutcome::new("X-Wing draft-06", "X-Wing", "keygen+encaps+decaps");
    let dec = |s: &str| hex::decode(s).map_err(|e| Error::Parse(e.to_string()));
    for (i, v) in vectors.iter().enumerate() {
        let seed: [u8; 32] = dec(&v.seed)?
            .try_into()
            .map_err(|_| Error::Parse("seed must be 32 bytes".into()))?;
        let eseed: [u8; 64] = dec(&v.eseed)?
            .try_into()
            .map_err(|_| Error::Parse("eseed must be 64 bytes".into()))?;
        let dk = HybridDecapsulationKey::<MlKem768, XWingCombiner>::from_seed(&seed);
        let ek = HybridEncapsulationKey::<MlKem768, XWingCombiner>::from_bytes(&dec(&v.pk)?)?;
        let (ct, ss) = ek.encapsulate_deterministic(&eseed)?;
        let ss_expected = dec(&v.ss)?;
        let ok = dk.seed()[..] == dec(&v.sk)?[..]
            && dk.encapsulation_key().as_bytes() == ek.as_bytes()
            && ct == dec(&v.ct)?
            && ss.as_bytes()[..] == ss_expected[..]
            && dk.decapsulate(&ct)?.as_bytes()[..] == ss_expected[..];
        out.record(ok, || format!("vector {i}: mismatch"));
    }
    Ok(out)
}

/// Check every file listed in `<dir>/SHA256SUMS` against its pinned digest.
/// Returns the number of files verified.
pub fn verify_checksums(dir: &Path) -> Result<usize> {
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS"))?;
    let mut verified = 0;
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (want, name) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| Error::Parse(format!("bad SHA256SUMS line {line:?}")))?;
        let name = name.trim();
        let got = hex::encode(Sha256::digest(std::fs::read(dir.join(name))?));
        if got != want {
            return Err(Error::Parse(format!(
                "checksum mismatch for {name}: want {want}, got {got}"
            )));
        }
        verified += 1;
    }
    Ok(verified)
}

/// Verify checksums, then run every suite in `dir` (normally `vectors/`).
pub fn run_all(dir: &Path) -> Result<Vec<KatOutcome>> {
    verify_checksums(dir)?;
    let read = |p: &str| std::fs::read_to_string(dir.join(p));
    let mut outcomes = run_acvp_keygen(&read("acvp/keygen.json")?)?;
    outcomes.extend(run_acvp_encap_decap(&read("acvp/encap-decap.json")?)?);
    outcomes.push(run_xwing(&read("xwing/test-vectors.json")?)?);
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_mode_and_garbage() {
        let json = r#"{"mode":"encapDecap","revision":"FIPS203","testGroups":[]}"#;
        assert!(run_acvp_keygen(json).is_err());
        assert!(run_acvp_encap_decap(json).unwrap().is_empty());
        assert!(run_acvp_keygen("not json").is_err());
        assert!(run_xwing("[{}]").is_err());
    }

    #[test]
    fn unknown_parameter_sets_and_functions_are_errors() {
        let json = r#"{"mode":"keyGen","revision":"FIPS203","testGroups":[
            {"parameterSet":"ML-KEM-999","tests":[]}]}"#;
        assert!(run_acvp_keygen(json).is_err());
        let json = r#"{"mode":"encapDecap","revision":"FIPS203","testGroups":[
            {"parameterSet":"ML-KEM-512","function":"frobnicate","tests":[{"tcId":1}]}]}"#;
        assert!(run_acvp_encap_decap(json).is_err());
        let json = r#"{"mode":"encapDecap","revision":"FIPS203","testGroups":[
            {"parameterSet":"ML-KEM-512","tests":[]}]}"#;
        assert!(run_acvp_encap_decap(json).is_err());
    }

    #[test]
    fn missing_or_malformed_fields_are_reported() {
        let json = r#"{"mode":"keyGen","revision":"FIPS203","testGroups":[
            {"parameterSet":"ML-KEM-512","tests":[{"tcId":7,"d":"00"}]}]}"#;
        let err = run_acvp_keygen(json).unwrap_err().to_string();
        assert!(err.contains("tcId 7"), "{err}");
        let json = r#"{"mode":"keyGen","revision":"FIPS203","testGroups":[
            {"parameterSet":"ML-KEM-512","tests":[{"tcId":8,"d":"zz","z":"00"}]}]}"#;
        assert!(run_acvp_keygen(json)
            .unwrap_err()
            .to_string()
            .contains("tcId 8"));
    }

    #[test]
    fn a_wrong_answer_is_recorded_as_failure_not_error() {
        let d = "00".repeat(32);
        let json = format!(
            r#"{{"mode":"keyGen","revision":"FIPS203","testGroups":[
            {{"parameterSet":"ML-KEM-512","tests":[{{"tcId":1,"d":"{d}","z":"{d}","ek":"00","dk":"00"}}]}}]}}"#
        );
        let out = run_acvp_keygen(&json).unwrap();
        assert_eq!(out[0].total(), 1);
        assert!(!out[0].ok());
        assert_eq!(out[0].failures, vec!["tcId 1: ek/dk mismatch".to_string()]);
    }

    #[test]
    fn checksum_mismatch_is_detected() {
        let dir = std::env::temp_dir().join(format!("hybridkem-kat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        let good = hex::encode(Sha256::digest(b"hello"));
        std::fs::write(dir.join("SHA256SUMS"), format!("{good}  a.txt\n")).unwrap();
        assert_eq!(verify_checksums(&dir).unwrap(), 1);
        std::fs::write(dir.join("a.txt"), b"hellO").unwrap();
        assert!(verify_checksums(&dir).is_err());
        std::fs::write(dir.join("SHA256SUMS"), "garbage\n").unwrap();
        assert!(verify_checksums(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
