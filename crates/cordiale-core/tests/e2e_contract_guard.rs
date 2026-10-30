// MIT License
//
// Copyright (c) 2026 Sythos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Keeps the E2E contract document and the E2E modules in step.
//!
//! The contract in `docs/e2e-contract.md` names the tests that prove each
//! point. These checks fail when a named test is renamed or removed, and when a
//! candidate marker comes back into an E2E module.

use std::fs;
use std::path::{Path, PathBuf};

fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_crates_dir() -> PathBuf {
    core_dir()
        .parent()
        .expect("the core crate lives in the crates directory")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("directory can be read") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_e2e_module_keeps_a_candidate_marker() {
    let mut checked = 0;
    for entry in fs::read_dir(core_dir().join("src")).expect("src can be read") {
        let path = entry.expect("directory entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if !(name.starts_with("e2e_") && name.ends_with(".rs")) {
            continue;
        }
        let source = fs::read_to_string(&path).expect("module can be read");
        assert!(
            !source.to_lowercase().contains("candidat"),
            "{name} still has a candidate marker"
        );
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} E2E modules found");
}

#[test]
fn every_test_that_the_contract_names_exists() {
    let contract = fs::read_to_string(
        workspace_crates_dir()
            .parent()
            .expect("the workspace root")
            .join("docs/e2e-contract.md"),
    )
    .expect("the contract document exists");

    // A name is a code span of lowercase words joined by at least three
    // underscores, for example `a_202_answer_sets_the_accepted_state_only`.
    let mut names: Vec<&str> = contract
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|span| {
            span.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                && span.matches('_').count() >= 3
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    assert!(
        names.len() >= 15,
        "the contract names only {} tests",
        names.len()
    );

    let mut files = Vec::new();
    rust_sources(&workspace_crates_dir(), &mut files);
    let sources: Vec<String> = files
        .iter()
        .map(|path| fs::read_to_string(path).expect("source can be read"))
        .collect();
    for name in names {
        let declaration = format!("fn {name}(");
        assert!(
            sources.iter().any(|source| source.contains(&declaration)),
            "the contract names `{name}` but no test or function has that name"
        );
    }
}
