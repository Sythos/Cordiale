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

//! The optional, non-blocking check for a newer Cordiale release.

use std::time::Duration;

use serde::Deserialize;

use crate::{APP_VERSION, EXTERNAL_USER_AGENT};

const LATEST_RELEASE_API: &str = "https://api.github.com/repos/Sythos/Cordiale/releases/latest";
pub const LATEST_RELEASE_PAGE: &str = "https://github.com/Sythos/Cordiale/releases/latest";

#[derive(Deserialize)]
struct LatestRelease {
    tag_name: String,
}

/// Compare only major, minor and patch. A packaging build number is valid but
/// does not make one release newer than another.
fn version_triplet(version: &str) -> Option<(u64, u64, u64)> {
    let version = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version);
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if let Some(build) = parts.next() {
        build.parse::<u64>().ok()?;
    }
    parts.next().is_none().then_some((major, minor, patch))
}

fn newer_than_installed(tag: &str) -> bool {
    matches!(
        (version_triplet(tag), version_triplet(APP_VERSION)),
        (Some(latest), Some(installed)) if latest > installed
    )
}

/// A failed or malformed check never blocks startup; callers may simply
/// decline to show an update prompt. No account token is sent to this host.
pub async fn check_newer_release() -> Result<Option<String>, reqwest::Error> {
    let client = reqwest::Client::builder()
        .user_agent(EXTERNAL_USER_AGENT)
        .timeout(Duration::from_secs(5))
        .build()?;
    let release: LatestRelease = client
        .get(LATEST_RELEASE_API)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(newer_than_installed(&release.tag_name).then_some(release.tag_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_only_the_first_three_numbers() {
        assert_eq!(version_triplet("v1.2.3.4"), Some((1, 2, 3)));
        assert_eq!(version_triplet("1.2.3"), Some((1, 2, 3)));
        assert_eq!(version_triplet("V1.2.4.999"), Some((1, 2, 4)));
        assert!(!newer_than_installed(&format!("v{APP_VERSION}.999")));
    }

    #[test]
    fn rejects_malformed_versions_and_compares_numeric_components() {
        for tag in ["v1.2", "v1.2.x", "v1.2.3.4.5", "v1.2.3-beta", "v-1.2.3"] {
            assert_eq!(version_triplet(tag), None, "{tag}");
        }
        assert!(version_triplet("v1.10.0") > version_triplet("v1.9.99"));
    }

    #[test]
    fn newer_release_is_strictly_greater() {
        let (major, minor, patch) = version_triplet(APP_VERSION).expect("package version");
        assert!(!newer_than_installed(&format!("v{major}.{minor}.{patch}")));
        assert!(!newer_than_installed(&format!("v{major}.{minor}.{patch}.999")));
        assert!(newer_than_installed(&format!("v{major}.{minor}.{}", patch + 1)));
    }
}
