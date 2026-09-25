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

fn main() {
    // The fourth version component Cordiale reports to Grappa in its
    // User-Agent (issue #102): the GitHub Actions run ID the packaging
    // workflows export as `BUILD_ID`, the same value NSIS and Info.plist
    // record. Local and CI check builds have none and report `0`.
    println!("cargo:rerun-if-env-changed=BUILD_ID");
    let build_id = match std::env::var("BUILD_ID") {
        Ok(id) if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) => id,
        Ok(id) => {
            println!("cargo:warning=ignoring non-numeric BUILD_ID {id:?}, using 0");
            "0".to_string()
        }
        Err(_) => "0".to_string(),
    };
    println!("cargo:rustc-env=CORDIALE_BUILD_ID={build_id}");
}
