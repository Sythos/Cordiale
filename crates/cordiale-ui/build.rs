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
    // Bundled translations (not runtime gettext): slint-build compiles the
    // `.po` files itself at build time, no external `msgfmt`/gettext
    // toolchain needed on any platform — see MEMORY.md §0septies for the
    // primary-source verification of this before writing it. Domain is
    // the crate name, per Slint's own convention.
    let config = slint_build::CompilerConfiguration::new().with_bundled_translations("lang");
    slint_build::compile_with_config("ui/appwindow.slint", config)
        .expect("failed to compile the Slint UI");

    // Embed the app icon into the .exe on Windows. The .ico is generated
    // from resources/branding/cordiale_icona.png by the CI workflows
    // (packages.yml, dev-build.yml) with ImageMagick before `cargo build`
    // runs, so it's expected to exist by the time build.rs gets here.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("../../resources/branding/cordiale.ico")
            .compile()
            .expect("failed to embed the Windows icon resource");
    }
}
