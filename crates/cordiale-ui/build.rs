// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)
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
    // toolchain needed on any platform. Domain is the crate name, per
    // Slint's own convention.
    //
    // The compile runs in a thread with a large stack: the Slint compiler
    // walks the long `else if` chains of `appwindow.slint` recursively, and
    // the 1 MiB main thread of a Windows build script is too small for them.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            // Embed the images in the binary. Without this, Slint keeps the
            // absolute path of the build machine and a packaged application
            // shows no splash logo.
            let config = slint_build::CompilerConfiguration::new()
                .embed_resources(slint_build::EmbedResourcesKind::EmbedFiles)
                .with_bundled_translations("lang");
            slint_build::compile_with_config("ui/appwindow.slint", config)
                .expect("failed to compile the Slint UI");
        })
        .expect("failed to start the Slint compiler thread")
        .join()
        .expect("the Slint compiler thread panicked");

    // Hardware decoding on Windows links FFmpeg's avcodec.lib. Its Media
    // Foundation wrappers need the GUID definitions of `mfuuid.lib`
    // (IID_IMFTransform, IID_IMFMediaEventGenerator) and `strmiids.lib`
    // (IID_ICodecAPI). The vcpkg route of ffmpeg-sys-next does not link
    // them, so the link fails with unresolved externals. Both libraries
    // ship with the Windows SDK for x64 and ARM64. A build script reads the
    // target and the features from the environment, not from `cfg!`.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var_os("CARGO_FEATURE_HW_DECODE").is_some()
    {
        println!("cargo:rustc-link-lib=mfuuid");
        println!("cargo:rustc-link-lib=strmiids");
    }

    // Embed the app icon into the .exe on Windows. The .ico is generated
    // from resources/branding/cordiale_icona.png by the release-building
    // workflows (packages.yml, dev-build.yml) with ImageMagick before
    // `cargo build` runs. ci.yml's plain `cargo check`/`build`/`test`
    // never runs that step (it's not building a distributable binary),
    // so the .ico is legitimately missing there — skip rather than fail
    // the build over a file only the packaging workflows are expected to
    // produce.
    let icon_path = "../../resources/branding/cordiale.ico";
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if std::path::Path::new(icon_path).exists() {
            winresource::WindowsResource::new()
                .set_icon(icon_path)
                .compile()
                .expect("failed to embed the Windows icon resource");
        } else {
            println!("cargo:warning=cordiale.ico not found, building without an embedded icon");
        }
    }
}
