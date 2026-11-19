# Third-party notices

Direct Rust and JavaScript dependencies are pinned in `Cargo.lock` and `bun.lock`. This document does not replace a complete set of transitive license texts.

| Component | Use | License |
| --- | --- | --- |
| Tauri v2 | Android app shell and IPC | MIT / Apache-2.0 |
| SolidJS | Reactive interface | MIT |
| Vite | Frontend build | MIT |
| Rust / Cargo | Compiler and package management | MIT / Apache-2.0 |
| Bun | JavaScript tooling | MIT, including its own third-party notices |
| Tokio | Asynchronous TCP scanning and forwarding runtime | MIT |
| tun2proxy 0.8.7 | IP forwarding from Android TUN | MIT |
| Gradle Wrapper | Bootstraps the Android build | Apache-2.0 |
| AndroidX | Android activity, lifecycle and WebView integration | Apache-2.0 |
| Google Play services Nearby Connections 19.4.0 | Cooperative Android discovery and capture transfer | Google SDK/API terms; not covered by SeekerShark's MIT license |

This source snapshot includes the Gradle Wrapper JAR and app image assets, but no APK, Google Play services binary, signing key, or model weights. The Android build resolves its AndroidX and Google Play services dependencies from their configured Maven repositories. See [Gradle's license](https://github.com/gradle/gradle/blob/master/LICENSE), [AndroidX licensing](https://source.android.com/docs/setup/about/licenses), and [Google's API terms](https://developers.google.com/terms) and [Nearby documentation](https://developers.google.com/nearby/connections/overview).

Before distributing a built APK, check licenses and required notices for all bundled binary dependencies against the shipped lockfiles and Android Gradle dependencies. SeekerShark's own source code uses MIT; this document is not a complete transitive dependency license bundle.

Scanner features are independently implemented in Rust; RustScan and Nmap code, binaries, databases, and scripts are not included.

## tun2proxy 0.8.7

Source: https://github.com/tun2proxy/tun2proxy/tree/v0.8.7

```text
MIT License

Copyright (c) @ssrlive, B. Blechschmidt and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
