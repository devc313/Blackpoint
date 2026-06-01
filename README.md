<div align="center">

# ◼ Blackpoint

**A native desktop binary analysis workbench — built in Rust.**

Reverse engineering, malware triage, and low-level executable inspection across PE, ELF, Mach-O, archives, and raw binaries. Zero dependencies on Python, Java, or external runtimes.

[![Build](https://img.shields.io/github/actions/workflow/status/devc313/Blackpoint/build.yml?branch=main&logo=githubactions&logoColor=white&label=Build&style=for-the-badge)](https://github.com/devc313/Blackpoint/actions)
[![Release](https://img.shields.io/github/v/release/devc313/Blackpoint?style=for-the-badge&logo=rust&logoColor=white&color=DE5400)](https://github.com/devc313/Blackpoint/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/devc313/Blackpoint)
[![Language](https://img.shields.io/badge/rust-1.83%2B-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License](https://img.shields.io/github/license/devc313/Blackpoint?style=for-the-badge&color=22C55E)](https://github.com/devc313/Blackpoint/blob/main/LICENSE)

</div>

---

## Overview

Blackpoint is a single-binary desktop tool for static binary analysis. It provides a fast, keyboard-friendly interface for inspecting executables, libraries, archives, and blobs — without leaving the desktop or opening a browser.

It is not a disassembler or debugger. Its scope is **static triage**: format identification, header parsing, hash computation, string extraction, import/export analysis, entropy measurement, and heuristic scoring. Think of it as a native, offline alternative to tools like PE-bear, CFF Explorer, or Detect-It-Easy — with a unified interface that handles more than just PE.

---

## Supported Formats

| Category | Formats |
|---|---|
| **Native executables** | PE (x86/x64/ARM), ELF, Mach-O, MS-DOS, COM, LE/LX |
| **Mobile / JVM** | DEX, APK, IPA, JAR |
| **Archives** | ZIP, `.tgz`, ISO 9660, NPM package archives |
| **Exotic** | Amiga Hunk binaries |
| **Fallback** | Generic binary with heuristic detection |

---

## Features

### Static Analysis Core

- File metadata, format identification, and detection confidence score
- `MD5`, `SHA-1`, `SHA-256` hash computation
- Architecture, machine type, subsystem, image base, entry point, section count, timestamp

### PE Inspection

- DOS header, File header, Optional header
- Section table with **entropy per section** and RWX permission flags
- Imports grouped by DLL, with ordinal resolution
- Exports with RVA and raw offset
- Resource tree enumeration
- Version information and application manifest extraction (execution level, DPI awareness)
- Build signals: overlay detection, debug directory, PDB path, CLR header, bound imports, delay imports, certificate table
- Hardening signals: **ASLR**, **DEP/NX**, **SEH**, **CFG**, TLS callback presence

### Content Inspection

- ASCII and UTF-16LE string extraction with search and live filtering
- Entry-point disassembly via **Capstone**
- Raw hex viewer with navigation: raw offset jump, RVA jump, entry jump, section quick-jump

### Heuristics & Triage

- Suspicious API import detection (anti-debug, injection, credential access patterns)
- Single-byte XOR candidate discovery
- Common-key XOR preview
- Repeating multi-byte XOR pattern detection
- Protection findings surface

### Workflow

- Drag-and-drop file loading
- Recent target list in sidebar
- Copy-path and open-folder actions for active target
- Asynchronous analysis pipeline — UI never blocks
- Responsive layout across compact and full-size windows

---

## UI

Custom frameless window with OLED-inspired dark surface system. Designed for extended use on high-contrast monitors. Scroll-first behavior at smaller window sizes prevents clipping.

No Electron. No web view. Native OpenGL rendering via `egui_glow`.

---

## Getting Started

**Requirements:** Rust stable 1.83+, Cargo

```bash
git clone https://github.com/devc313/Blackpoint
cd Blackpoint

# Development
cargo run

# Release binary
cargo build --release
# → target/release/blackpoint
```

No additional setup. The binary is self-contained.

---

## Tech Stack

| Layer | Crate |
|---|---|
| GUI framework | `eframe` + `egui` + `egui_extras` |
| Rendering | `egui_glow` (OpenGL) |
| PE parsing | `pelite` |
| Multi-format parsing | `goblin` (ELF, Mach-O, PE, archive) |
| Disassembly | `capstone` |
| Archive handling | `zip`, `tar`, `flate2` |

No runtime dependencies outside these crates and the standard library.

---

## Roadmap

- [ ] RVA ↔ raw offset translation with section-aware hex navigation
- [ ] Code cave detection and richer TLS callback detail
- [ ] Richer ELF symbol and dynamic segment views
- [ ] Richer Mach-O load command and dylib views
- [ ] Heuristic packer/injector scoring
- [ ] Copy/export actions for strings, hashes, section data
- [ ] YARA rule evaluation against loaded targets
- [ ] Localization (EN, TR, DE)

---

## Contributing

```bash
# Before opening a PR:
cargo fmt
cargo clippy -- -D warnings
cargo test
```

Keep analysis modules (`scanner`, `parser`, `heuristics`) independent of the GUI layer. No cross-module state sharing through globals.

---

## License

MIT — see [LICENSE](LICENSE).

> **Disclaimer:** Blackpoint is intended for analysis of binaries you own or have explicit authorization to inspect. Use responsibly and in compliance with applicable laws.

---

<div align="center">
Built by <a href="https://github.com/devc313">devc313</a>
</div>
