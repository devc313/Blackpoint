# Blackpoint

Blackpoint is a desktop static analysis workbench for reverse engineering and binary triage on Windows.

It is built in Rust with `eframe/egui` and focuses on a smooth native workflow for inspecting executables, libraries, archives, and mixed-format payloads without leaving a single UI.

## Current Capabilities

- Multi-format detection for PE, ELF, Mach-O, DEX, ZIP, APK, IPA, JAR, ISO9660, MS-DOS, COM, LE/LX, NPM archives, Amiga hunk binaries, and generic binary inputs
- PE-focused metadata including DOS/File/Optional headers, section layout, imports, exports, mitigations, compile timestamp, entry point, image base, and machine type
- Hash generation with `MD5`, `SHA-1`, and `SHA-256`
- Searchable string extraction with ASCII and UTF-16LE filtering
- Entry-point disassembly using Capstone
- XOR analysis with single-byte candidates, common-key previews, and repeating multi-byte pattern discovery
- Archive member listing for ZIP-like and `.tgz` containers
- Raw hex viewer with offset jump and entry-point jump
- Custom OLED-style UI with drag-and-drop loading and async analysis overlay

## Stack

- Rust
- `eframe` / `egui`
- `goblin`
- `capstone`
- `zip`
- `tar`
- `flate2`

## Run

```bash
cargo run
```

## Build

```bash
cargo build --release
```

## Roadmap

- RVA to raw offset conversion and section-aware navigation
- Resource tree, version info, and manifest parsing
- TLS callback expansion and code cave analysis
- Richer ELF and Mach-O symbol views
- Heuristic scoring for packers, injectors, and suspicious loaders

## Repository

Prepared for GitHub publishing under [devc313](https://github.com/devc313).
