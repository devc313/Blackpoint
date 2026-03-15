# Blackpoint

Blackpoint is a modern desktop binary analysis workbench built in Rust for reverse engineering, malware triage, and low-level executable inspection across PE, ELF, Mach-O, archives, and raw binaries.

It is designed as a native desktop workflow with custom window chrome, an OLED-inspired interface, async analysis, drag-and-drop loading, bounded-memory extraction paths, and a responsive layout that remains usable in both compact and full-size windows.

## Highlights

- Native Rust desktop application built with `eframe/egui`
- Custom dark UI with responsive panels, pixel-tight section surfaces, and explicit empty/error/loading states
- Asynchronous analysis pipeline with animated `Analyzing...` overlay and in-place retry flow
- Drag-and-drop file loading and custom title bar controls
- Static triage workflow for executables, libraries, package archives, and mixed binary blobs
- Fail-soft parsing for PE resources, archive enumeration, and entry-point disassembly so partial analysis still renders

## Supported Formats

- PE
- ELF
- Mach-O
- DEX
- APK
- IPA
- JAR
- ZIP
- ISO9660
- MS-DOS
- COM
- LE/LX
- NPM package archives
- Amiga hunk binaries
- Generic binary fallback with heuristic detection

## Current Features

### General analysis

- File metadata and format identification
- `MD5`, `SHA-1`, and `SHA-256`
- Architecture, machine type, subsystem, image base, entry point, section count, and timestamp
- Detection confidence and heuristic notes

### PE-focused inspection

- DOS header
- File header
- Optional header
- Resource tree enumeration
- Version information extraction
- Application manifest extraction with execution-level and awareness hints
- PE build signals such as overlay detection, debug directories, PDB path, CLR, bound import, delay import, and certificate-table presence
- Section table with entropy and permission flags
- Imports grouped by DLL with ordinal support
- Exports with RVA and offset information
- Mitigation and hardening signals such as `ASLR`, `DEP/NX`, `SEH`, and TLS callback presence

### Content inspection

- ASCII and UTF-16LE string extraction
- Search and filtering in the strings view with bounded visible-row rendering
- Entry-point disassembly with Capstone
- Raw hex viewer with raw offset jump, RVA jump, entry jump, section quick-jump, and virtual-only RVA fallback messaging
- ZIP and `.tgz` archive member listing with stored-versus-total accounting

### Heuristics and triage

- Protection findings and suspicious API indicators
- Anti-debug oriented import heuristics
- Single-byte XOR candidate discovery
- Common-key XOR previews
- Repeating multi-byte XOR pattern detection

### Workflow quality

- Recent target list in the sidebar
- Copy-path and open-folder actions for the active target
- Dedicated `Resources` surface for PE metadata
- Responsive layout for compact and wide desktop windows
- Memory-bounded string and archive previews to avoid pathological UI allocations on large inputs
- CI verification with `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, and release builds

## Tech Stack

- Rust
- `eframe`
- `egui`
- `egui_extras`
- `goblin`
- `pelite`
- `capstone`
- `zip`
- `tar`
- `flate2`

## Getting Started

### Run

```bash
cargo run
```

### Debug build

```bash
cargo build
```

### Release build

```bash
cargo build --release
```

### Verification

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

## UI Notes

- Custom title bar and window controls
- OLED-style dark surface system
- Responsive layout for compact and wide window sizes
- Scroll-first behavior for smaller windows instead of clipping
- Dedicated resource/version/manifest view for PE targets

## Roadmap

- Code cave analysis and richer TLS callback detail
- Richer ELF and Mach-O symbol and loader views
- Heuristic scoring for packers, injectors, and suspicious loaders
- Copy/export actions for strings, hashes, and paths
- Persisted session history and exportable analysis snapshots

## Repository

Prepared for GitHub publishing under [devc313](https://github.com/devc313).
