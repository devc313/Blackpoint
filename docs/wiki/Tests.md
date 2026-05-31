# Tests

**Özet:** Mevcut test coverage ve test stratejisi.

**Kütüphaneler:** [built-in test framework]

## Test Coverage

### analyzer.rs (4 test)
- `recognizes_tgz_like_names` - .tgz, .tar.gz, .npm extension tespiti
- `classifies_tar_gz_as_generic_tgz_archive` - Format detection
- `keeps_npm_extension_classification` - NPM format
- `extracts_utf16le_strings_from_odd_offsets` - UTF-16LE extraction

### app.rs (4 test)
- `case_insensitive_match_reuses_precomputed_needle` - String search
- `ascii_case_insensitive_contains_handles_shorter_haystacks` - Case-insensitive
- `raw_offset_translation_rejects_virtual_only_section_tail` - RVA → raw offset
- `entry_hex_selection_falls_back_to_nearest_file_backed_offset` - Hex selection

### report_export.rs (2 test)
- `default_snapshot_path_uses_blackpoint_suffix` - Path generation
- `snapshot_json_omits_raw_bytes_and_preserves_core_sections` - JSON export

## Test Komutları

```bash
cargo test                          # Tüm testleri çalıştır
cargo test -- --nocapture           # Output göstererek
cargo test analyzer::tests          # Sadece analyzer testleri
cargo test app::tests               # Sadece app testleri
```

## CI Pipeline

```yaml
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
```

## Baglantilar

- [[Analyzer]] - Analyzer testleri
- [[App]] - App testleri
- [[ReportExport]] - Export testleri
