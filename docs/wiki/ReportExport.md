# ReportExport

**Özet:** JSON snapshot export ve string export fonksiyonları. serde kullanmadan hand-rolled JSON serialization yapar.

**Kütüphaneler:** std::fmt, std::fs

## Public Fonksiyonlar

### Snapshot Export
- `default_snapshot_path(report)` - `<parent>/<stem>.blackpoint.json`
- `snapshot_json(report)` - BinaryReport'ı JSON string'e çevir
- `write_snapshot(report, path)` - JSON'u dosyaya yaz

### String Export
- `default_strings_path(report)` - `<parent>/<stem>.strings.txt`
- `write_strings_txt(report, path)` - String'leri TXT olarak export
- `write_strings_csv(report, path)` - String'leri CSV olarak export

## JSON Snapshot Schema

```json
{
  "schema_version": "blackpoint.snapshot/v1",
  "raw_bytes_included": false,
  "target": { "path", "file_name", "extension", "file_size" },
  "hashes": { "md5", "sha1", "sha256" },
  "counts": { "sections", "imports", "exports", "stored_strings", ... },
  "layout": { "format_name", "architecture", "entry_point", ... },
  "protections": { "aslr", "dep_nx", "no_seh", "tls_callbacks" },
  "headers": { "rich_headers", "dos_header", "file_header", "optional_header" },
  "sections": [...],
  "imports": [...],
  "exports": [...],
  "strings": [...],
  "resources": { "entries", "version_info_rows", "manifest_text" },
  "archive": { "entries", "total_entries", "omitted_entries" },
  "disassembly": [...],
  "notes": [...],
  "protection_findings": [...],
  "xor_analysis": { "candidates", "common_key_hits", "patterns" }
}
```

## Baglantilar

- [[Analyzer]] - BinaryReport yapısı
- [[App]] - Export UI butonları
