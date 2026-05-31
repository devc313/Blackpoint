# DataTypes

**Özet:** Tüm veri yapıları: BinaryReport, SectionInfo, ImportDll, ExportSymbol, vb.

**Kütüphaneler:** std::path::PathBuf

## Ana Struct: BinaryReport

37 field ile tam analiz raporu:
- `path` - Dosya yolu
- `file_size` - Dosya boyutu
- `raw_bytes` - Ham dosya içeriği
- `md5`, `sha1`, `sha256` - Hash'ler
- `format_name`, `format_family`, `detection_confidence`
- `machine_type`, `is_64bit`, `subsystem`
- `image_base`, `entry_point`, `section_alignment`, `file_alignment`
- `timestamp`, `section_count`
- `sections: Vec<SectionInfo>`
- `imports: Vec<ImportDll>`, `exports: Vec<ExportSymbol>`
- `strings: Vec<ExtractedString>`
- `disassembly: Vec<DisassembledInstruction>`
- `archive_entries: Vec<ArchiveEntry>`
- `resource_entries: Vec<ResourceEntry>`
- Header vectors: `rich_headers`, `dos_header`, `file_header`, `optional_header`
- `protections: ProtectionFlags`
- `protection_findings: Vec<ProtectionFinding>`
- XOR: `xor_candidates`, `xor_patterns`, `xor_common_key_hits`
- `notes: Vec<String>`

## SectionInfo
```rust
struct SectionInfo {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_address: u32,
    raw_size: u32,
    characteristics: String,
    entropy: f32,
}
```

## ImportDll & ImportFunction
```rust
struct ImportDll {
    name: String,
    functions: Vec<ImportFunction>,
}
struct ImportFunction {
    name: String,
    ordinal: u16,
}
```

## ProtectionFlags
```rust
struct ProtectionFlags {
    aslr: bool,
    dep_nx: bool,
    no_seh: bool,
    seh_enabled: bool,
    tls_callbacks: usize,
}
```

## Other Types
- `ExportSymbol` - name, offset, RVA
- `ExtractedString` - kind, offset, value
- `DisassembledInstruction` - address, bytes, mnemonic, operand
- `KeyValueRow` - key, value
- `ArchiveEntry` - name, kind, size
- `ResourceEntry` - depth, name, path, kind, size, code_page
- `ProtectionFinding` - title, detail, severity
- `XorCandidate` - source, key, readability, preview
- `XorPattern` - length, pattern, count
- `DetectedFormat` - name, family, confidence, notes

## Baglantilar

- [[Analyzer]] - Struct oluşturma mantığı
- [[ReportExport]] - JSON serialization
