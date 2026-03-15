use crate::analyzer::{BinaryReport, KeyValueRow, ProtectionFlags, ResourceEntry, SectionInfo};
use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const SNAPSHOT_SCHEMA_VERSION: &str = "blackpoint.snapshot/v1";

enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn render_pretty(&self, output: &mut String, indent: usize) {
        match self {
            Self::Null => output.push_str("null"),
            Self::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => output.push_str(value),
            Self::String(value) => push_json_string(output, value),
            Self::Array(values) => render_array(output, values, indent),
            Self::Object(fields) => render_object(output, fields, indent),
        }
    }
}

pub fn default_snapshot_path(report: &BinaryReport) -> PathBuf {
    let parent = report.path.parent().unwrap_or_else(|| Path::new("."));
    let stem = report
        .path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("analysis");
    parent.join(format!("{stem}.blackpoint.json"))
}

pub fn snapshot_json(report: &BinaryReport) -> Result<String> {
    let mut output = String::with_capacity(32 * 1024);
    snapshot_value(report).render_pretty(&mut output, 0);
    output.push('\n');
    Ok(output)
}

pub fn write_snapshot(report: &BinaryReport, output_path: &Path) -> Result<()> {
    if let Some(parent) = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create export directory {}", parent.display()))?;
    }

    let json = snapshot_json(report)?;
    fs::write(output_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", output_path.display()))
}

fn snapshot_value(report: &BinaryReport) -> JsonValue {
    let imported_api_count = report
        .imports
        .iter()
        .map(|dll| dll.functions.len())
        .sum::<usize>();

    obj(vec![
        ("schema_version", string(SNAPSHOT_SCHEMA_VERSION)),
        ("raw_bytes_included", bool_value(false)),
        (
            "target",
            obj(vec![
                ("path", string(report.path.display().to_string())),
                (
                    "file_name",
                    opt_string(report.path.file_name().and_then(|value| value.to_str())),
                ),
                (
                    "extension",
                    opt_string(report.path.extension().and_then(|value| value.to_str())),
                ),
                ("file_size", usize_value(report.file_size)),
            ]),
        ),
        (
            "hashes",
            obj(vec![
                ("md5", string(&report.md5)),
                ("sha1", string(&report.sha1)),
                ("sha256", string(&report.sha256)),
            ]),
        ),
        (
            "counts",
            obj(vec![
                ("sections", usize_value(report.sections.len())),
                ("imports", usize_value(report.imports.len())),
                ("imported_api_count", usize_value(imported_api_count)),
                ("exports", usize_value(report.exports.len())),
                ("stored_strings", usize_value(report.strings.len())),
                ("ascii_strings", usize_value(report.ascii_string_count)),
                ("utf16_strings", usize_value(report.utf16_string_count)),
                (
                    "resource_entries",
                    usize_value(report.resource_entries.len()),
                ),
                ("archive_entries", usize_value(report.archive_entries.len())),
                (
                    "archive_entries_omitted",
                    usize_value(report.archive_entries_omitted),
                ),
                (
                    "protection_findings",
                    usize_value(report.protection_findings.len()),
                ),
                ("xor_candidates", usize_value(report.xor_candidates.len())),
                (
                    "xor_common_key_hits",
                    usize_value(report.xor_common_key_hits.len()),
                ),
                ("xor_patterns", usize_value(report.xor_patterns.len())),
            ]),
        ),
        (
            "layout",
            obj(vec![
                ("format_name", string(&report.format_name)),
                ("format_family", string(&report.format_family)),
                ("detection_confidence", string(&report.detection_confidence)),
                ("machine_type", string(&report.machine_type)),
                (
                    "architecture",
                    string(if report.is_64bit {
                        "64-bit"
                    } else {
                        "32-bit / n.a."
                    }),
                ),
                ("subsystem", string(&report.subsystem)),
                ("image_base", u64_value(report.image_base)),
                ("entry_point", u64_value(report.entry_point)),
                ("section_alignment", u32_value(report.section_alignment)),
                ("file_alignment", u32_value(report.file_alignment)),
                ("timestamp", u32_value(report.timestamp)),
            ]),
        ),
        ("protections", protections_value(&report.protections)),
        (
            "headers",
            obj(vec![
                ("rich_headers", key_value_rows(&report.rich_headers)),
                ("dos_header", key_value_rows(&report.dos_header)),
                ("file_header", key_value_rows(&report.file_header)),
                ("optional_header", key_value_rows(&report.optional_header)),
            ]),
        ),
        ("sections", sections_value(&report.sections)),
        ("imports", imports_value(report)),
        ("exports", exports_value(report)),
        ("strings", strings_value(report)),
        (
            "resources",
            obj(vec![
                ("entries", resource_entries_value(&report.resource_entries)),
                (
                    "version_info_rows",
                    key_value_rows(&report.version_info_rows),
                ),
                ("pe_metadata_rows", key_value_rows(&report.pe_metadata_rows)),
                ("manifest_rows", key_value_rows(&report.manifest_rows)),
                ("manifest_text", opt_string(report.manifest_text.as_deref())),
            ]),
        ),
        (
            "archive",
            obj(vec![
                ("entries", archive_entries_value(report)),
                ("total_entries", usize_value(report.archive_entry_total)),
                (
                    "omitted_entries",
                    usize_value(report.archive_entries_omitted),
                ),
            ]),
        ),
        ("disassembly", disassembly_value(report)),
        (
            "notes",
            array(report.notes.iter().map(string).collect::<Vec<_>>()),
        ),
        ("protection_findings", protection_findings_value(report)),
        (
            "xor_analysis",
            obj(vec![
                ("candidates", xor_candidates_value(&report.xor_candidates)),
                (
                    "common_key_hits",
                    xor_candidates_value(&report.xor_common_key_hits),
                ),
                ("patterns", xor_patterns_value(report)),
            ]),
        ),
    ])
}

fn protections_value(flags: &ProtectionFlags) -> JsonValue {
    obj(vec![
        ("aslr", bool_value(flags.aslr)),
        ("dep_nx", bool_value(flags.dep_nx)),
        ("no_seh", bool_value(flags.no_seh)),
        ("seh_enabled", bool_value(flags.seh_enabled)),
        ("tls_callbacks", usize_value(flags.tls_callbacks)),
    ])
}

fn key_value_rows(rows: &[KeyValueRow]) -> JsonValue {
    array(
        rows.iter()
            .map(|row| {
                obj(vec![
                    ("key", string(&row.key)),
                    ("value", string(&row.value)),
                ])
            })
            .collect(),
    )
}

fn sections_value(sections: &[SectionInfo]) -> JsonValue {
    array(
        sections
            .iter()
            .map(|section| {
                obj(vec![
                    ("name", string(&section.name)),
                    ("virtual_address", u32_value(section.virtual_address)),
                    ("virtual_size", u32_value(section.virtual_size)),
                    ("raw_address", u32_value(section.raw_address)),
                    ("raw_size", u32_value(section.raw_size)),
                    ("characteristics", string(&section.characteristics)),
                    ("entropy", f32_value(section.entropy)),
                ])
            })
            .collect(),
    )
}

fn imports_value(report: &BinaryReport) -> JsonValue {
    array(
        report
            .imports
            .iter()
            .map(|dll| {
                obj(vec![
                    ("name", string(&dll.name)),
                    (
                        "functions",
                        array(
                            dll.functions
                                .iter()
                                .map(|function| {
                                    obj(vec![
                                        ("name", string(&function.name)),
                                        ("ordinal", u16_value(function.ordinal)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    )
}

fn exports_value(report: &BinaryReport) -> JsonValue {
    array(
        report
            .exports
            .iter()
            .map(|export| {
                obj(vec![
                    ("name", string(&export.name)),
                    ("offset", u64_value(export.offset)),
                    ("rva", u64_value(export.rva)),
                ])
            })
            .collect(),
    )
}

fn strings_value(report: &BinaryReport) -> JsonValue {
    array(
        report
            .strings
            .iter()
            .map(|entry| {
                obj(vec![
                    ("kind", string(entry.kind)),
                    ("offset", usize_value(entry.offset)),
                    ("value", string(&entry.value)),
                ])
            })
            .collect(),
    )
}

fn resource_entries_value(entries: &[ResourceEntry]) -> JsonValue {
    array(
        entries
            .iter()
            .map(|entry| {
                obj(vec![
                    ("depth", usize_value(entry.depth)),
                    ("name", string(&entry.name)),
                    ("path", string(&entry.path)),
                    ("kind", string(&entry.kind)),
                    ("size", usize_value(entry.size)),
                    ("code_page", u32_value(entry.code_page)),
                ])
            })
            .collect(),
    )
}

fn archive_entries_value(report: &BinaryReport) -> JsonValue {
    array(
        report
            .archive_entries
            .iter()
            .map(|entry| {
                obj(vec![
                    ("name", string(&entry.name)),
                    ("kind", string(&entry.kind)),
                    ("size", u64_value(entry.size)),
                ])
            })
            .collect(),
    )
}

fn disassembly_value(report: &BinaryReport) -> JsonValue {
    array(
        report
            .disassembly
            .iter()
            .map(|instruction| {
                obj(vec![
                    ("address", u64_value(instruction.address)),
                    ("bytes", string(&instruction.bytes)),
                    ("mnemonic", string(&instruction.mnemonic)),
                    ("operand", string(&instruction.operand)),
                ])
            })
            .collect(),
    )
}

fn protection_findings_value(report: &BinaryReport) -> JsonValue {
    array(
        report
            .protection_findings
            .iter()
            .map(|finding| {
                obj(vec![
                    ("title", string(&finding.title)),
                    ("detail", string(&finding.detail)),
                    ("severity", string(finding.severity)),
                ])
            })
            .collect(),
    )
}

fn xor_candidates_value(entries: &[crate::analyzer::XorCandidate]) -> JsonValue {
    array(
        entries
            .iter()
            .map(|candidate| {
                obj(vec![
                    ("source", string(&candidate.source)),
                    ("key", string(&candidate.key)),
                    ("readability", f32_value(candidate.readability)),
                    ("preview", string(&candidate.preview)),
                ])
            })
            .collect(),
    )
}

fn xor_patterns_value(report: &BinaryReport) -> JsonValue {
    array(
        report
            .xor_patterns
            .iter()
            .map(|pattern| {
                obj(vec![
                    ("length", usize_value(pattern.length)),
                    ("pattern", string(&pattern.pattern)),
                    ("count", usize_value(pattern.count)),
                ])
            })
            .collect(),
    )
}

fn render_object(output: &mut String, fields: &[(String, JsonValue)], indent: usize) {
    output.push('{');
    if fields.is_empty() {
        output.push('}');
        return;
    }

    output.push('\n');
    for (index, (key, value)) in fields.iter().enumerate() {
        push_indent(output, indent + 1);
        push_json_string(output, key);
        output.push_str(": ");
        value.render_pretty(output, indent + 1);
        if index + 1 != fields.len() {
            output.push(',');
        }
        output.push('\n');
    }
    push_indent(output, indent);
    output.push('}');
}

fn render_array(output: &mut String, values: &[JsonValue], indent: usize) {
    output.push('[');
    if values.is_empty() {
        output.push(']');
        return;
    }

    output.push('\n');
    for (index, value) in values.iter().enumerate() {
        push_indent(output, indent + 1);
        value.render_pretty(output, indent + 1);
        if index + 1 != values.len() {
            output.push(',');
        }
        output.push('\n');
    }
    push_indent(output, indent);
    output.push(']');
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0C}' => output.push_str("\\f"),
            ch if ch.is_control() => {
                let _ = write!(output, "\\u{:04X}", ch as u32);
            }
            ch => output.push(ch),
        }
    }
    output.push('"');
}

fn push_indent(output: &mut String, indent: usize) {
    for _ in 0..indent {
        output.push_str("  ");
    }
}

fn obj(fields: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn array(values: Vec<JsonValue>) -> JsonValue {
    JsonValue::Array(values)
}

fn string(value: impl Into<String>) -> JsonValue {
    JsonValue::String(value.into())
}

fn opt_string(value: Option<&str>) -> JsonValue {
    match value {
        Some(value) => string(value),
        None => JsonValue::Null,
    }
}

fn bool_value(value: bool) -> JsonValue {
    JsonValue::Bool(value)
}

fn usize_value(value: usize) -> JsonValue {
    JsonValue::Number(value.to_string())
}

fn u64_value(value: u64) -> JsonValue {
    JsonValue::Number(value.to_string())
}

fn u32_value(value: u32) -> JsonValue {
    JsonValue::Number(value.to_string())
}

fn u16_value(value: u16) -> JsonValue {
    JsonValue::Number(value.to_string())
}

fn f32_value(value: f32) -> JsonValue {
    JsonValue::Number(format!("{value:.4}"))
}

#[cfg(test)]
mod tests {
    use super::{default_snapshot_path, snapshot_json};
    use crate::analyzer::{
        ArchiveEntry, BinaryReport, DisassembledInstruction, ExportSymbol, ExtractedString,
        ImportDll, ImportFunction, KeyValueRow, ProtectionFinding, ProtectionFlags, ResourceEntry,
        SectionInfo, XorCandidate, XorPattern,
    };
    use std::path::PathBuf;

    fn sample_report() -> BinaryReport {
        BinaryReport {
            path: PathBuf::from("calc.exe"),
            file_size: 0x800,
            raw_bytes: vec![0x90, 0x90, 0xC3],
            md5: "md5".to_string(),
            sha1: "sha1".to_string(),
            sha256: "sha256".to_string(),
            ascii_string_count: 3,
            utf16_string_count: 1,
            format_name: "PE".to_string(),
            format_family: "Portable Executable".to_string(),
            detection_confidence: "Signature".to_string(),
            machine_type: "x86".to_string(),
            section_count: 1,
            is_64bit: false,
            subsystem: "Windows GUI".to_string(),
            image_base: 0x400000,
            entry_point: 0x401000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            timestamp: 0x1234_5678,
            sections: vec![SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x600,
                raw_address: 0x400,
                raw_size: 0x600,
                characteristics: "EXEC | READ".to_string(),
                entropy: 6.1,
            }],
            imports: vec![ImportDll {
                name: "KERNEL32.dll".to_string(),
                functions: vec![ImportFunction {
                    name: "LoadLibraryA".to_string(),
                    ordinal: 0,
                }],
            }],
            exports: vec![ExportSymbol {
                name: "Exported".to_string(),
                offset: 0x420,
                rva: 0x1020,
            }],
            strings: vec![ExtractedString {
                kind: "ASCII",
                offset: 0x120,
                value: "CreateFileA".to_string(),
            }],
            rich_headers: vec![KeyValueRow {
                key: "DanS".to_string(),
                value: "present".to_string(),
            }],
            dos_header: vec![KeyValueRow {
                key: "e_magic".to_string(),
                value: "MZ".to_string(),
            }],
            file_header: vec![KeyValueRow {
                key: "Machine".to_string(),
                value: "0x14C".to_string(),
            }],
            optional_header: vec![KeyValueRow {
                key: "AddressOfEntryPoint".to_string(),
                value: "0x1000".to_string(),
            }],
            disassembly: vec![DisassembledInstruction {
                address: 0x401000,
                bytes: "55 8B EC".to_string(),
                mnemonic: "push".to_string(),
                operand: "ebp".to_string(),
            }],
            archive_entries: vec![ArchiveEntry {
                name: "payload.bin".to_string(),
                kind: "file".to_string(),
                size: 512,
            }],
            archive_entry_total: 3,
            archive_entries_omitted: 2,
            resource_entries: vec![ResourceEntry {
                depth: 1,
                name: "RT_MANIFEST".to_string(),
                path: "RT_MANIFEST/1/1033".to_string(),
                kind: "data".to_string(),
                size: 128,
                code_page: 1200,
            }],
            version_info_rows: vec![KeyValueRow {
                key: "CompanyName".to_string(),
                value: "Blackpoint Labs".to_string(),
            }],
            pe_metadata_rows: vec![KeyValueRow {
                key: "PDB Path".to_string(),
                value: "calc.pdb".to_string(),
            }],
            manifest_rows: vec![KeyValueRow {
                key: "Requested Execution Level".to_string(),
                value: "asInvoker".to_string(),
            }],
            manifest_text: Some("<manifest/>".to_string()),
            notes: vec!["heuristic note".to_string()],
            protections: ProtectionFlags {
                aslr: true,
                dep_nx: true,
                no_seh: false,
                seh_enabled: true,
                tls_callbacks: 1,
            },
            protection_findings: vec![ProtectionFinding {
                title: "Packed import surface".to_string(),
                detail: "Suspicious import cluster".to_string(),
                severity: "medium",
            }],
            xor_candidates: vec![XorCandidate {
                source: "Entry block".to_string(),
                key: "0x41".to_string(),
                readability: 0.72,
                preview: "This program".to_string(),
            }],
            xor_patterns: vec![XorPattern {
                length: 4,
                pattern: "41 42 43 44".to_string(),
                count: 3,
            }],
            xor_common_key_hits: vec![XorCandidate {
                source: "String pool".to_string(),
                key: "0x20".to_string(),
                readability: 0.81,
                preview: "kernel32".to_string(),
            }],
        }
    }

    #[test]
    fn default_snapshot_path_uses_blackpoint_suffix() {
        let report = sample_report();
        assert_eq!(
            default_snapshot_path(&report),
            PathBuf::from("calc.blackpoint.json")
        );
    }

    #[test]
    fn snapshot_json_omits_raw_bytes_and_preserves_core_sections() {
        let json = snapshot_json(&sample_report()).expect("snapshot JSON should serialize");
        assert!(json.ends_with('\n'));
        assert!(json.contains("\"schema_version\": \"blackpoint.snapshot/v1\""));
        assert!(json.contains("\"file_name\": \"calc.exe\""));
        assert!(json.contains("\"raw_bytes_included\": false"));
        assert!(json.contains("\"stored_strings\": 1"));
        assert!(json.contains("\"total_entries\": 3"));
        assert!(json.contains("\"omitted_entries\": 2"));
        assert!(json.contains("\"manifest_text\": \"<manifest/>\""));
        assert!(json.contains("\"sha256\": \"sha256\""));
        assert!(!json.contains("\"raw_bytes\""));
    }
}
