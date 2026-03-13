use anyhow::{anyhow, Context, Result};
use capstone::prelude::*;
use flate2::read::GzDecoder;
use goblin::{mach::Mach, pe::PE, Object};
use md5::Md5;
use pelite::{
    resources::{version_info::VersionInfo, Directory as ResourceDirectory, Entry as ResourceKind},
    PeFile,
};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tar::Archive;
use zip::ZipArchive;

#[derive(Clone, Debug)]
pub struct BinaryReport {
    pub path: PathBuf,
    pub file_size: usize,
    pub raw_bytes: Vec<u8>,
    pub md5: String,
    pub sha1: String,
    pub sha256_placeholder: String,
    pub format_name: String,
    pub format_family: String,
    pub detection_confidence: String,
    pub machine_type: String,
    pub section_count: usize,
    pub is_64bit: bool,
    pub subsystem: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub timestamp: u32,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportDll>,
    pub exports: Vec<ExportSymbol>,
    pub strings: Vec<ExtractedString>,
    pub rich_headers: Vec<KeyValueRow>,
    pub dos_header: Vec<KeyValueRow>,
    pub file_header: Vec<KeyValueRow>,
    pub optional_header: Vec<KeyValueRow>,
    pub disassembly: Vec<DisassembledInstruction>,
    pub archive_entries: Vec<ArchiveEntry>,
    pub resource_entries: Vec<ResourceEntry>,
    pub version_info_rows: Vec<KeyValueRow>,
    pub pe_metadata_rows: Vec<KeyValueRow>,
    pub manifest_rows: Vec<KeyValueRow>,
    pub manifest_text: Option<String>,
    pub notes: Vec<String>,
    pub protections: ProtectionFlags,
    pub protection_findings: Vec<ProtectionFinding>,
    pub xor_candidates: Vec<XorCandidate>,
    pub xor_patterns: Vec<XorPattern>,
    pub xor_common_key_hits: Vec<XorCandidate>,
}

#[derive(Clone, Debug)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_address: u32,
    pub raw_size: u32,
    pub characteristics: String,
    pub entropy: f32,
}

#[derive(Clone, Debug)]
pub struct ImportDll {
    pub name: String,
    pub functions: Vec<ImportFunction>,
}

#[derive(Clone, Debug)]
pub struct ImportFunction {
    pub name: String,
    pub ordinal: u16,
}

#[derive(Clone, Debug)]
pub struct ExportSymbol {
    pub name: String,
    pub offset: u64,
    pub rva: u64,
}

#[derive(Clone, Debug)]
pub struct ExtractedString {
    pub kind: &'static str,
    pub offset: usize,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct DisassembledInstruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operand: String,
}

#[derive(Clone, Debug)]
pub struct KeyValueRow {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct ArchiveEntry {
    pub name: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct ResourceEntry {
    pub depth: usize,
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: usize,
    pub code_page: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ProtectionFlags {
    pub aslr: bool,
    pub dep_nx: bool,
    pub no_seh: bool,
    pub seh_enabled: bool,
    pub tls_callbacks: usize,
}

#[derive(Clone, Debug)]
pub struct ProtectionFinding {
    pub title: String,
    pub detail: String,
    pub severity: &'static str,
}

#[derive(Clone, Debug)]
pub struct XorCandidate {
    pub source: String,
    pub key: String,
    pub readability: f32,
    pub preview: String,
}

#[derive(Clone, Debug)]
pub struct XorPattern {
    pub length: usize,
    pub pattern: String,
    pub count: usize,
}

#[derive(Clone, Debug)]
struct DetectedFormat {
    name: String,
    family: String,
    confidence: String,
    notes: Vec<String>,
}

pub fn analyze_file(path: impl AsRef<Path>) -> Result<BinaryReport> {
    let path = path.as_ref().to_path_buf();
    let buffer = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut report = base_report(path.clone(), &buffer);
    let detected = detect_file_format(&path, &buffer);

    report.format_name = detected.name;
    report.format_family = detected.family;
    report.detection_confidence = detected.confidence;
    report.notes.extend(detected.notes);

    match Object::parse(&buffer) {
        Ok(Object::PE(pe)) => {
            populate_pe_report(&mut report, &pe, &buffer)?;
        }
        Ok(Object::Elf(elf)) => {
            populate_elf_report(&mut report, &elf, &buffer);
        }
        Ok(Object::Mach(Mach::Binary(macho))) => {
            populate_mach_report(&mut report, &macho, &buffer);
        }
        Ok(Object::Mach(Mach::Fat(_))) => {
            report.notes.push("Fat Mach-O detected; thin-slice parsing is not yet implemented.".to_string());
        }
        Ok(Object::Archive(_)) => {
            report.notes.push("UNIX archive container detected.".to_string());
        }
        Ok(Object::Unknown(_)) | Ok(_) | Err(_) => {
            report.notes.push("Structured parser did not fully recognize this file; heuristic analysis applied.".to_string());
        }
    }

    if is_zip_like(&path, &buffer) {
        report.archive_entries = zip_entries(&buffer)?;
        if report.notes.iter().all(|note| !note.contains("ZIP central directory")) {
            report
                .notes
                .push("ZIP central directory parsed successfully.".to_string());
        }
    } else if is_gzip(&buffer) && path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("tgz")) {
        report.archive_entries = tgz_entries(&buffer)?;
        report
            .notes
            .push("tar.gz package members parsed successfully.".to_string());
    } else if report.format_name == "ISO9660" {
        report.notes.push("ISO9660 volume signature found. Full filesystem walk is planned.".to_string());
    }

    populate_xor_analysis(&mut report, &buffer);

    Ok(report)
}

fn base_report(path: PathBuf, buffer: &[u8]) -> BinaryReport {
    BinaryReport {
        path,
        file_size: buffer.len(),
        raw_bytes: buffer.to_vec(),
        md5: hex_digest::<Md5>(buffer),
        sha1: hex_digest::<Sha1>(buffer),
        sha256_placeholder: hex_sha256(buffer),
        format_name: "Binary".to_string(),
        format_family: "Unclassified".to_string(),
        detection_confidence: "Heuristic".to_string(),
        machine_type: "Unknown".to_string(),
        section_count: 0,
        is_64bit: false,
        subsystem: "Unknown".to_string(),
        image_base: 0,
        entry_point: 0,
        section_alignment: 0,
        file_alignment: 0,
        timestamp: 0,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: extract_strings(buffer, 4),
        rich_headers: vec![KeyValueRow {
            key: "Status".to_string(),
            value: "No rich header data for this format.".to_string(),
        }],
        dos_header: vec![KeyValueRow {
            key: "Status".to_string(),
            value: "No DOS header".to_string(),
        }],
        file_header: vec![KeyValueRow {
            key: "Status".to_string(),
            value: "No COFF/File header".to_string(),
        }],
        optional_header: vec![KeyValueRow {
            key: "Status".to_string(),
            value: "No optional header".to_string(),
        }],
        disassembly: Vec::new(),
        archive_entries: Vec::new(),
        resource_entries: Vec::new(),
        version_info_rows: Vec::new(),
        pe_metadata_rows: Vec::new(),
        manifest_rows: Vec::new(),
        manifest_text: None,
        notes: vec!["Static heuristic scan completed.".to_string()],
        protections: ProtectionFlags::default(),
        protection_findings: Vec::new(),
        xor_candidates: Vec::new(),
        xor_patterns: Vec::new(),
        xor_common_key_hits: Vec::new(),
    }
}

fn populate_pe_report(report: &mut BinaryReport, pe: &PE, buffer: &[u8]) -> Result<()> {
    let header = &pe.header;
    let optional = header
        .optional_header
        .as_ref()
        .ok_or_else(|| anyhow!("optional header missing"))?;

    report.format_name = "PE".to_string();
    report.format_family = "Portable Executable".to_string();
    report.detection_confidence = "Signature".to_string();
    report.machine_type = goblin::pe::header::machine_to_str(header.coff_header.machine).to_string();
    report.section_count = header.coff_header.number_of_sections as usize;
    report.is_64bit = pe.is_64;
    report.subsystem = decode_subsystem(optional.windows_fields.subsystem).to_string();
    report.image_base = optional.windows_fields.image_base;
    report.entry_point = optional.standard_fields.address_of_entry_point;
    report.section_alignment = optional.windows_fields.section_alignment;
    report.file_alignment = optional.windows_fields.file_alignment;
    report.timestamp = header.coff_header.time_date_stamp;

    report.sections = pe
        .sections
        .iter()
        .map(|section| {
            let raw_start = section.pointer_to_raw_data as usize;
            let raw_end = raw_start.saturating_add(section.size_of_raw_data as usize);
            let slice = buffer.get(raw_start..raw_end).unwrap_or(&[]);

            SectionInfo {
                name: section.name().unwrap_or("<invalid>").to_string(),
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_address: section.pointer_to_raw_data,
                raw_size: section.size_of_raw_data,
                characteristics: format_section_characteristics(section.characteristics),
                entropy: shannon_entropy(slice),
            }
        })
        .collect();

    let mut imports_by_dll: Vec<ImportDll> = Vec::new();
    for import in &pe.imports {
        if let Some(existing) = imports_by_dll
            .iter_mut()
            .find(|dll| dll.name.eq_ignore_ascii_case(import.dll))
        {
            existing.functions.push(ImportFunction {
                name: import.name.to_string(),
                ordinal: import.ordinal,
            });
        } else {
            imports_by_dll.push(ImportDll {
                name: import.dll.to_string(),
                functions: vec![ImportFunction {
                    name: import.name.to_string(),
                    ordinal: import.ordinal,
                }],
            });
        }
    }
    report.imports = imports_by_dll;

    report.exports = pe
        .exports
        .iter()
        .map(|export| ExportSymbol {
            name: export.name.unwrap_or("<ordinal>").to_string(),
            offset: export.offset.map(|offset| offset as u64).unwrap_or_default(),
            rva: export.rva as u64,
        })
        .collect();

    report.dos_header = vec![
        KeyValueRow {
            key: "Magic".to_string(),
            value: format!("0x{:04X}", header.dos_header.signature),
        },
        KeyValueRow {
            key: "BytesOnLastPage".to_string(),
            value: format!("0x{:04X}", header.dos_header.bytes_on_last_page),
        },
        KeyValueRow {
            key: "PagesInFile".to_string(),
            value: format!("0x{:04X}", header.dos_header.pages_in_file),
        },
        KeyValueRow {
            key: "PE Offset".to_string(),
            value: format!("0x{:08X}", header.dos_header.pe_pointer),
        },
        KeyValueRow {
            key: "RelocationTable".to_string(),
            value: format!("0x{:04X}", header.dos_header.file_address_of_relocation_table),
        },
    ];

    report.file_header = vec![
        KeyValueRow {
            key: "Machine".to_string(),
            value: format!(
                "{} (0x{:04X})",
                goblin::pe::header::machine_to_str(header.coff_header.machine),
                header.coff_header.machine
            ),
        },
        KeyValueRow {
            key: "NumberOfSections".to_string(),
            value: format!("{}", header.coff_header.number_of_sections),
        },
        KeyValueRow {
            key: "TimeDateStamp".to_string(),
            value: format!("0x{:08X}", header.coff_header.time_date_stamp),
        },
        KeyValueRow {
            key: "PointerToSymbolTable".to_string(),
            value: format!("0x{:08X}", header.coff_header.pointer_to_symbol_table),
        },
        KeyValueRow {
            key: "NumberOfSymbols".to_string(),
            value: format!("{}", header.coff_header.number_of_symbol_table),
        },
        KeyValueRow {
            key: "SizeOfOptionalHeader".to_string(),
            value: format!("0x{:04X}", header.coff_header.size_of_optional_header),
        },
        KeyValueRow {
            key: "Characteristics".to_string(),
            value: format!("0x{:04X}", header.coff_header.characteristics),
        },
    ];

    report.optional_header = vec![
        KeyValueRow {
            key: "Magic".to_string(),
            value: format!("0x{:04X}", optional.standard_fields.magic),
        },
        KeyValueRow {
            key: "LinkerVersion".to_string(),
            value: format!(
                "{}.{}",
                optional.standard_fields.major_linker_version, optional.standard_fields.minor_linker_version
            ),
        },
        KeyValueRow {
            key: "AddressOfEntryPoint".to_string(),
            value: format!("0x{:08X}", optional.standard_fields.address_of_entry_point),
        },
        KeyValueRow {
            key: "BaseOfCode".to_string(),
            value: format!("0x{:X}", optional.standard_fields.base_of_code),
        },
        KeyValueRow {
            key: "BaseOfData".to_string(),
            value: format!("0x{:X}", optional.standard_fields.base_of_data),
        },
        KeyValueRow {
            key: "ImageBase".to_string(),
            value: format!("0x{:X}", optional.windows_fields.image_base),
        },
        KeyValueRow {
            key: "Subsystem".to_string(),
            value: decode_subsystem(optional.windows_fields.subsystem).to_string(),
        },
        KeyValueRow {
            key: "DLL Characteristics".to_string(),
            value: format!("0x{:04X}", optional.windows_fields.dll_characteristics),
        },
        KeyValueRow {
            key: "SizeOfImage".to_string(),
            value: format!("0x{:X}", optional.windows_fields.size_of_image),
        },
        KeyValueRow {
            key: "SizeOfHeaders".to_string(),
            value: format!("0x{:X}", optional.windows_fields.size_of_headers),
        },
        KeyValueRow {
            key: "Checksum".to_string(),
            value: format!("0x{:X}", optional.windows_fields.check_sum),
        },
        KeyValueRow {
            key: "StackReserve".to_string(),
            value: format!("0x{:X}", optional.windows_fields.size_of_stack_reserve),
        },
        KeyValueRow {
            key: "HeapReserve".to_string(),
            value: format!("0x{:X}", optional.windows_fields.size_of_heap_reserve),
        },
    ];

    report.pe_metadata_rows = build_pe_metadata_rows(pe, buffer, optional);

    report.disassembly = disassemble_entry_block(pe, buffer, optional.standard_fields.address_of_entry_point)?;
    report.protections = build_pe_protections(pe, optional.windows_fields.dll_characteristics);
    report.protection_findings = build_protection_findings(report, pe);
    populate_pe_resources(report, buffer);

    if report.sections.iter().any(|section| section.entropy >= 7.2) {
        report
            .notes
            .push("High-entropy section detected; packed or encrypted payload is possible.".to_string());
    }

    Ok(())
}

fn populate_pe_resources(report: &mut BinaryReport, buffer: &[u8]) {
    let pe_file = match PeFile::from_bytes(buffer) {
        Ok(file) => file,
        Err(err) => {
            report
                .notes
                .push(format!("PE resource parser could not initialize: {err}"));
            return;
        }
    };

    let resources = match pe_file.resources() {
        Ok(resources) => resources,
        Err(_) => return,
    };

    if let Err(err) = resources.fsck() {
        report
            .notes
            .push(format!("Resources directory integrity issue detected: {err}"));
    }

    match resources.root() {
        Ok(root) => collect_resource_entries(root, 0, String::new(), &mut report.resource_entries),
        Err(err) => report
            .notes
            .push(format!("Resources directory exists but could not be enumerated: {err}")),
    }

    if let Ok(version_info) = resources.version_info() {
        report.version_info_rows = build_version_info_rows(version_info);
    }

    if let Ok(manifest) = resources.manifest() {
        let manifest = manifest.trim().to_string();
        report.manifest_rows = build_manifest_rows(&manifest);
        report.manifest_text = Some(manifest.clone());

        if let Some(level) = manifest_execution_level(&manifest) {
            report.notes.push(format!("Application manifest requests `{level}` execution level."));
        }
    }
}

fn collect_resource_entries(
    directory: ResourceDirectory<'_>,
    depth: usize,
    prefix: String,
    output: &mut Vec<ResourceEntry>,
) {
    for entry in directory.entries() {
        let name = entry
            .name()
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "<invalid>".to_string());
        let path = if prefix.is_empty() {
            format!("/{name}")
        } else {
            format!("{prefix}/{name}")
        };

        match entry.entry() {
            Ok(ResourceKind::Directory(child)) => {
                output.push(ResourceEntry {
                    depth,
                    name: name.clone(),
                    path: path.clone(),
                    kind: "Directory".to_string(),
                    size: 0,
                    code_page: 0,
                });
                collect_resource_entries(child, depth + 1, path, output);
            }
            Ok(ResourceKind::DataEntry(data)) => {
                output.push(ResourceEntry {
                    depth,
                    name,
                    path,
                    kind: "Data".to_string(),
                    size: data.size(),
                    code_page: data.code_page(),
                });
            }
            Err(err) => output.push(ResourceEntry {
                depth,
                name,
                path,
                kind: format!("Error: {err}"),
                size: 0,
                code_page: 0,
            }),
        }
    }
}

fn build_version_info_rows(version_info: VersionInfo<'_>) -> Vec<KeyValueRow> {
    let mut rows = Vec::new();

    if let Some(fixed) = version_info.fixed() {
        rows.push(KeyValueRow {
            key: "FileVersion".to_string(),
            value: format!(
                "{}.{}.{}.{}",
                fixed.dwFileVersion.Major,
                fixed.dwFileVersion.Minor,
                fixed.dwFileVersion.Patch,
                fixed.dwFileVersion.Build
            ),
        });
        rows.push(KeyValueRow {
            key: "ProductVersion".to_string(),
            value: format!(
                "{}.{}.{}.{}",
                fixed.dwProductVersion.Major,
                fixed.dwProductVersion.Minor,
                fixed.dwProductVersion.Patch,
                fixed.dwProductVersion.Build
            ),
        });
        rows.push(KeyValueRow {
            key: "FileFlagsMask".to_string(),
            value: format!("0x{:X}", fixed.dwFileFlagsMask),
        });
        rows.push(KeyValueRow {
            key: "FileFlags".to_string(),
            value: format!("0x{:X}", fixed.dwFileFlags),
        });
        rows.push(KeyValueRow {
            key: "FileOS".to_string(),
            value: format!("0x{:X}", fixed.dwFileOS),
        });
        rows.push(KeyValueRow {
            key: "FileType".to_string(),
            value: format!("0x{:X}", fixed.dwFileType),
        });
        rows.push(KeyValueRow {
            key: "FileSubtype".to_string(),
            value: format!("0x{:X}", fixed.dwFileSubtype),
        });
    }

    let translations = version_info.translation();
    if !translations.is_empty() {
        rows.push(KeyValueRow {
            key: "Translations".to_string(),
            value: translations
                .iter()
                .map(|lang| lang.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    let file_info = version_info.file_info();
    let mut languages = file_info.strings.into_iter().collect::<Vec<_>>();
    languages.sort_by_key(|(lang, _)| lang.to_string());

    for (language, map) in languages {
        let mut string_rows = map.into_iter().collect::<Vec<_>>();
        string_rows.sort_by(|a, b| a.0.cmp(&b.0));

        for (key, value) in string_rows {
            rows.push(KeyValueRow {
                key: format!("[{language}] {key}"),
                value,
            });
        }
    }

    rows
}

fn build_manifest_rows(manifest: &str) -> Vec<KeyValueRow> {
    let manifest_lower = manifest.to_ascii_lowercase();
    let execution_level = manifest_execution_level(manifest).unwrap_or("Not declared");
    let auto_elevate = contains_any(&manifest_lower, &["<autoelevate>true</autoelevate>"]);
    let long_path = contains_any(&manifest_lower, &["<longpathaware>true</longpathaware>"]);
    let dpi_aware = contains_any(
        &manifest_lower,
        &[
            "<dpiaware>true",
            "<dpiawareness>",
            "<gdiscaling>true</gdiscaling>",
        ],
    );
    let ui_access = contains_any(&manifest_lower, &["uiaccess='true'", "uiaccess=\"true\""]);

    vec![
        KeyValueRow {
            key: "Execution Level".to_string(),
            value: execution_level.to_string(),
        },
        KeyValueRow {
            key: "Auto Elevate".to_string(),
            value: bool_badge(auto_elevate).to_string(),
        },
        KeyValueRow {
            key: "Long Path Aware".to_string(),
            value: bool_badge(long_path).to_string(),
        },
        KeyValueRow {
            key: "DPI Aware".to_string(),
            value: bool_badge(dpi_aware).to_string(),
        },
        KeyValueRow {
            key: "UI Access".to_string(),
            value: bool_badge(ui_access).to_string(),
        },
    ]
}

fn manifest_execution_level(manifest: &str) -> Option<&'static str> {
    let lower = manifest.to_ascii_lowercase();
    if lower.contains("requireadministrator") {
        Some("requireAdministrator")
    } else if lower.contains("highestavailable") {
        Some("highestAvailable")
    } else if lower.contains("asinvoker") {
        Some("asInvoker")
    } else {
        None
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn bool_badge(value: bool) -> &'static str {
    if value {
        "Enabled"
    } else {
        "Disabled"
    }
}

fn build_pe_metadata_rows(
    pe: &PE,
    buffer: &[u8],
    optional: &goblin::pe::optional_header::OptionalHeader,
) -> Vec<KeyValueRow> {
    let directories = &optional.data_directories;
    let mut rows = vec![
        KeyValueRow {
            key: "Overlay".to_string(),
            value: match file_overlay_size(pe, buffer, optional) {
                0 => "None".to_string(),
                size => format!("{size} bytes"),
            },
        },
        KeyValueRow {
            key: "Certificate Table".to_string(),
            value: match directories.get_certificate_table() {
                Some(entry) => format!("Present (size 0x{:X})", entry.size),
                None => "Missing".to_string(),
            },
        },
        KeyValueRow {
            key: "Delay Imports".to_string(),
            value: bool_badge(directories.get_delay_import_descriptor().is_some()).to_string(),
        },
        KeyValueRow {
            key: "CLR Header".to_string(),
            value: bool_badge(directories.get_clr_runtime_header().is_some()).to_string(),
        },
        KeyValueRow {
            key: "Load Config".to_string(),
            value: bool_badge(directories.get_load_config_table().is_some()).to_string(),
        },
        KeyValueRow {
            key: "Bound Imports".to_string(),
            value: bool_badge(directories.get_bound_import_table().is_some()).to_string(),
        },
    ];

    if let Ok(file) = PeFile::from_bytes(buffer) {
        if let Ok(debug) = file.debug() {
            rows.push(KeyValueRow {
                key: "Debug Entries".to_string(),
                value: debug.image().len().to_string(),
            });
            if let Some(pdb) = debug.pdb_file_name() {
                rows.push(KeyValueRow {
                    key: "PDB Path".to_string(),
                    value: pdb.to_string(),
                });
            }
        }
    }

    rows
}

fn file_overlay_size(
    pe: &PE,
    buffer: &[u8],
    optional: &goblin::pe::optional_header::OptionalHeader,
) -> usize {
    let section_end = pe
        .sections
        .iter()
        .map(|section| section.pointer_to_raw_data as usize + section.size_of_raw_data as usize)
        .max()
        .unwrap_or(0);
    let certificate_end = optional
        .data_directories
        .get_certificate_table()
        .map(|entry| entry.virtual_address as usize + entry.size as usize)
        .unwrap_or(0);
    let structured_end = section_end.max(certificate_end).min(buffer.len());

    buffer.len().saturating_sub(structured_end)
}

fn populate_elf_report(report: &mut BinaryReport, elf: &goblin::elf::Elf, buffer: &[u8]) {
    report.format_name = "ELF".to_string();
    report.format_family = "Executable and Linkable Format".to_string();
    report.detection_confidence = "Signature".to_string();
    report.is_64bit = elf.is_64;
    report.entry_point = elf.entry;
    report.subsystem = match elf.header.e_type {
        goblin::elf::header::ET_EXEC => "Executable",
        goblin::elf::header::ET_DYN => "Shared Object / PIE",
        goblin::elf::header::ET_REL => "Relocatable",
        _ => "Other",
    }
    .to_string();

    report.sections = elf
        .section_headers
        .iter()
        .enumerate()
        .map(|(index, section)| {
            let name = elf
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or("<unnamed>")
                .to_string();
            let raw_start = section.sh_offset as usize;
            let raw_end = raw_start.saturating_add(section.sh_size as usize);
            let slice = buffer.get(raw_start..raw_end).unwrap_or(&[]);

            SectionInfo {
                name: if name.is_empty() { format!("section_{index}") } else { name },
                virtual_address: section.sh_addr as u32,
                virtual_size: section.sh_size as u32,
                raw_address: section.sh_offset as u32,
                raw_size: section.sh_size as u32,
                characteristics: format!("0x{:X}", section.sh_flags),
                entropy: shannon_entropy(slice),
            }
        })
        .collect();

    report.imports = elf
        .libraries
        .iter()
        .map(|lib| ImportDll {
            name: (*lib).to_string(),
            functions: Vec::new(),
        })
        .collect();

    report.optional_header = vec![
        KeyValueRow {
            key: "Machine".to_string(),
            value: format!("0x{:X}", elf.header.e_machine),
        },
        KeyValueRow {
            key: "Entry".to_string(),
            value: format!("0x{:X}", elf.entry),
        },
        KeyValueRow {
            key: "Type".to_string(),
            value: report.subsystem.clone(),
        },
    ];

    report.notes.push("ELF parsing is active; relocation and symbol detail can be extended next.".to_string());
}

fn populate_mach_report(report: &mut BinaryReport, macho: &goblin::mach::MachO, _buffer: &[u8]) {
    report.format_name = "MACH".to_string();
    report.format_family = "Mach-O".to_string();
    report.detection_confidence = "Signature".to_string();
    report.is_64bit = macho.is_64;
    report.entry_point = macho.entry;
    report.subsystem = "Mach-O Binary".to_string();

    report.sections = macho
        .segments
        .sections()
        .flatten()
        .filter_map(Result::ok)
        .map(|(section, _)| SectionInfo {
            name: section.name().unwrap_or("<unnamed>").to_string(),
            virtual_address: section.addr as u32,
            virtual_size: section.size as u32,
            raw_address: section.offset,
            raw_size: section.size as u32,
            characteristics: format!("flags=0x{:X}", section.flags),
            entropy: 0.0,
        })
        .collect();

    report.optional_header = vec![
        KeyValueRow {
            key: "CPU".to_string(),
            value: format!("0x{:X}", macho.header.cputype),
        },
        KeyValueRow {
            key: "FileType".to_string(),
            value: format!("0x{:X}", macho.header.filetype),
        },
        KeyValueRow {
            key: "Entry".to_string(),
            value: format!("0x{:X}", macho.entry),
        },
    ];

    report.notes.push("Mach-O parsing is active; load command detail can be expanded next.".to_string());
}

fn detect_file_format(path: &Path, bytes: &[u8]) -> DetectedFormat {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if bytes.starts_with(b"MZ") {
        if let Some(pe_offset) = pe_offset(bytes) {
            if bytes.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0") {
                return format_hit("PE", "Portable Executable", "Signature", vec!["DOS stub and PE signature matched.".to_string()]);
            }
            if bytes.get(pe_offset..pe_offset + 2) == Some(b"LE") {
                return format_hit("LE/LX", "Linear Executable", "Signature", vec!["Linear Executable header detected at e_lfanew.".to_string()]);
            }
            if bytes.get(pe_offset..pe_offset + 2) == Some(b"LX") {
                return format_hit("LE/LX", "Linear Executable", "Signature", vec!["LX executable header detected at e_lfanew.".to_string()]);
            }
        }
        return format_hit("MS-DOS", "DOS Executable", "Heuristic", vec!["MZ header found without a valid PE signature.".to_string()]);
    }

    if bytes.starts_with(b"\x7FELF") {
        return format_hit("ELF", "Executable and Linkable Format", "Signature", vec!["ELF magic matched.".to_string()]);
    }

    if is_macho_magic(bytes) {
        return format_hit("MACH", "Mach-O", "Signature", vec!["Mach-O magic matched.".to_string()]);
    }

    if is_dex(bytes) {
        return format_hit("DEX", "Dalvik Executable", "Signature", vec!["DEX magic matched.".to_string()]);
    }

    if is_iso9660(bytes) {
        return format_hit("ISO9660", "Optical Media Image", "Signature", vec!["CD001 volume descriptor signature matched.".to_string()]);
    }

    if is_zip_like(path, bytes) {
        let name = match extension.as_str() {
            "apk" => "APK",
            "ipa" => "IPA",
            "jar" => "JAR",
            _ => "ZIP",
        };
        return format_hit(name, "ZIP Container", "Signature", vec!["ZIP local file header matched.".to_string()]);
    }

    if extension == "com" {
        return format_hit("COM", "DOS COM", "Heuristic", vec![".com extension with flat binary layout heuristic.".to_string()]);
    }

    if (extension == "tgz" || extension == "npm") && is_gzip(bytes) {
        return format_hit("NPM", "Node Package Archive", "Heuristic", vec!["gzip-compressed package archive detected.".to_string()]);
    }

    if is_amiga_hunk(bytes) {
        return format_hit("Amiga", "Amiga Hunk Executable", "Signature", vec!["Amiga hunk header magic matched.".to_string()]);
    }

    format_hit("Binary", "Unclassified", "Heuristic", vec!["No primary signature matched; generic binary heuristics used.".to_string()])
}

fn format_hit(name: &str, family: &str, confidence: &str, notes: Vec<String>) -> DetectedFormat {
    DetectedFormat {
        name: name.to_string(),
        family: family.to_string(),
        confidence: confidence.to_string(),
        notes,
    }
}

fn pe_offset(bytes: &[u8]) -> Option<usize> {
    let offset = bytes.get(0x3C..0x40)?;
    Some(u32::from_le_bytes(offset.try_into().ok()?) as usize)
}

fn is_macho_magic(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some([0xFE, 0xED, 0xFA, 0xCE])
            | Some([0xFE, 0xED, 0xFA, 0xCF])
            | Some([0xCE, 0xFA, 0xED, 0xFE])
            | Some([0xCF, 0xFA, 0xED, 0xFE])
            | Some([0xCA, 0xFE, 0xBA, 0xBE])
    )
}

fn is_zip_like(path: &Path, bytes: &[u8]) -> bool {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or_default();
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
        || matches!(ext.to_ascii_lowercase().as_str(), "zip" | "apk" | "ipa" | "jar")
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1F, 0x8B])
}

fn is_dex(bytes: &[u8]) -> bool {
    bytes.starts_with(b"dex\n")
}

fn is_iso9660(bytes: &[u8]) -> bool {
    bytes.get(0x8001..0x8006) == Some(b"CD001") || bytes.get(0x8801..0x8806) == Some(b"CD001")
}

fn is_amiga_hunk(bytes: &[u8]) -> bool {
    bytes.get(0..4) == Some(&[0x00, 0x00, 0x03, 0xF3])
}

fn zip_entries(bytes: &[u8]) -> Result<Vec<ArchiveEntry>> {
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).map_err(|err| anyhow!("zip parse failed: {err}"))?;
    let mut entries = Vec::new();

    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|err| anyhow!("zip entry read failed: {err}"))?;
        entries.push(ArchiveEntry {
            name: file.name().to_string(),
            kind: if file.is_dir() { "Directory" } else { "File" }.to_string(),
            size: file.size(),
        });
    }

    Ok(entries)
}

fn tgz_entries(bytes: &[u8]) -> Result<Vec<ArchiveEntry>> {
    let cursor = Cursor::new(bytes);
    let decoder = GzDecoder::new(cursor);
    let mut archive = Archive::new(decoder);
    let mut entries = Vec::new();

    for item in archive.entries().map_err(|err| anyhow!("tar entries failed: {err}"))? {
        let file = item.map_err(|err| anyhow!("tar member read failed: {err}"))?;
        let path = file
            .path()
            .map_err(|err| anyhow!("tar member path failed: {err}"))?
            .display()
            .to_string();
        let size = file.header().size().unwrap_or(0);
        entries.push(ArchiveEntry {
            name: path,
            kind: "File".to_string(),
            size,
        });
    }

    Ok(entries)
}

fn decode_subsystem(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows Boot Application",
        _ => "Unknown",
    }
}

fn format_section_characteristics(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x20000000 != 0 {
        parts.push("EXEC");
    }
    if flags & 0x40000000 != 0 {
        parts.push("READ");
    }
    if flags & 0x80000000 != 0 {
        parts.push("WRITE");
    }
    if flags & 0x00000020 != 0 {
        parts.push("CODE");
    }
    if flags & 0x00000040 != 0 {
        parts.push("INIT");
    }
    if flags & 0x00000080 != 0 {
        parts.push("UNINIT");
    }

    if parts.is_empty() {
        format!("0x{flags:08X}")
    } else {
        let mut out = String::new();
        let _ = write!(&mut out, "0x{flags:08X} [{}]", parts.join(" | "));
        out
    }
}

fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f32;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn extract_strings(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = extract_ascii_strings(bytes, min_len);
    out.extend(extract_utf16le_strings(bytes, min_len));
    out.sort_by_key(|item| item.offset);
    out
}

fn extract_ascii_strings(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut start = None;

    for (idx, byte) in bytes.iter().enumerate() {
        let printable = matches!(byte, 0x20..=0x7E | b'\t');
        match (start, printable) {
            (None, true) => start = Some(idx),
            (Some(begin), false) => {
                if idx - begin >= min_len {
                    strings.push(ExtractedString {
                        kind: "ASCII",
                        offset: begin,
                        value: String::from_utf8_lossy(&bytes[begin..idx]).into_owned(),
                    });
                }
                start = None;
            }
            _ => {}
        }
    }

    if let Some(begin) = start {
        if bytes.len() - begin >= min_len {
            strings.push(ExtractedString {
                kind: "ASCII",
                offset: begin,
                value: String::from_utf8_lossy(&bytes[begin..]).into_owned(),
            });
        }
    }

    strings
}

fn extract_utf16le_strings(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut idx = 0usize;

    while idx + 1 < bytes.len() {
        let start = idx;
        let mut code_units = Vec::new();

        while idx + 1 < bytes.len() {
            let code_unit = u16::from_le_bytes([bytes[idx], bytes[idx + 1]]);
            let ch = char::from_u32(code_unit as u32);
            let printable = matches!(ch, Some(c) if !c.is_control());
            if printable && bytes[idx + 1] == 0 {
                code_units.push(code_unit);
                idx += 2;
            } else {
                break;
            }
        }

        if code_units.len() >= min_len {
            strings.push(ExtractedString {
                kind: "UTF-16LE",
                offset: start,
                value: String::from_utf16_lossy(&code_units),
            });
        }

        idx = if idx == start { idx + 2 } else { idx };
    }

    strings
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn hex_digest<D: Digest>(bytes: &[u8]) -> String {
    let digest = D::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn build_pe_protections(pe: &PE, dll_characteristics: u16) -> ProtectionFlags {
    use goblin::pe::dll_characteristic::{
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
        IMAGE_DLLCHARACTERISTICS_NO_SEH,
    };

    ProtectionFlags {
        aslr: dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
        dep_nx: dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0,
        no_seh: dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0,
        seh_enabled: dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH == 0,
        tls_callbacks: pe.tls_data.as_ref().map(|tls| tls.callbacks.len()).unwrap_or(0),
    }
}

fn build_protection_findings(report: &BinaryReport, pe: &PE) -> Vec<ProtectionFinding> {
    let mut findings = Vec::new();

    let anti_debug_apis = [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "GetTickCount",
        "QueryPerformanceCounter",
    ];
    let suspicious_apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
    ];
    let suspicious_sections = [".packed", "UPX0", "UPX1", ".enigma", ".aspack", ".themida"];

    for api in anti_debug_apis {
        if report
            .imports
            .iter()
            .flat_map(|dll| dll.functions.iter())
            .any(|func| func.name.eq_ignore_ascii_case(api))
        {
            findings.push(ProtectionFinding {
                title: "Anti-debug API".to_string(),
                detail: format!("Imported API detected: {api}"),
                severity: "medium",
            });
        }
    }

    for api in suspicious_apis {
        if report
            .imports
            .iter()
            .flat_map(|dll| dll.functions.iter())
            .any(|func| func.name.eq_ignore_ascii_case(api))
        {
            findings.push(ProtectionFinding {
                title: "Suspicious API".to_string(),
                detail: format!("Potential injection or loader-related API detected: {api}"),
                severity: "medium",
            });
        }
    }

    if report.sections.iter().any(|section| section.entropy > 7.0) {
        findings.push(ProtectionFinding {
            title: "High entropy section".to_string(),
            detail: "At least one section exceeds 7.0 entropy and may be packed or encrypted.".to_string(),
            severity: "high",
        });
    }

    for section in &report.sections {
        if suspicious_sections
            .iter()
            .any(|name| section.name.eq_ignore_ascii_case(name))
        {
            findings.push(ProtectionFinding {
                title: "Suspicious section name".to_string(),
                detail: format!("Section {} matches a common packer/protector naming pattern.", section.name),
                severity: "high",
            });
        }
    }

    if report.imports.len() <= 2 && !report.sections.is_empty() {
        findings.push(ProtectionFinding {
            title: "Low import count".to_string(),
            detail: "Very small import surface may indicate dynamic resolution or packing.".to_string(),
            severity: "medium",
        });
    }

    if report.protections.tls_callbacks > 0 {
        findings.push(ProtectionFinding {
            title: "TLS callbacks".to_string(),
            detail: format!("{} TLS callback(s) detected.", report.protections.tls_callbacks),
            severity: "medium",
        });
    }

    if pe.tls_data.is_none() && report.protections.tls_callbacks == 0 {
        findings.push(ProtectionFinding {
            title: "TLS callbacks".to_string(),
            detail: "No TLS callbacks detected.".to_string(),
            severity: "low",
        });
    }

    findings
}

fn populate_xor_analysis(report: &mut BinaryReport, buffer: &[u8]) {
    let sources = xor_sources(report, buffer);
    report.xor_candidates = single_byte_xor_candidates(&sources);
    report.xor_patterns = repeating_xor_patterns(buffer);
    report.xor_common_key_hits = common_key_xor_hits(&sources);
}

fn xor_sources<'a>(report: &BinaryReport, buffer: &'a [u8]) -> Vec<(String, &'a [u8])> {
    let mut out = Vec::new();

    for section in report.sections.iter().filter(|section| section.entropy >= 6.8) {
        let start = section.raw_address as usize;
        let end = start.saturating_add(section.raw_size as usize).min(buffer.len());
        if start < end {
            out.push((
                format!("section {}", section.name),
                &buffer[start..end.min(start + 2048)],
            ));
        }
    }

    if out.is_empty() {
        let len = buffer.len().min(4096);
        out.push(("file head".to_string(), &buffer[..len]));
    }

    out
}

fn single_byte_xor_candidates(sources: &[(String, &[u8])]) -> Vec<XorCandidate> {
    let mut hits = Vec::new();

    for (source_name, bytes) in sources {
        for key in 1u8..=255 {
            let decoded: Vec<u8> = bytes.iter().take(512).map(|byte| byte ^ key).collect();
            let score = printable_ratio(&decoded);
            if score >= 0.72 {
                hits.push(XorCandidate {
                    source: source_name.clone(),
                    key: format!("0x{key:02X}"),
                    readability: score * 100.0,
                    preview: xor_preview(&decoded),
                });
            }
        }
    }

    hits.sort_by(|a, b| b.readability.total_cmp(&a.readability));
    hits.truncate(24);
    hits
}

fn common_key_xor_hits(sources: &[(String, &[u8])]) -> Vec<XorCandidate> {
    let keys = [0x42u8, 0x13, 0x37, 0x55, 0xAA];
    let mut hits = Vec::new();

    for (source_name, bytes) in sources {
        for key in keys {
            let decoded: Vec<u8> = bytes.iter().take(512).map(|byte| byte ^ key).collect();
            let score = printable_ratio(&decoded);
            if score >= 0.55 {
                hits.push(XorCandidate {
                    source: source_name.clone(),
                    key: format!("0x{key:02X}"),
                    readability: score * 100.0,
                    preview: xor_preview(&decoded),
                });
            }
        }
    }

    hits.sort_by(|a, b| b.readability.total_cmp(&a.readability));
    hits.truncate(16);
    hits
}

fn repeating_xor_patterns(bytes: &[u8]) -> Vec<XorPattern> {
    let mut patterns = Vec::new();
    let sample = &bytes[..bytes.len().min(32 * 1024)];

    for length in [2usize, 4, 8, 16] {
        if sample.len() < length {
            continue;
        }

        let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
        for chunk in sample.chunks_exact(length) {
            if chunk.iter().all(|byte| *byte == 0) {
                continue;
            }
            *counts.entry(chunk.to_vec()).or_insert(0) += 1;
        }

        let mut local: Vec<_> = counts
            .into_iter()
            .filter(|(_, count)| *count >= 3)
            .map(|(pattern, count)| XorPattern {
                length,
                pattern: pattern
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                count,
            })
            .collect();

        local.sort_by(|a, b| b.count.cmp(&a.count));
        local.truncate(4);
        patterns.extend(local);
    }

    patterns
}

fn printable_ratio(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let printable = bytes
        .iter()
        .filter(|byte| matches!(**byte, 0x09 | 0x0A | 0x0D | 0x20..=0x7E))
        .count();

    printable as f32 / bytes.len() as f32
}

fn xor_preview(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|byte| match byte {
            0x20..=0x7E => *byte as char,
            b'\n' | b'\r' | b'\t' => ' ',
            _ => '.',
        })
        .take(80)
        .collect()
}

fn disassemble_entry_block(pe: &PE, bytes: &[u8], entry_rva: u64) -> Result<Vec<DisassembledInstruction>> {
    let entry_rva_u32 =
        u32::try_from(entry_rva).map_err(|_| anyhow!("entry point RVA exceeds 32-bit PE range"))?;

    let text_section = pe
        .sections
        .iter()
        .find(|section| section.name().ok() == Some(".text"))
        .or_else(|| {
            pe.sections.iter().find(|section| {
                let start = section.virtual_address;
                let end = start.saturating_add(section.virtual_size.max(section.size_of_raw_data));
                entry_rva_u32 >= start && entry_rva_u32 < end
            })
        })
        .ok_or_else(|| anyhow!("failed to locate .text or entry section"))?;

    let section_start_rva = text_section.virtual_address;
    let file_offset = text_section.pointer_to_raw_data as usize;
    let section_size = text_section.size_of_raw_data as usize;
    let section_bytes = bytes
        .get(file_offset..file_offset.saturating_add(section_size))
        .ok_or_else(|| anyhow!("section bytes are out of bounds"))?;

    let decode_offset = entry_rva_u32.saturating_sub(section_start_rva) as usize;
    let decode_bytes = if decode_offset < section_bytes.len() {
        &section_bytes[decode_offset..section_bytes.len().min(decode_offset + 512)]
    } else {
        &section_bytes[..section_bytes.len().min(512)]
    };

    let image_base = pe.image_base as u64;
    let base_address = image_base
        .checked_add(entry_rva)
        .ok_or_else(|| anyhow!("entry address overflow"))?;
    let capstone = build_capstone(pe.is_64)?;
    let instructions = capstone
        .disasm_all(decode_bytes, base_address)
        .map_err(|err| anyhow!("disassembly failed: {err}"))?;

    Ok(instructions
        .iter()
        .take(128)
        .map(|insn| DisassembledInstruction {
            address: insn.address(),
            bytes: insn
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
            mnemonic: insn.mnemonic().unwrap_or_default().to_string(),
            operand: insn.op_str().unwrap_or_default().to_string(),
        })
        .collect())
}

fn build_capstone(is_64: bool) -> Result<Capstone> {
    let cs = if is_64 {
        Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(false)
            .build()
    } else {
        Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(false)
            .build()
    };

    cs.map_err(|err| anyhow!("capstone init failed: {err}"))
}
