# Analyzer

**Özet:** Statik analiz motoru. Dosya formatını tespit eder, binary'yi parse eder ve [[DataTypes#BinaryReport]] oluşturur.

**Kütüphaneler:** goblin, pelite, capstone, md5, sha1, sha2, zip, tar, flate2

## analyze_file Pipeline

1. Dosyayı buffer'a oku (`fs::read`)
2. `detect_file_format()` - Magic bytes + extension kontrolü
3. `extract_strings()` - ASCII + UTF-16LE + UTF-16BE çıkarma
4. `base_report()` - Hash'ler (MD5, SHA-1, SHA-256) ile temel rapor
5. `Object::parse()` - goblin ile format-specific parsing
6. Archive tespiti (ZIP, tar.gz)
7. `populate_xor_analysis()` - XOR analizi
8. `report.raw_bytes = buffer` - Ham veriyi rapora ekle

## Format Detection

| Format | Magic Bytes | Extension |
|--------|-------------|-----------|
| PE | `MZ` + `PE\0\0` | .exe, .dll |
| LE/LX | `MZ` + `LE` | .exe |
| ELF | `\x7FELF` | - |
| Mach-O | 4 farklı magic | - |
| DEX | `dex\n` | .dex |
| ZIP/APK/IPA/JAR | `PK\x03\x04` | .zip, .apk, .ipa, .jar |
| ISO9660 | `CD001` | .iso |
| COM | - | .com |
| Amiga | `\0\0\x03\xF3` | - |
| Binary | Fallback | - |

## Format-Specific Parsing

### PE
- Section tablosu + entropy
- Imports (DLL bazlı gruplama)
- Exports (RVA + offset)
- DOS/File/Optional header
- Resource tree enumeration (pelite)
- Version info + manifest
- Protection flags (ASLR, DEP/NX, SEH, TLS)
- Capstone ile entry-point disassembly

### ELF
- Section tablosu + entropy (EXEC, WRITE, ALLOC flags)
- Libraries (NEEDED)
- Dynamic tags (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH)
- Symbol tables (dynsym + symtab)
- Program headers (PT_LOAD, PT_DYNAMIC, PT_GNU_STACK)

### Mach-O
- Section tablosu + entropy
- Load commands (LC_SEGMENT_64, LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLIB)
- Imported libraries
- Fat binary support (note only)

## Heuristic Scoring

### Anti-debug APIs
IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, OutputDebugStringA/W, GetTickCount, QueryPerformanceCounter, NtSetInformationThread

### Suspicious APIs
VirtualAlloc, VirtualProtect, WriteProcessMemory, CreateRemoteThread, LoadLibraryA/W, GetProcAddress, NtCreateThreadEx, QueueUserAPC, SetWindowsHookExA/W

### Suspicious Section Names
.packed, UPX0/1/2, .enigma, .aspack, .themida, .vmp0/1/2, .vmprotect, .ndata, .nsp0/1

### Ek Tespitler
- Entry point high-entropy section'da → high risk
- Multiple high-entropy sections → high risk
- Writable + executable section → high risk

## XOR Analysis

- `single_byte_xor_candidates()` - 255 tek-byte key denemesi (entropy >= 7.0)
- `common_key_xor_hits()` - Sabit key'ler: [0x42, 0x13, 0x37, 0x55, 0xAA]
- `repeating_xor_patterns()` - 2/4/8/16 byte pattern tespiti

## String Extraction

- **ASCII**: 0x20-0x7E + tab, min 4 char, max 256 preview
- **UTF-16LE**: High byte 0, min 4 code unit
- **UTF-16BE**: Low byte 0, min 4 code unit
- Max 20,000 stored entries

## Baglantilar

- [[DataTypes]] - BinaryReport, SectionInfo, tüm struct'lar
- [[ReportExport]] - JSON serialization
- [[Tests]] - Test coverage
