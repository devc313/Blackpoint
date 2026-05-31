# TabRenderers

**Özet:** 12 analiz sekmesinin her birinin render fonksiyonu.

**Kütüphaneler:** egui, egui_extras

## Sekmeler

### GeneralInfo (render_overview)
- Identity block (filename, path, pills)
- Metric strip (Sections, APIs, Strings, TLS)
- Binary Profile, Execution Layout, Hashes grids
- Heuristic notes panel

### Resources (render_resources)
- PE resource identity + metric strip
- Resource tree table
- PE Build Signals KV rows
- Version info + Manifest

### Hex (render_hex_viewer)
- Offset input + Jump/Entry buttons
- RVA input + Jump RVA button
- Section quick-jump buttons
- Hex dump (16 bytes/row) + ASCII preview

### Sections (render_sections)
- Metric strip (Count, Executable, Writable, High Entropy)
- Table: Name, VA, VSZ, Raw, RSZ, Characteristics, Entropy
- **Section → Hex navigasyonu**: Section adına tıkla → Hex'te o offset'e git

### Imports (render_imports)
- Metric strip (DLLs, APIs, Ordinals, Empty Groups)
- **Import arama/filtreleme**: Search input ile DLL/fonksiyon filtreleme
- CollapsingHeader per DLL

### Exports (render_exports)
- Metric strip (Exports, Named, Ordinal, Last RVA)
- Table: Name, Offset, RVA

### Disassembly (render_disassembly)
- Metric strip (Instructions, Entry, First, Last)
- Table: Address, Bytes, Mnemonic, Operands

### Strings (render_strings)
- Search input + Clear button
- Case-sensitive/ASCII/UTF-16 checkboxes
- Metric strip (Stored, Visible, ASCII, UTF-16LE)
- **String Export**: TXT ve CSV export butonları
- Table: Kind, Offset, Value

### Protection (render_protection)
- Metric strip (Mitigations, Findings, High, TLS)
- Mitigations KV grid
- Findings cards with severity badges

### Xor (render_xor)
- Metric strip
- Single-byte candidates panel
- Common-key hits panel
- Repeating multi-byte patterns table

### Archive (render_archive)
- Metric strip (Entries, Stored, Total Size, Format)
- Table: Name, Kind, Size

### Headers (render_headers)
- Metric strip
- DOS, File, Optional, Rich header KV groups

## Baglantilar

- [[App#ActiveReportState]] - State yönetimi
- [[Widgets]] - Ortak UI bileşenleri
- [[Analyzer]] - Veri kaynakları
