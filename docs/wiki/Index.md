# Blackpoint Knowledge Graph

**Özet:** Blackpoint, Rust ile yazılmış bir desktop binary analysis workbench'idir. PE, ELF, Mach-O ve diğer formatların statik analizini yapar.

**Kütüphaneler:** Rust, eframe/egui, goblin, pelite, capstone, zip, tar, flate2

## Modüller

- [[Main]] - Entry point, pencere oluşturma
- [[App]] - BlackpointApp yapısı, state management, UI rendering
- [[Analyzer]] - analyze_file pipeline, format detection, data structures
- [[ReportExport]] - JSON serialization, snapshot schema
- [[Theme]] - UiTheme, renk paleti, OLED-dark tema
- [[TabRenderers]] - 12 tab'ın her birinin detayı
- [[Widgets]] - Button, pill, metric tile, icon system
- [[DataTypes]] - BinaryReport, SectionInfo, tüm data struct'ları
- [[Tests]] - Mevcut test coverage ve test stratejisi

## Hızlı Erişim

- [[TabRenderers#Imports]] - Import arama/filtreleme
- [[TabRenderers#Sections]] - Section → Hex navigasyonu
- [[App#Keyboard Shortcuts]] - Kısayol tuşları
- [[Analyzer#ELF]] - ELF enhancement (dynamic tags, symbols)
- [[Analyzer#Mach-O]] - Mach-O enhancement (load commands)
- [[Analyzer#Heuristic Scoring]] - Packer/injector tespiti
