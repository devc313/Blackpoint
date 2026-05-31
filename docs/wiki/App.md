# App

**Özet:** Ana uygulama modülü. BlackpointApp struct'ı tüm state'i yönetir, UI'ı render eder ve kullanıcı etkileşimlerini işler.

**Kütüphaneler:** eframe, egui, egui_extras

## Ana Yapı: BlackpointApp

14 field ile uygulama state'i:
- `active_tab` - Aktif sekme
- `loaded_file` - Yüklü dosya yolu
- `report` - [[DataTypes#BinaryReport]] analiz sonucu
- `import_filter` - Import arama filtresi
- `string_filter` - String arama filtresi
- `hex_offset_input` / `hex_rva_input` - Hex viewer pozisyonu
- `recent_files` - Son analiz edilen dosyalar (max 50)
- `history_path` - Session history dosya yolu (~/.blackpoint/history.json)
- `analysis_receiver` - Background thread'den analiz sonucu

## Metodlar

### Dosya Yonetimi
- `pick_file()` - [[Widgets#File Dialog]] ile dosya seçimi
- `load_path()` - Dosya yükleme, boyut kontrolü (500MB warn, 2GB block)
- `push_recent_file()` - Son dosya listesini güncelle + history kaydet
- `remove_recent_file()` - Son dosyadan kaldır

### Clipboard & Export
- `copy_target_path()` - Dosya yolunu clipboard'a kopyala
- `copy_hashes()` - MD5/SHA-1/SHA-256 clipboard'a kopyala
- `reveal_target_in_explorer()` - Cross-platform file manager açma
- `export_snapshot()` - JSON snapshot export

### UI Rendering
- `render_title_bar()` - Custom title bar, window controls
- `render_sidebar()` - Sol panel (dosya bilgisi, navigation, recent files)
- `render_main()` - Ana içerik paneli
- `render_status_bar()` - Alt bilgi çubuğu
- `render_drag_overlay()` - Drag-and-drop overlay
- `render_analysis_overlay()` - Analiz animasyonu

### Keyboard Shortcuts
- `Ctrl+O` - Dosya aç
- `Ctrl+E` - Snapshot export
- `Ctrl+C` - Dosya yolunu kopyala
- `Ctrl+Shift+C` - Hash'leri kopyala
- `1-9` - Sekme değiştirme

## ActiveReportState

UI state'i taşımak için struct:
```rust
struct ActiveReportState<'a> {
    hex_offset_input: &'a mut String,
    hex_rva_input: &'a mut String,
    hex_status: &'a mut Option<String>,
    hex_selected_offset: &'a mut usize,
    string_filter: &'a mut String,
    import_filter: &'a mut String,
    strings_case_sensitive: &'a mut bool,
    show_ascii_strings: &'a mut bool,
    show_utf16_strings: &'a mut bool,
}
```

## Session History

- `~/.blackpoint/history.json` dosyasına kaydedilir
- Max 50 entry tutulur
- Uygulama açılışında geçmiş yüklenir
- JSON format: `["C:\\path\\to\\file.exe", ...]`

## Baglantilar

- [[Main]] - Entry point
- [[Analyzer]] - Analiz pipeline'ı
- [[ReportExport]] - Export fonksiyonları
- [[Theme]] - Renk paleti
- [[TabRenderers]] - Sekme render fonksiyonları
- [[Widgets]] - UI bileşenleri
