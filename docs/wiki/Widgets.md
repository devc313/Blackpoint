# Widgets

**Özet:** Tekrar kullanılan UI bileşenleri: button, pill, metric tile, icon, panel.

**Kütüphaneler:** egui

## Button Widget'lari

- `primary_button()` / `primary_button_sized()` - Ana aksiyon butonu
- `secondary_button_sized()` - İkincil buton
- `ghost_button()` - Şeffaf buton
- `primary_action_button_with_width()` - Özelleştirilmiş 52px buton
- `secondary_action_button_with_width()` - Özelleştirilmiş 48px buton
- `ghost_action_button()` - Panel arka planlı buton
- `titlebar_button()` - Window control butonu
- `nav_button()` - Sidebar navigasyon butonu

## Badge & Pill

- `pill()` - Yuvarlak badge
- `sidebar_pill()` - Küçük sidebar badge
- `bool_badge()` - "Enabled" / "Disabled" badge

## Metric & Panel

- `metric_tile()` - Tek metric kartı (title + value)
- `inline_fact()` - Küçük label + value
- `render_metric_strip()` - 4'lü metric strip (responsive)
- `framed_panel()` - Panel with fill, corners, border
- `section_surface()` - Inset frame
- `tabular_surface()` - Horizontal scroll area
- `vertical_surface_scroll()` - Vertical scroll area
- `render_panel_title()` - Başlık + alt başlık
- `render_placeholder_panel()` - Boş durum paneli

## Icon System

- `AppIcon` enum - 24 icon variant
- `paint_icon()` - Manuel vektör icon çizimi (574 lines)
- `icon_tile()` - Yuvarlak icon kutusu

## Navigasyon

- `workspace_status_chip()` - Durum göstergesi
- `tab_meta()` - ActiveTab → (AppIcon, label) dönüşümü
- `sidebar_section_label()` / `shell_section_label()` - Başlık etiketleri

## Baglantilar

- [[Theme]] - Renk paleti
- [[App]] - Widget kullanımı
- [[TabRenderers]] - Sekme-specific widget'lar
