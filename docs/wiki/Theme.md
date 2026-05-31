# Theme

**Özet:** OLED-inspired koyu tema sistemi. 20 renk field'ı ile UiTheme struct'ı.

**Kütüphaneler:** eframe::egui::Color32

## Renk Paleti

| Renk | Hex | Kullanım |
|------|-----|----------|
| app_bg | #181412 | Ana arka plan |
| shell_bg | #1E1815 | Panel arka planı |
| panel | #261E19 | Kart arka planı |
| panel_alt | #2B221C | Alternatif panel |
| inset | #1F1515 | İç panel |
| border | #4E3D31 | Ana çerçeve |
| border_soft | #3D2D29 | Yumuşak çerçeve |
| dashed_border | #584435 | Kesik çizgi |
| text | #E6E1DC | Ana metin |
| title | #FAF6F2 | Başlık |
| muted | #978F87 | Sessiz metin |
| status | #7683A4 | Durum |
| primary | #E77E23 | Ana vurgu |
| primary_soft | #4A2E17 | Yumuşak vurgu |
| primary_border | #8C5220 | Vurgu çerçevesi |
| primary_text | #18120E | Vurgu üzeri metin |
| info | #6096EB | Bilgi |
| success | #52C87E | Başarı |
| warning | #E09A4C | Uyarı |
| danger | #D65C5C | Hata |

## Widget Stilleri

- `configure_theme()` - egui Visuals'ı ayarla
- Corner radius: 14-16px
- Inner margin: symmetric(10-12, 6-10)
- Stroke: 1.0px border

## Baglantilar

- [[App]] - Theme kullanımı
- [[Widgets]] - Widget stilleri
