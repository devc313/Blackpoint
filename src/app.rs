use crate::analyzer::{analyze_file, BinaryReport, KeyValueRow};
use eframe::egui::{self, Color32, RichText, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveTab {
    GeneralInfo,
    Sections,
    Imports,
    Exports,
    Disassembly,
    Strings,
    Protection,
    Xor,
    Archive,
    Headers,
}

pub struct VibeAnalyzerApp {
    active_tab: ActiveTab,
    loaded_file: Option<PathBuf>,
    report: Option<BinaryReport>,
    last_error: Option<String>,
    string_filter: String,
    strings_case_sensitive: bool,
    show_ascii_strings: bool,
    show_utf16_strings: bool,
    drag_hovering: bool,
    analysis_receiver: Option<Receiver<Result<BinaryReport, String>>>,
    analyzing_since: Option<Instant>,
    analyzing_path: Option<PathBuf>,
}

impl VibeAnalyzerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_theme(&cc.egui_ctx);

        Self {
            active_tab: ActiveTab::GeneralInfo,
            loaded_file: None,
            report: None,
            last_error: None,
            string_filter: String::new(),
            strings_case_sensitive: false,
            show_ascii_strings: true,
            show_utf16_strings: true,
            drag_hovering: false,
            analysis_receiver: None,
            analyzing_since: None,
            analyzing_path: None,
        }
    }

    fn pick_file(&mut self) {
        let file = rfd::FileDialog::new()
            .add_filter("PE files", &["exe", "dll", "sys"])
            .pick_file();

        if let Some(path) = file {
            self.load_path(path);
        }
    }

    fn load_path(&mut self, path: PathBuf) {
        let (tx, rx) = mpsc::channel();
        let analyze_path = path.clone();

        self.loaded_file = Some(path.clone());
        self.analysis_receiver = Some(rx);
        self.analyzing_since = Some(Instant::now());
        self.analyzing_path = Some(path);
        self.last_error = None;

        std::thread::spawn(move || {
            let result = analyze_file(&analyze_path).map_err(|err| err.to_string());
            let _ = tx.send(result);
        });
    }

    fn poll_analysis(&mut self) {
        let Some(receiver) = &self.analysis_receiver else {
            return;
        };

        match receiver.try_recv() {
            Ok(Ok(report)) => {
                self.report = Some(report);
                self.analysis_receiver = None;
                self.analyzing_since = None;
                self.analyzing_path = None;
                self.last_error = None;
            }
            Ok(Err(err)) => {
                self.analysis_receiver = None;
                self.analyzing_since = None;
                self.analyzing_path = None;
                self.last_error = Some(err);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.analysis_receiver = None;
                self.analyzing_since = None;
                self.analyzing_path = None;
                self.last_error = Some("analysis worker disconnected unexpectedly".to_string());
            }
        }
    }

    fn handle_drag_and_drop(&mut self, ctx: &egui::Context) {
        let hovered = ctx.input(|input| !input.raw.hovered_files.is_empty());
        self.drag_hovering = hovered;

        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        for file in dropped {
            if let Some(path) = file.path {
                self.load_path(path);
                self.drag_hovering = false;
                break;
            }
        }
    }

    fn render_title_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("title_bar")
            .exact_height(52.0)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(5, 7, 10))
                    .inner_margin(egui::Margin::symmetric(14, 10))
                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(24, 31, 41))),
            )
            .show(ctx, |ui| {
                let rect = ui.max_rect();
                let drag_id = ui.id().with("title_drag_zone");
                let response = ui.interact(rect, drag_id, egui::Sense::click_and_drag());
                if response.is_pointer_button_down_on() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Blackpoint")
                                .size(18.0)
                                .strong()
                                .color(Color32::from_rgb(244, 245, 247)),
                        );
                        ui.label(
                            RichText::new("Static binary analysis workbench")
                                .small()
                                .color(Color32::from_rgb(124, 134, 147)),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        titlebar_button(
                            ui,
                            "X",
                            Color32::from_rgb(214, 78, 78),
                            "Close",
                            || ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                        );
                        titlebar_button(
                            ui,
                            "[]",
                            Color32::from_rgb(110, 122, 140),
                            "Maximize",
                            || {
                                let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                                ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                            },
                        );
                        titlebar_button(
                            ui,
                            "_",
                            Color32::from_rgb(110, 122, 140),
                            "Minimize",
                            || ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)),
                        );
                    });
                });
            });
    }

    fn render_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.heading("Blackpoint");
                ui.label(RichText::new("Static binary triage workbench").color(Color32::GRAY));
                ui.add_space(10.0);

                if ui.button("Open EXE / DLL / SYS").clicked() {
                    self.pick_file();
                }

                if let Some(path) = &self.loaded_file {
                    ui.add_space(8.0);
                    ui.label(RichText::new(path.display().to_string()).monospace());
                }

                if let Some(error) = &self.last_error {
                    ui.add_space(10.0);
                    ui.colored_label(Color32::from_rgb(255, 120, 120), error);
                }

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                for (tab, label) in [
                    (ActiveTab::GeneralInfo, "General Info"),
                    (ActiveTab::Headers, "Headers"),
                    (ActiveTab::Sections, "Sections"),
                    (ActiveTab::Imports, "Imports"),
                    (ActiveTab::Exports, "Exports"),
                    (ActiveTab::Strings, "Strings"),
                    (ActiveTab::Protection, "Protection"),
                    (ActiveTab::Xor, "XOR Analysis"),
                    (ActiveTab::Disassembly, "Disassembly"),
                    (ActiveTab::Archive, "Archive"),
                ] {
                    let selected = self.active_tab == tab;
                    if nav_button(ui, label, selected).clicked() {
                        self.active_tab = tab;
                    }
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new("Roadmap: Capstone / LIEF / yara-x / graph view")
                            .small()
                            .color(Color32::GRAY),
                    );
                });
            });
    }

    fn render_main(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(report) = &self.report else {
                render_empty_state(ui);
                return;
            };

            match self.active_tab {
                ActiveTab::GeneralInfo => render_overview(ui, report),
                ActiveTab::Sections => render_sections(ui, report),
                ActiveTab::Imports => render_imports(ui, report),
                ActiveTab::Exports => render_exports(ui, report),
                ActiveTab::Disassembly => render_disassembly(ui, report),
                ActiveTab::Strings => render_strings(
                    ui,
                    report,
                    &mut self.string_filter,
                    &mut self.strings_case_sensitive,
                    &mut self.show_ascii_strings,
                    &mut self.show_utf16_strings,
                ),
                ActiveTab::Protection => render_protection(ui, report),
                ActiveTab::Xor => render_xor(ui, report),
                ActiveTab::Archive => render_archive(ui, report),
                ActiveTab::Headers => render_headers(ui, report),
            }
        });
    }

    fn render_drag_overlay(&self, ctx: &egui::Context) {
        if !self.drag_hovering {
            return;
        }

        let layer_id = egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop_overlay"));
        let painter = ctx.layer_painter(layer_id);
        let rect = ctx.content_rect();
        painter.rect_filled(rect, 0.0, Color32::from_rgba_unmultiplied(0, 0, 0, 185));

        let card = egui::Rect::from_center_size(rect.center(), egui::vec2(420.0, 180.0));
        painter.rect(
            card,
            24.0,
            Color32::from_rgba_unmultiplied(14, 19, 26, 240),
            egui::Stroke::new(2.0, Color32::from_rgb(207, 94, 57)),
            egui::StrokeKind::Outside,
        );
        painter.text(
            card.center_top() + egui::vec2(0.0, 44.0),
            egui::Align2::CENTER_TOP,
            "Drop binary to analyze",
            egui::FontId::proportional(24.0),
            Color32::from_rgb(245, 245, 246),
        );
        painter.text(
            card.center_top() + egui::vec2(0.0, 86.0),
            egui::Align2::CENTER_TOP,
            "EXE  DLL  SYS",
            egui::FontId::monospace(16.0),
            Color32::from_rgb(124, 134, 147),
        );
    }

    fn render_analysis_overlay(&self, ctx: &egui::Context) {
        let Some(started) = self.analyzing_since else {
            return;
        };

        let elapsed = started.elapsed().as_secs_f32();
        let dots = match ((elapsed * 2.0) as usize) % 4 {
            0 => "",
            1 => ".",
            2 => "..",
            _ => "...",
        };

        let layer_id = egui::LayerId::new(egui::Order::Foreground, egui::Id::new("analysis_overlay"));
        let painter = ctx.layer_painter(layer_id);
        let rect = ctx.content_rect();
        painter.rect_filled(rect, 0.0, Color32::from_rgba_unmultiplied(0, 0, 0, 176));

        egui::Area::new("analysis_overlay_card".into())
            .order(egui::Order::Foreground)
            .fixed_pos(rect.center() - egui::vec2(220.0, 80.0))
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(Color32::from_rgb(11, 15, 20))
                    .corner_radius(egui::CornerRadius::same(22))
                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(70, 84, 104)))
                    .inner_margin(egui::Margin::same(20))
                    .show(ui, |ui| {
                        ui.set_width(440.0);
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(28.0));
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(format!("Analyzing{dots}"))
                                        .strong()
                                        .size(22.0)
                                        .color(Color32::from_rgb(244, 245, 247)),
                                );
                                if let Some(path) = &self.analyzing_path {
                                    ui.label(
                                        RichText::new(path.display().to_string())
                                            .small()
                                            .monospace()
                                            .color(Color32::from_rgb(142, 151, 163)),
                                    );
                                }
                                ui.label(
                                    RichText::new("Parsing headers, strings, imports, heuristics, and XOR candidates")
                                        .small()
                                        .color(Color32::from_rgb(162, 172, 184)),
                                );
                            });
                        });
                    });
            });
    }
}

impl eframe::App for VibeAnalyzerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_analysis();
        if self.analysis_receiver.is_some() {
            ctx.request_repaint();
        }
        self.handle_drag_and_drop(ctx);
        self.render_title_bar(ctx);
        self.render_sidebar(ctx);
        self.render_main(ctx);
        self.render_drag_overlay(ctx);
        self.render_analysis_overlay(ctx);
    }
}

fn configure_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = Color32::from_rgb(2, 4, 6);
    style.visuals.window_fill = Color32::from_rgb(4, 6, 8);
    style.visuals.extreme_bg_color = Color32::from_rgb(0, 0, 0);
    style.visuals.faint_bg_color = Color32::from_rgb(15, 20, 28);
    style.visuals.code_bg_color = Color32::from_rgb(8, 11, 15);
    style.visuals.selection.bg_fill = Color32::from_rgb(207, 94, 57);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, Color32::from_rgb(255, 197, 175));
    style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(9, 12, 16);
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(38, 47, 60));
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(13, 17, 23);
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(42, 52, 67));
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(20, 26, 34);
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(83, 98, 119));
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(248, 248, 249));
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(207, 94, 57);
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(255, 197, 175));
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, Color32::WHITE);
    style.visuals.widgets.open.bg_fill = Color32::from_rgb(17, 22, 30);
    style.visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(61, 74, 93));
    style.visuals.window_stroke = egui::Stroke::new(1.0, Color32::from_rgb(52, 62, 78));
    style.visuals.window_corner_radius = egui::CornerRadius::same(18);
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 9.0);
    style.spacing.window_margin = egui::Margin::same(14);
    ctx.set_style(style);
}

fn render_empty_state(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(104.0);
        egui::Frame::new()
            .fill(Color32::from_rgb(7, 9, 12))
            .corner_radius(egui::CornerRadius::same(28))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(25, 31, 42)))
            .inner_margin(egui::Margin::same(28))
            .show(ui, |ui| {
                ui.set_max_width(620.0);
                ui.label(
                    RichText::new("Static analysis for real binaries")
                        .size(30.0)
                        .strong()
                        .color(Color32::from_rgb(246, 247, 248)),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new("Open an executable, library, package, or archive to inspect structure, strings, imports, exports, and format-specific metadata.")
                        .color(Color32::from_rgb(140, 149, 160)),
                );
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    pill(ui, "Drag & Drop");
                    pill(ui, "Multi-Format");
                    pill(ui, "Disassembly");
                });
            });
    });
}

fn render_overview(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "General Info", "Core file metadata, hashes, mitigations, and build signals");

    framed_panel(ui, |ui| {
        egui::Grid::new("overview_grid")
            .num_columns(2)
            .spacing([28.0, 10.0])
            .show(ui, |ui| {
                overview_row(ui, "Path", &report.path.display().to_string());
                overview_row(ui, "MD5", &report.md5);
                overview_row(ui, "SHA-1", &report.sha1);
                overview_row(ui, "Format", &report.format_name);
                overview_row(ui, "Family", &report.format_family);
                overview_row(ui, "Confidence", &report.detection_confidence);
                overview_row(ui, "File Size", &format!("{} bytes", report.file_size));
                overview_row(ui, "Machine", &report.machine_type);
                overview_row(ui, "Section Count", &report.section_count.to_string());
                overview_row(ui, "Architecture", if report.is_64bit { "64-bit" } else { "32-bit / n.a." });
                overview_row(ui, "Subsystem", &report.subsystem);
                overview_row(ui, "Image Base", &format!("0x{:X}", report.image_base));
                overview_row(ui, "Entry Point", &format!("0x{:X}", report.entry_point));
                overview_row(ui, "ASLR", bool_badge(report.protections.aslr));
                overview_row(ui, "DEP / NX", bool_badge(report.protections.dep_nx));
                overview_row(ui, "SEH", bool_badge(report.protections.seh_enabled));
                overview_row(ui, "TLS Callbacks", &report.protections.tls_callbacks.to_string());
                overview_row(ui, "Section Alignment", &format!("0x{:X}", report.section_alignment));
                overview_row(ui, "File Alignment", &format!("0x{:X}", report.file_alignment));
                overview_row(ui, "Timestamp", &format!("0x{:08X}", report.timestamp));
                overview_row(ui, "SHA-256", &report.sha256_placeholder);
            });
    });

    ui.add_space(18.0);
    ui.columns(3, |columns| {
        stat_card(
            &mut columns[0],
            "Sections",
            &report.sections.len().to_string(),
            Color32::from_rgb(90, 160, 255),
        );
        stat_card(
            &mut columns[1],
            "Imported APIs",
            &report
                .imports
                .iter()
                .map(|dll| dll.functions.len())
                .sum::<usize>()
                .to_string(),
            Color32::from_rgb(92, 184, 92),
        );
        stat_card(
            &mut columns[2],
            "Strings",
            &report.strings.len().to_string(),
            Color32::from_rgb(210, 144, 72),
        );
    });

    ui.add_space(16.0);
    framed_panel(ui, |ui| {
        ui.label(
            RichText::new("Heuristic Notes")
                .strong()
                .color(Color32::from_rgb(229, 233, 237)),
        );
        ui.add_space(6.0);
        for note in &report.notes {
            ui.label(
                RichText::new(format!("• {note}"))
                    .color(Color32::from_rgb(162, 172, 184)),
            );
        }
    });
}

fn render_sections(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Sections", "PE section layout, permissions, and entropy");

    framed_panel(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::initial(120.0))
            .column(Column::initial(100.0))
            .column(Column::initial(100.0))
            .column(Column::initial(100.0))
            .column(Column::initial(100.0))
            .column(Column::remainder())
            .column(Column::initial(80.0))
            .header(24.0, |mut header| {
                for title in ["Name", "VA", "VSZ", "Raw", "RSZ", "Characteristics", "Entropy"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|mut body| {
                for section in &report.sections {
                    body.row(22.0, |mut row| {
                        row.col(|ui| {
                            ui.monospace(&section.name);
                        });
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", section.virtual_address));
                        });
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", section.virtual_size));
                        });
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", section.raw_address));
                        });
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", section.raw_size));
                        });
                        row.col(|ui| {
                            ui.label(&section.characteristics);
                        });
                        row.col(|ui| {
                            ui.label(format!("{:.2}", section.entropy));
                        });
                    });
                }
            });
    });
}

fn render_imports(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Imports", "Grouped imported DLLs and resolved function names");

    framed_panel(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            for dll in &report.imports {
                egui::CollapsingHeader::new(format!("{} ({})", dll.name, dll.functions.len()))
                    .default_open(true)
                    .show(ui, |ui| {
                        if dll.functions.is_empty() {
                            ui.label(RichText::new("Container or library reference only").small().color(Color32::GRAY));
                        }
                        for function in &dll.functions {
                            ui.monospace(format!("{}    ordinal: {}", function.name, function.ordinal));
                        }
                    });
            }
        });
    });
}

fn render_exports(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Exports", "Exported names with offsets and RVAs");

    framed_panel(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::remainder())
            .column(Column::initial(120.0))
            .column(Column::initial(120.0))
            .header(24.0, |mut header| {
                for title in ["Name", "Offset", "RVA"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|mut body| {
                for export in &report.exports {
                    body.row(22.0, |mut row| {
                        row.col(|ui| {
                            ui.monospace(&export.name);
                        });
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", export.offset));
                        });
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", export.rva));
                        });
                    });
                }
            });
    });
}

fn render_strings(
    ui: &mut Ui,
    report: &BinaryReport,
    string_filter: &mut String,
    case_sensitive: &mut bool,
    show_ascii: &mut bool,
    show_utf16: &mut bool,
) {
    render_panel_title(ui, "Strings", "Searchable string extraction with format filters");

    framed_panel(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Search").color(Color32::from_rgb(188, 195, 205)));
                ui.add_sized(
                    [340.0, 28.0],
                    egui::TextEdit::singleline(string_filter).hint_text("needle, dll path, api key, domain..."),
                );
                if ui.button("Clear").clicked() {
                    string_filter.clear();
                }
            });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(case_sensitive, "Case sensitive");
                ui.checkbox(show_ascii, "ASCII");
                ui.checkbox(show_utf16, "UTF-16LE");
            });
    });

    ui.add_space(10.0);

    let filtered: Vec<_> = report
        .strings
        .iter()
        .filter(|entry| match entry.kind {
            "ASCII" => *show_ascii,
            "UTF-16LE" => *show_utf16,
            _ => true,
        })
        .filter(|entry| string_matches(entry.value.as_str(), string_filter, *case_sensitive))
        .collect();

    let visible_count = filtered.len().min(100);

    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("showing {} of {} visible / {} total", visible_count, filtered.len(), report.strings.len()))
                .small()
                .color(Color32::from_rgb(126, 136, 149)),
        );
        if !string_filter.is_empty() {
            ui.label(
                RichText::new(format!("query=\"{}\"", string_filter))
                    .small()
                    .monospace()
                    .color(Color32::from_rgb(207, 94, 57)),
            );
        }
    });
    ui.add_space(8.0);

    framed_panel(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::initial(90.0))
            .column(Column::initial(120.0))
            .column(Column::remainder())
            .header(24.0, |mut header| {
                for title in ["Kind", "Offset", "Value"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|mut body| {
                for string in filtered.into_iter().take(100) {
                    body.row(22.0, |mut row| {
                        row.col(|ui| {
                            ui.label(
                                RichText::new(string.kind).color(match string.kind {
                                    "ASCII" => Color32::from_rgb(110, 174, 255),
                                    "UTF-16LE" => Color32::from_rgb(124, 208, 156),
                                    _ => Color32::LIGHT_GRAY,
                                }),
                            );
                        });
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", string.offset));
                        });
                        row.col(|ui| {
                            ui.label(&string.value);
                        });
                    });
                }
            });
    });
}

fn render_disassembly(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "Disassembly",
        "Entry-point focused preview from .text or the containing section",
    );

    framed_panel(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::initial(140.0))
            .column(Column::initial(220.0))
            .column(Column::initial(110.0))
            .column(Column::remainder())
            .header(24.0, |mut header| {
                for title in ["Address", "Bytes", "Mnemonic", "Operands"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|mut body| {
                for insn in &report.disassembly {
                    body.row(22.0, |mut row| {
                        row.col(|ui| {
                            ui.monospace(format!("0x{:X}", insn.address));
                        });
                        row.col(|ui| {
                            ui.monospace(&insn.bytes);
                        });
                        row.col(|ui| {
                            ui.monospace(&insn.mnemonic);
                        });
                        row.col(|ui| {
                            ui.monospace(&insn.operand);
                        });
                    });
                }
            });
    });
}

fn render_archive(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Archive", "Container members for ZIP-like and package formats");

    framed_panel(ui, |ui| {
        if report.archive_entries.is_empty() {
            ui.label(
                RichText::new("No parsed archive member table for this file.")
                    .color(Color32::from_rgb(140, 149, 160)),
            );
            return;
        }

        TableBuilder::new(ui)
            .striped(true)
            .column(Column::remainder())
            .column(Column::initial(120.0))
            .column(Column::initial(120.0))
            .header(24.0, |mut header| {
                for title in ["Name", "Kind", "Size"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|mut body| {
                for entry in &report.archive_entries {
                    body.row(22.0, |mut row| {
                        row.col(|ui| {
                            ui.monospace(&entry.name);
                        });
                        row.col(|ui| {
                            ui.label(&entry.kind);
                        });
                        row.col(|ui| {
                            ui.monospace(format!("{}", entry.size));
                        });
                    });
                }
            });
    });
}

fn render_headers(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Headers", "DOS, file, and optional header detail");

    framed_panel(ui, |ui| {
        ui.columns(3, |columns| {
            render_kv_group(&mut columns[0], "DOS Header", &report.dos_header);
            render_kv_group(&mut columns[1], "File Header", &report.file_header);
            render_kv_group(&mut columns[2], "Optional Header", &report.optional_header);
        });
    });

    ui.add_space(12.0);
    framed_panel(ui, |ui| {
        render_kv_group(ui, "Rich Header", &report.rich_headers);
    });
}

fn render_protection(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Protection", "Mitigations, anti-debug indicators, and suspicious API heuristics");

    ui.columns(2, |columns| {
        framed_panel(&mut columns[0], |ui| {
            render_kv_group(
                ui,
                "Mitigations",
                &[
                    KeyValueRow {
                        key: "ASLR".to_string(),
                        value: bool_badge(report.protections.aslr).to_string(),
                    },
                    KeyValueRow {
                        key: "DEP / NX".to_string(),
                        value: bool_badge(report.protections.dep_nx).to_string(),
                    },
                    KeyValueRow {
                        key: "SEH Enabled".to_string(),
                        value: bool_badge(report.protections.seh_enabled).to_string(),
                    },
                    KeyValueRow {
                        key: "NO_SEH".to_string(),
                        value: bool_badge(report.protections.no_seh).to_string(),
                    },
                    KeyValueRow {
                        key: "TLS Callbacks".to_string(),
                        value: report.protections.tls_callbacks.to_string(),
                    },
                ],
            );
        });

        framed_panel(&mut columns[1], |ui| {
            ui.label(
                RichText::new("Findings")
                    .strong()
                    .color(Color32::from_rgb(229, 233, 237)),
            );
            ui.add_space(6.0);
            for finding in &report.protection_findings {
                ui.label(
                    RichText::new(format!(
                        "[{}] {}: {}",
                        finding.severity.to_uppercase(),
                        finding.title,
                        finding.detail
                    ))
                    .color(match finding.severity {
                        "high" => Color32::from_rgb(235, 104, 104),
                        "medium" => Color32::from_rgb(233, 184, 97),
                        _ => Color32::from_rgb(150, 180, 150),
                    }),
                );
            }
        });
    });
}

fn render_xor(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "XOR Analysis",
        "Single-byte candidates, repeating multi-byte patterns, and common-key previews",
    );

    ui.columns(2, |columns| {
        framed_panel(&mut columns[0], |ui| {
            ui.label(
                RichText::new("Single-byte XOR Candidates")
                    .strong()
                    .color(Color32::from_rgb(229, 233, 237)),
            );
            ui.add_space(8.0);
            if report.xor_candidates.is_empty() {
                ui.label("No high-confidence single-byte XOR candidates found.");
            } else {
                for candidate in &report.xor_candidates {
                    ui.label(
                        RichText::new(format!(
                            "{} | key={} | {:.1}% | {}",
                            candidate.source, candidate.key, candidate.readability, candidate.preview
                        ))
                        .monospace()
                        .color(Color32::from_rgb(186, 194, 204)),
                    );
                }
            }
        });

        framed_panel(&mut columns[1], |ui| {
            ui.label(
                RichText::new("Common-Key Hits")
                    .strong()
                    .color(Color32::from_rgb(229, 233, 237)),
            );
            ui.add_space(8.0);
            if report.xor_common_key_hits.is_empty() {
                ui.label("No useful previews for common XOR keys.");
            } else {
                for candidate in &report.xor_common_key_hits {
                    ui.label(
                        RichText::new(format!(
                            "{} | key={} | {:.1}% | {}",
                            candidate.source, candidate.key, candidate.readability, candidate.preview
                        ))
                        .monospace()
                        .color(Color32::from_rgb(186, 194, 204)),
                    );
                }
            }
        });
    });

    ui.add_space(12.0);
    framed_panel(ui, |ui| {
        ui.label(
            RichText::new("Repeating Multi-byte Patterns")
                .strong()
                .color(Color32::from_rgb(229, 233, 237)),
        );
        ui.add_space(8.0);
        if report.xor_patterns.is_empty() {
            ui.label("No repeating 2/4/8/16-byte patterns crossed the reporting threshold.");
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::initial(80.0))
                .column(Column::initial(80.0))
                .column(Column::remainder())
                .header(24.0, |mut header| {
                    for title in ["Len", "Count", "Pattern"] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|mut body| {
                    for pattern in &report.xor_patterns {
                        body.row(22.0, |mut row| {
                            row.col(|ui| {
                                ui.monospace(pattern.length.to_string());
                            });
                            row.col(|ui| {
                                ui.monospace(pattern.count.to_string());
                            });
                            row.col(|ui| {
                                ui.monospace(&pattern.pattern);
                            });
                        });
                    }
                });
        }
    });
}

fn render_kv_group(ui: &mut Ui, title: &str, rows: &[KeyValueRow]) {
    ui.group(|ui| {
        ui.strong(title);
        ui.add_space(6.0);
        for row in rows {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&row.key).monospace().color(Color32::LIGHT_BLUE));
                ui.label(&row.value);
            });
        }
    });
}

fn overview_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).color(Color32::GRAY));
    ui.label(RichText::new(value).text_style(TextStyle::Monospace));
    ui.end_row();
}

fn bool_badge(value: bool) -> &'static str {
    if value {
        "Enabled"
    } else {
        "Disabled"
    }
}

fn stat_card(ui: &mut Ui, title: &str, value: &str, accent: Color32) {
    egui::Frame::group(ui.style())
        .fill(Color32::from_rgb(9, 12, 16))
        .corner_radius(egui::CornerRadius::same(20))
        .stroke(egui::Stroke::new(1.0, accent.gamma_multiply(0.8)))
        .show(ui, |ui| {
            ui.set_min_height(92.0);
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new(title).small().color(Color32::GRAY));
                ui.label(RichText::new(value).size(30.0).color(accent));
            });
        });
}

fn framed_panel(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(9, 12, 16))
        .corner_radius(egui::CornerRadius::same(18))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(49, 59, 74)))
        .inner_margin(egui::Margin::same(14))
        .show(ui, add_contents);
}

fn render_panel_title(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(
        RichText::new(title)
            .size(22.0)
            .strong()
            .color(Color32::from_rgb(244, 245, 247)),
    );
    ui.label(
        RichText::new(subtitle)
            .small()
            .color(Color32::from_rgb(122, 132, 145)),
    );
    ui.add_space(10.0);
}

fn string_matches(value: &str, needle: &str, case_sensitive: bool) -> bool {
    if needle.is_empty() {
        return true;
    }

    if case_sensitive {
        value.contains(needle)
    } else {
        value.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
    }
}

fn nav_button(ui: &mut Ui, label: &str, selected: bool) -> egui::Response {
    let fill = if selected {
        Color32::from_rgb(207, 94, 57)
    } else {
        Color32::from_rgb(9, 12, 17)
    };
    let stroke = if selected {
        Color32::from_rgb(255, 197, 175)
    } else {
        Color32::from_rgb(25, 31, 42)
    };

    ui.add(
        egui::Button::new(
            RichText::new(label)
                .color(if selected {
                    Color32::from_rgb(250, 250, 251)
                } else {
                    Color32::from_rgb(185, 192, 202)
                })
                .size(13.5),
        )
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke))
        .corner_radius(egui::CornerRadius::same(12))
        .min_size(egui::vec2(ui.available_width(), 34.0)),
    )
}

fn pill(ui: &mut Ui, text: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(13, 17, 23))
        .corner_radius(egui::CornerRadius::same(24))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(31, 39, 51)))
        .inner_margin(egui::Margin::symmetric(12, 6))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(Color32::from_rgb(189, 196, 206)));
        });
}

fn titlebar_button(
    ui: &mut Ui,
    text: &str,
    accent: Color32,
    tooltip: &str,
    on_click: impl FnOnce(),
) {
    let button = egui::Button::new(
        RichText::new(text)
            .monospace()
            .size(14.0)
            .color(Color32::from_rgb(242, 243, 245)),
    )
    .min_size(egui::vec2(34.0, 26.0))
    .fill(Color32::from_rgb(13, 17, 23))
    .corner_radius(egui::CornerRadius::same(10))
    .stroke(egui::Stroke::new(1.0, accent));

    let response = ui.add(button).on_hover_text(tooltip);
    if response.clicked() {
        on_click();
    }
}
