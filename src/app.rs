use crate::analyzer::{analyze_file, BinaryReport, KeyValueRow};
use eframe::egui::{self, Color32, RichText, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveTab {
    GeneralInfo,
    Resources,
    Hex,
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

pub struct BlackpointApp {
    active_tab: ActiveTab,
    loaded_file: Option<PathBuf>,
    report: Option<BinaryReport>,
    last_error: Option<String>,
    string_filter: String,
    hex_offset_input: String,
    hex_rva_input: String,
    hex_status: Option<String>,
    strings_case_sensitive: bool,
    show_ascii_strings: bool,
    show_utf16_strings: bool,
    drag_hovering: bool,
    analysis_receiver: Option<Receiver<Result<BinaryReport, String>>>,
    analyzing_since: Option<Instant>,
    analyzing_path: Option<PathBuf>,
    recent_files: Vec<PathBuf>,
}

impl BlackpointApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_theme(&cc.egui_ctx);

        Self {
            active_tab: ActiveTab::GeneralInfo,
            loaded_file: None,
            report: None,
            last_error: None,
            string_filter: String::new(),
            hex_offset_input: "0x0".to_string(),
            hex_rva_input: "0x0".to_string(),
            hex_status: None,
            strings_case_sensitive: false,
            show_ascii_strings: true,
            show_utf16_strings: true,
            drag_hovering: false,
            analysis_receiver: None,
            analyzing_since: None,
            analyzing_path: None,
            recent_files: Vec::new(),
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
        self.analyzing_path = Some(path.clone());
        self.last_error = None;
        self.hex_status = None;
        self.hex_offset_input = "0x0".to_string();
        self.hex_rva_input = "0x0".to_string();
        self.push_recent_file(path.clone());

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
                self.hex_status = None;
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

    fn push_recent_file(&mut self, path: PathBuf) {
        self.recent_files.retain(|existing| existing != &path);
        self.recent_files.insert(0, path);
        self.recent_files.truncate(6);
    }

    fn render_title_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("title_bar")
            .exact_height(56.0)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(6, 8, 12))
                    .corner_radius(egui::CornerRadius {
                        nw: 22,
                        ne: 22,
                        sw: 0,
                        se: 0,
                    })
                    .inner_margin(egui::Margin::symmetric(16, 12))
                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(28, 36, 48))),
            )
            .show(ctx, |ui| {
                let compact_title = ui.available_width() < 760.0;
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
                        if !compact_title {
                            ui.label(
                                RichText::new("Static binary analysis workbench")
                                    .small()
                                    .color(Color32::from_rgb(124, 134, 147)),
                            );
                        }
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
            .default_width(248.0)
            .min_width(200.0)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(6, 9, 13))
                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(30, 38, 49)))
                    .inner_margin(egui::Margin {
                        left: 14,
                        right: 12,
                        top: 14,
                        bottom: 14,
                    }),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let compact_sidebar = ui.available_width() < 220.0;
                        ui.label(
                            RichText::new("Workspace")
                                .small()
                                .color(Color32::from_rgb(120, 130, 144)),
                        );
                        ui.label(
                            RichText::new("Analysis Session")
                                .size(24.0)
                                .strong()
                                .color(Color32::from_rgb(244, 245, 247)),
                        );
                        if !compact_sidebar {
                            ui.label(
                                RichText::new("One active target, fast navigation, clean analysis surfaces")
                                    .small()
                                    .color(Color32::from_rgb(126, 136, 149)),
                            );
                        }
                        ui.add_space(12.0);

                        egui::Frame::new()
                            .fill(Color32::from_rgb(10, 14, 18))
                            .corner_radius(egui::CornerRadius::same(24))
                            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(43, 53, 68)))
                            .inner_margin(egui::Margin::same(14))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("Target")
                                        .small()
                                        .color(Color32::from_rgb(145, 154, 166)),
                                );
                                ui.add_space(6.0);

                                if let Some(path) = &self.loaded_file {
                                    let file_name = path
                                        .file_name()
                                        .and_then(|name| name.to_str())
                                        .unwrap_or("Loaded binary");

                                    ui.label(
                                        RichText::new(file_name)
                                            .strong()
                                            .size(20.0)
                                            .color(Color32::from_rgb(240, 242, 245)),
                                    );
                                    if !compact_sidebar {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(path.display().to_string())
                                                    .small()
                                                    .monospace()
                                                    .color(Color32::from_rgb(152, 161, 174)),
                                            )
                                            .wrap(),
                                        );
                                    }

                                    ui.add_space(10.0);
                                    ui.horizontal_wrapped(|ui| {
                                        if let Some(report) = &self.report {
                                            sidebar_pill(ui, &report.format_name);
                                            sidebar_pill(ui, if report.is_64bit { "64-bit" } else { "32-bit" });
                                            sidebar_pill(ui, report.subsystem.as_str());
                                        } else {
                                            sidebar_pill(ui, "Pending");
                                        }
                                    });
                                } else {
                                    ui.label(
                                        RichText::new("No binary loaded")
                                            .strong()
                                            .color(Color32::from_rgb(230, 233, 238)),
                                    );
                                    if !compact_sidebar {
                                        ui.label(
                                            RichText::new("Open or drop an executable, library, package, or archive to begin.")
                                                .small()
                                                .color(Color32::from_rgb(140, 149, 160)),
                                        );
                                    }
                                }

                                ui.add_space(12.0);
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("Open EXE / DLL / SYS")
                                                .size(14.0)
                                                .color(Color32::from_rgb(247, 247, 248)),
                                        )
                                        .fill(Color32::from_rgb(207, 94, 57))
                                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(255, 197, 175)))
                                        .corner_radius(egui::CornerRadius::same(16))
                                        .min_size(egui::vec2(ui.available_width(), 40.0)),
                                    )
                                    .clicked()
                                {
                                    self.pick_file();
                                }

                                if let Some(path) = &self.loaded_file {
                                    ui.add_space(8.0);
                                    ui.horizontal_wrapped(|ui| {
                                        if ui.button("Copy Path").clicked() {
                                            ctx.copy_text(path.display().to_string());
                                        }

                                        if ui.button("Open Folder").clicked() {
                                            let folder = path.parent().unwrap_or(path.as_path());
                                            let _ = Command::new("explorer").arg(folder).spawn();
                                        }
                                    });
                                }
                            });

                        if let Some(error) = &self.last_error {
                            ui.add_space(10.0);
                            egui::Frame::new()
                                .fill(Color32::from_rgb(26, 12, 13))
                                .corner_radius(egui::CornerRadius::same(18))
                                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(120, 46, 52)))
                                .inner_margin(egui::Margin::same(12))
                                .show(ui, |ui| {
                                    ui.colored_label(Color32::from_rgb(255, 138, 138), error);
                                });
                        }

                        ui.add_space(16.0);
                        egui::Frame::new()
                            .fill(Color32::from_rgb(8, 11, 16))
                            .corner_radius(egui::CornerRadius::same(24))
                            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(37, 46, 59)))
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("Surfaces")
                                        .small()
                                        .color(Color32::from_rgb(140, 149, 160)),
                                );
                                ui.add_space(8.0);

                                for (tab, label) in [
                                    (ActiveTab::GeneralInfo, "General Info"),
                                    (ActiveTab::Resources, "Resources"),
                                    (ActiveTab::Headers, "Headers"),
                                    (ActiveTab::Hex, "Hex Viewer"),
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
                            });

                        if !compact_sidebar && !self.recent_files.is_empty() {
                            ui.add_space(12.0);
                            egui::Frame::new()
                                .fill(Color32::from_rgb(8, 11, 16))
                                .corner_radius(egui::CornerRadius::same(22))
                                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(34, 42, 54)))
                                .inner_margin(egui::Margin::same(12))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new("Recent")
                                            .small()
                                            .color(Color32::from_rgb(140, 149, 160)),
                                    );
                                    ui.add_space(8.0);

                                    let recent_files = self.recent_files.clone();
                                    for path in recent_files {
                                        let file_name = path
                                            .file_name()
                                            .and_then(|name| name.to_str())
                                            .unwrap_or("Recent target");

                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(file_name)
                                                        .color(Color32::from_rgb(210, 216, 224)),
                                                )
                                                .fill(Color32::from_rgb(11, 15, 20))
                                                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(31, 39, 51)))
                                                .corner_radius(egui::CornerRadius::same(14))
                                                .min_size(egui::vec2(ui.available_width(), 32.0)),
                                            )
                                            .on_hover_text(path.display().to_string())
                                            .clicked()
                                        {
                                            self.load_path(path.clone());
                                        }
                                    }
                                });
                        }

                        if !compact_sidebar {
                            ui.add_space(12.0);
                            egui::Frame::new()
                                .fill(Color32::from_rgb(8, 11, 16))
                                .corner_radius(egui::CornerRadius::same(22))
                                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(34, 42, 54)))
                                .inner_margin(egui::Margin::same(12))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new("Next")
                                            .small()
                                            .color(Color32::from_rgb(140, 149, 160)),
                                    );
                                    ui.add_space(4.0);
                                    ui.label(
                                        RichText::new("Resources, PE deep dives, YARA-friendly heuristics, and symbol depth")
                                            .small()
                                            .color(Color32::from_rgb(184, 191, 200)),
                                    );
                                });
                        }

                        ui.add_space(8.0);
                    });
            });
    }

    fn render_main(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(4, 7, 10))
                    .inner_margin(egui::Margin::same(10)),
            )
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(Color32::from_rgb(5, 8, 12))
                    .corner_radius(egui::CornerRadius::same(28))
                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(26, 34, 44)))
                    .inner_margin(egui::Margin::same(18))
                    .show(ui, |ui| {
                        let Some(report) = &self.report else {
                            render_empty_state(ui);
                            return;
                        };

                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                    .show(ui, |ui| match self.active_tab {
                        ActiveTab::GeneralInfo => render_overview(ui, report),
                        ActiveTab::Resources => render_resources(ui, report),
                        ActiveTab::Hex => render_hex_viewer(
                            ui,
                            report,
                            &mut self.hex_offset_input,
                            &mut self.hex_rva_input,
                            &mut self.hex_status,
                        ),
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
                            });
                    });
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
            30.0,
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
                    .corner_radius(egui::CornerRadius::same(28))
                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(76, 90, 111)))
                    .inner_margin(egui::Margin::same(22))
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

impl eframe::App for BlackpointApp {
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
    style.visuals.window_stroke = egui::Stroke::new(1.0, Color32::from_rgb(58, 70, 88));
    style.visuals.window_corner_radius = egui::CornerRadius::same(24);
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(16.0, 10.0);
    style.spacing.window_margin = egui::Margin::same(16);
    ctx.set_style(style);
}

fn render_empty_state(ui: &mut Ui) {
    let compact = ui.available_width() < 840.0;
    ui.vertical_centered(|ui| {
        ui.add_space(if compact { 48.0 } else { 104.0 });
        egui::Frame::new()
            .fill(Color32::from_rgb(7, 9, 12))
            .corner_radius(egui::CornerRadius::same(34))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(34, 42, 56)))
            .inner_margin(egui::Margin::same(32))
            .show(ui, |ui| {
                ui.set_max_width((ui.available_width() - 24.0).clamp(320.0, 620.0));
                ui.label(
                    RichText::new("Static analysis for real binaries")
                        .size(if compact { 24.0 } else { 30.0 })
                        .strong()
                        .color(Color32::from_rgb(246, 247, 248)),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new("Open an executable, library, package, or archive to inspect structure, strings, imports, exports, and format-specific metadata.")
                        .color(Color32::from_rgb(140, 149, 160)),
                );
                ui.add_space(18.0);
                ui.horizontal_wrapped(|ui| {
                    pill(ui, "Drag & Drop");
                    pill(ui, "Multi-Format");
                    pill(ui, "Disassembly");
                });
            });
    });
}

fn render_overview(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "General Info", "Core file metadata, hashes, mitigations, and build signals");

    let width = ui.available_width();
    let imported_api_count = report.imports.iter().map(|dll| dll.functions.len()).sum::<usize>();
    let architecture = if report.is_64bit { "64-bit" } else { "32-bit / n.a." };
    let profile_rows = vec![
        ("Family".to_string(), report.format_family.clone()),
        ("Confidence".to_string(), report.detection_confidence.clone()),
        ("Architecture".to_string(), architecture.to_string()),
        ("Subsystem".to_string(), report.subsystem.clone()),
        ("Machine".to_string(), report.machine_type.clone()),
        ("Section Count".to_string(), report.section_count.to_string()),
        ("Timestamp".to_string(), format!("0x{:08X}", report.timestamp)),
        ("File Size".to_string(), format!("{} bytes", report.file_size)),
    ];
    let layout_rows = vec![
        ("Image Base".to_string(), format!("0x{:X}", report.image_base)),
        ("Entry Point".to_string(), format!("0x{:X}", report.entry_point)),
        ("Section Alignment".to_string(), format!("0x{:X}", report.section_alignment)),
        ("File Alignment".to_string(), format!("0x{:X}", report.file_alignment)),
        ("ASLR".to_string(), bool_badge(report.protections.aslr).to_string()),
        ("DEP / NX".to_string(), bool_badge(report.protections.dep_nx).to_string()),
        ("SEH".to_string(), bool_badge(report.protections.seh_enabled).to_string()),
        ("TLS Callbacks".to_string(), report.protections.tls_callbacks.to_string()),
    ];
    let hash_rows = vec![
        ("MD5".to_string(), report.md5.clone()),
        ("SHA-1".to_string(), report.sha1.clone()),
        ("SHA-256".to_string(), report.sha256_placeholder.clone()),
    ];
    let file_name = report
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Unknown binary");

    framed_panel(ui, |ui| {
        if width >= 1600.0 {
            ui.columns(2, |columns| {
                columns[0].vertical(|ui| {
                    render_overview_identity(ui, report, file_name, architecture);
                });

                columns[1].vertical(|ui| {
                    render_overview_snapshot(ui, report, imported_api_count);
                });
            });
        } else {
            render_overview_identity(ui, report, file_name, architecture);
            ui.add_space(14.0);
            render_overview_snapshot(ui, report, imported_api_count);
        }
    });

    ui.add_space(14.0);
    if width >= 1500.0 {
        ui.columns(2, |columns| {
            framed_panel(&mut columns[0], |ui| {
                render_overview_rows(ui, "Binary Profile", &profile_rows);
            });

            framed_panel(&mut columns[1], |ui| {
                render_overview_rows(ui, "Execution Layout", &layout_rows);
            });
        });
    } else {
        framed_panel(ui, |ui| {
            render_overview_rows(ui, "Binary Profile", &profile_rows);
        });
        ui.add_space(14.0);
        framed_panel(ui, |ui| {
            render_overview_rows(ui, "Execution Layout", &layout_rows);
        });
    }

    ui.add_space(14.0);
    if width >= 1500.0 {
        ui.columns(2, |columns| {
            framed_panel(&mut columns[0], |ui| {
                render_overview_rows(ui, "Hashes", &hash_rows);
            });

            framed_panel(&mut columns[1], |ui| {
                render_notes_panel(ui, &report.notes);
            });
        });
    } else {
        framed_panel(ui, |ui| {
            render_overview_rows(ui, "Hashes", &hash_rows);
        });
        ui.add_space(14.0);
        framed_panel(ui, |ui| {
            render_notes_panel(ui, &report.notes);
        });
    }
}

fn render_overview_rows(ui: &mut Ui, title: &str, rows: &[(String, String)]) {
    ui.label(
        RichText::new(title)
            .strong()
            .color(Color32::from_rgb(229, 233, 237)),
    );
    ui.add_space(8.0);
    egui::Grid::new(title)
        .num_columns(2)
        .spacing([20.0, 10.0])
        .show(ui, |ui| {
            for (label, value) in rows {
                overview_row(ui, label, value);
            }
        });
}

fn render_overview_identity(ui: &mut Ui, report: &BinaryReport, file_name: &str, architecture: &str) {
    ui.label(
        RichText::new(file_name)
            .size(24.0)
            .strong()
            .color(Color32::from_rgb(245, 246, 248)),
    );
    ui.add_space(4.0);

    egui::Frame::new()
        .fill(Color32::from_rgb(8, 11, 16))
        .corner_radius(egui::CornerRadius::same(18))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(36, 45, 58)))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.label(
                RichText::new(report.path.display().to_string())
                    .small()
                    .monospace()
                    .color(Color32::from_rgb(152, 161, 174)),
            );
        });

    ui.add_space(10.0);
    ui.horizontal_wrapped(|ui| {
        pill(ui, &report.format_name);
        pill(ui, architecture);
        pill(ui, report.subsystem.as_str());
    });

    ui.add_space(14.0);
    ui.horizontal_wrapped(|ui| {
        inline_fact(ui, "Machine", &report.machine_type);
        inline_fact(ui, "Entry", &format!("0x{:X}", report.entry_point));
        inline_fact(ui, "Image Base", &format!("0x{:X}", report.image_base));
        inline_fact(ui, "Size", &format!("{} bytes", report.file_size));
    });
}

fn render_overview_snapshot(ui: &mut Ui, report: &BinaryReport, imported_api_count: usize) {
    ui.label(
        RichText::new("Snapshot")
            .strong()
            .color(Color32::from_rgb(229, 233, 237)),
    );
    ui.add_space(8.0);
    if ui.available_width() >= 760.0 {
        ui.columns(2, |columns| {
            metric_tile(
                &mut columns[0],
                "Sections",
                &report.sections.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            );
            metric_tile(
                &mut columns[1],
                "Imported APIs",
                &imported_api_count.to_string(),
                Color32::from_rgb(92, 184, 92),
            );
        });
        ui.add_space(10.0);
        ui.columns(2, |columns| {
            metric_tile(
                &mut columns[0],
                "Strings",
                &report.strings.len().to_string(),
                Color32::from_rgb(210, 144, 72),
            );
            metric_tile(
                &mut columns[1],
                "TLS Callbacks",
                &report.protections.tls_callbacks.to_string(),
                Color32::from_rgb(198, 122, 255),
            );
        });
    } else {
        metric_tile(
            ui,
            "Sections",
            &report.sections.len().to_string(),
            Color32::from_rgb(90, 160, 255),
        );
        ui.add_space(10.0);
        metric_tile(
            ui,
            "Imported APIs",
            &imported_api_count.to_string(),
            Color32::from_rgb(92, 184, 92),
        );
        ui.add_space(10.0);
        metric_tile(
            ui,
            "Strings",
            &report.strings.len().to_string(),
            Color32::from_rgb(210, 144, 72),
        );
        ui.add_space(10.0);
        metric_tile(
            ui,
            "TLS Callbacks",
            &report.protections.tls_callbacks.to_string(),
            Color32::from_rgb(198, 122, 255),
        );
    }
}

fn render_notes_panel(ui: &mut Ui, notes: &[String]) {
    ui.label(
        RichText::new("Heuristic Notes")
            .strong()
            .color(Color32::from_rgb(229, 233, 237)),
    );
    ui.add_space(8.0);
    for note in notes {
        ui.label(
            RichText::new(format!("* {note}"))
                .color(Color32::from_rgb(162, 172, 184)),
        );
    }
}

fn metric_tile(ui: &mut Ui, title: &str, value: &str, accent: Color32) {
    egui::Frame::new()
        .fill(Color32::from_rgb(10, 14, 18))
        .corner_radius(egui::CornerRadius::same(22))
        .stroke(egui::Stroke::new(1.0, accent.gamma_multiply(0.75)))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(130.0);
            ui.set_min_height(94.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(title).small().color(Color32::from_rgb(145, 154, 166)));
                ui.add_space(6.0);
                ui.label(
                    RichText::new(value)
                        .size(24.0)
                        .strong()
                        .color(accent),
                );
            });
        });
}

fn inline_fact(ui: &mut Ui, label: &str, value: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(8, 11, 16))
        .corner_radius(egui::CornerRadius::same(16))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(34, 43, 55)))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(label)
                        .small()
                        .color(Color32::from_rgb(145, 154, 166)),
                );
                ui.label(
                    RichText::new(value)
                        .monospace()
                        .color(Color32::from_rgb(214, 220, 228)),
                );
            });
        });
}

fn render_hex_viewer(
    ui: &mut Ui,
    report: &BinaryReport,
    hex_offset_input: &mut String,
    hex_rva_input: &mut String,
    hex_status: &mut Option<String>,
) {
    render_panel_title(ui, "Hex Viewer", "Raw byte view with offset jump and synchronized ASCII preview");
    let compact = ui.available_width() < 760.0;

    framed_panel(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Offset").color(Color32::from_rgb(188, 195, 205)));
            ui.add_sized(
                [if compact { (ui.available_width() - 120.0).max(140.0) } else { 180.0 }, 28.0],
                egui::TextEdit::singleline(hex_offset_input).hint_text("0x401000 or 16384"),
            );

            if ui.button("Jump").clicked() {
                match parse_offset_input(hex_offset_input, report.raw_bytes.len()) {
                    Ok(offset) => {
                        *hex_offset_input = format!("0x{offset:X}");
                        *hex_status = Some(format!("Jumped to offset 0x{offset:X}"));
                    }
                    Err(err) => *hex_status = Some(err),
                }
            }

            if ui.button("Entry").clicked() {
                let offset = raw_offset_for_entry(report).min(report.raw_bytes.len().saturating_sub(1));
                *hex_offset_input = format!("0x{offset:X}");
                if let Some(rva) = rva_from_raw_offset(report, offset) {
                    *hex_rva_input = format!("0x{rva:X}");
                }
                *hex_status = Some(format!("Jumped near entry point at raw offset 0x{offset:X}"));
            }

            if !compact {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{} bytes loaded", report.raw_bytes.len()))
                            .small()
                            .monospace()
                            .color(Color32::from_rgb(126, 136, 149)),
                    );
                });
            }
        });

        if let Some(status) = hex_status.as_deref() {
            ui.add_space(8.0);
            ui.label(
                RichText::new(status)
                    .small()
                    .color(if status.starts_with("Invalid") || status.contains("outside") {
                        Color32::from_rgb(235, 104, 104)
                    } else {
                        Color32::from_rgb(150, 180, 150)
                    }),
            );
        }
    });

    if report.format_name == "PE" && !report.sections.is_empty() {
        ui.add_space(10.0);
        framed_panel(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("RVA").color(Color32::from_rgb(188, 195, 205)));
                ui.add_sized(
                    [if compact { (ui.available_width() - 120.0).max(140.0) } else { 180.0 }, 28.0],
                    egui::TextEdit::singleline(hex_rva_input).hint_text("0x1130"),
                );

                if ui.button("Jump RVA").clicked() {
                    match parse_offset_input(hex_rva_input, usize::MAX) {
                        Ok(rva) => {
                            if let Some(offset) = raw_offset_from_rva(report, rva as u64) {
                                *hex_offset_input = format!("0x{offset:X}");
                                *hex_rva_input = format!("0x{:X}", rva);
                                *hex_status = Some(format!("RVA 0x{rva:X} resolved to raw offset 0x{offset:X}"));
                            } else {
                                *hex_status = Some(format!("RVA 0x{rva:X} does not map to a loaded section"));
                            }
                        }
                        Err(err) => *hex_status = Some(err),
                    }
                }
            });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Sections").color(Color32::from_rgb(188, 195, 205)));
                for section in &report.sections {
                    if ui.button(section.name.as_str()).clicked() {
                        let offset = section.raw_address as usize;
                        *hex_offset_input = format!("0x{offset:X}");
                        *hex_rva_input = format!("0x{:X}", section.virtual_address);
                        *hex_status = Some(format!(
                            "Jumped to section {} at raw 0x{:X} / RVA 0x{:X}",
                            section.name, section.raw_address, section.virtual_address
                        ));
                    }
                }
            });
        });
    }

    ui.add_space(10.0);

    let selected_offset = parse_offset_input(hex_offset_input, report.raw_bytes.len()).unwrap_or(0);
    if let Some(rva) = rva_from_raw_offset(report, selected_offset) {
        *hex_rva_input = format!("0x{rva:X}");
    }
    let row_size = 16usize;
    let selected_row = selected_offset / row_size;
    let start_row = selected_row.saturating_sub(8);
    let total_rows = report.raw_bytes.len().div_ceil(row_size);
    let end_row = (start_row + 160).min(total_rows);

    framed_panel(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("Raw 0x{selected_offset:X}"))
                    .small()
                    .monospace()
                    .color(Color32::from_rgb(152, 161, 174)),
            );
            if let Some(rva) = rva_from_raw_offset(report, selected_offset) {
                ui.label(
                    RichText::new(format!("RVA 0x{rva:X}"))
                        .small()
                        .monospace()
                        .color(Color32::from_rgb(152, 161, 174)),
                );
            }
            if let Some(section_name) = section_name_for_raw_offset(report, selected_offset) {
                ui.label(
                    RichText::new(section_name)
                        .small()
                        .color(Color32::from_rgb(207, 94, 57)),
                );
            }
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new("Offset        Hex Bytes                                              ASCII")
                .monospace()
                .color(Color32::from_rgb(142, 151, 163)),
        );
        ui.add_space(6.0);

        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            for row_index in start_row..end_row {
                let start = row_index * row_size;
                let end = (start + row_size).min(report.raw_bytes.len());
                let row = &report.raw_bytes[start..end];
                let is_focus_row = selected_offset >= start && selected_offset < end;

                let line = format!(
                    "{:08X}    {:<48}    {}",
                    start,
                    format_hex_bytes(row, row_size),
                    format_ascii_preview(row)
                );

                let text = RichText::new(line).monospace().color(if is_focus_row {
                    Color32::from_rgb(255, 210, 188)
                } else {
                    Color32::from_rgb(196, 202, 212)
                });

                if is_focus_row {
                    egui::Frame::new()
                        .fill(Color32::from_rgb(26, 17, 14))
                        .corner_radius(egui::CornerRadius::same(16))
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(207, 94, 57)))
                        .inner_margin(egui::Margin::symmetric(8, 4))
                        .show(ui, |ui| {
                            ui.label(text);
                        });
                } else {
                    ui.label(text);
                }
            }
        });
    });
}

fn render_resources(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "Resources",
        "PE resource tree, version information, manifest signals, and embedded metadata",
    );

    if report.resource_entries.is_empty() && report.version_info_rows.is_empty() && report.manifest_text.is_none() {
        framed_panel(ui, |ui| {
            ui.label(
                RichText::new("No PE resource directory was parsed for this target.")
                    .color(Color32::from_rgb(140, 149, 160)),
            );
        });
        return;
    }

    let width = ui.available_width();

    let file_name = report
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("PE resources");
    let architecture = if report.is_64bit { "64-bit" } else { "32-bit / n.a." };

    framed_panel(ui, |ui| {
        if width >= 1680.0 {
            ui.columns(2, |columns| {
                columns[0].vertical(|ui| {
                    render_resource_identity(ui, report, file_name, architecture);
                });
                columns[1].vertical(|ui| {
                    render_resource_snapshot(ui, report);
                });
            });
        } else {
            render_resource_identity(ui, report, file_name, architecture);
            ui.add_space(14.0);
            render_resource_snapshot(ui, report);
        }
    });

    ui.add_space(12.0);

    if width >= 1760.0 {
        ui.columns(2, |columns| {
            render_resource_tree_panel(&mut columns[0], report);
            render_resource_detail_stack(&mut columns[1], report);
        });
    } else {
        render_resource_tree_panel(ui, report);
        ui.add_space(12.0);
        render_resource_detail_stack(ui, report);
    }
}

fn render_resource_identity(ui: &mut Ui, report: &BinaryReport, file_name: &str, architecture: &str) {
    ui.label(
        RichText::new(file_name)
            .size(24.0)
            .strong()
            .color(Color32::from_rgb(245, 246, 248)),
    );
    ui.add_space(4.0);

    egui::Frame::new()
        .fill(Color32::from_rgb(8, 11, 16))
        .corner_radius(egui::CornerRadius::same(18))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(36, 45, 58)))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.label(
                RichText::new(report.path.display().to_string())
                    .small()
                    .monospace()
                    .color(Color32::from_rgb(152, 161, 174)),
            );
        });

    ui.add_space(10.0);
    ui.horizontal_wrapped(|ui| {
        pill(ui, "Resource Directory");
        pill(ui, architecture);
        if report.manifest_text.is_some() {
            pill(ui, "Manifest Present");
        }
        if !report.version_info_rows.is_empty() {
            pill(ui, "Version Info");
        }
    });

    ui.add_space(14.0);
    ui.horizontal_wrapped(|ui| {
        inline_fact(ui, "Nodes", &report.resource_entries.len().to_string());
        inline_fact(ui, "Version Rows", &report.version_info_rows.len().to_string());
        inline_fact(
            ui,
            "Manifest",
            if report.manifest_text.is_some() { "Present" } else { "Missing" },
        );
        inline_fact(ui, "Build Signals", &report.pe_metadata_rows.len().to_string());
    });
}

fn render_resource_snapshot(ui: &mut Ui, report: &BinaryReport) {
    ui.label(
        RichText::new("Snapshot")
            .strong()
            .color(Color32::from_rgb(229, 233, 237)),
    );
    ui.add_space(8.0);

    let compact = ui.available_width() < 760.0;
    let top_row = [
        (
            "Resource Nodes",
            report.resource_entries.len().to_string(),
            Color32::from_rgb(90, 160, 255),
        ),
        (
            "Version Rows",
            report.version_info_rows.len().to_string(),
            Color32::from_rgb(92, 184, 92),
        ),
    ];
    let bottom_row = [
        (
            "Manifest",
            if report.manifest_text.is_some() { "Present".to_string() } else { "Missing".to_string() },
            Color32::from_rgb(210, 144, 72),
        ),
        (
            "Build Signals",
            report.pe_metadata_rows.len().to_string(),
            Color32::from_rgb(198, 122, 255),
        ),
    ];

    if compact {
        for (title, value, accent) in top_row.into_iter().chain(bottom_row.into_iter()) {
            metric_tile(ui, title, &value, accent);
            ui.add_space(10.0);
        }
    } else {
        ui.columns(2, |columns| {
            metric_tile(&mut columns[0], top_row[0].0, &top_row[0].1, top_row[0].2);
            metric_tile(&mut columns[1], top_row[1].0, &top_row[1].1, top_row[1].2);
        });
        ui.add_space(10.0);
        ui.columns(2, |columns| {
            metric_tile(&mut columns[0], bottom_row[0].0, &bottom_row[0].1, bottom_row[0].2);
            metric_tile(&mut columns[1], bottom_row[1].0, &bottom_row[1].1, bottom_row[1].2);
        });
    }
}

fn render_resource_tree_panel(ui: &mut Ui, report: &BinaryReport) {
    framed_panel(ui, |ui| {
        ui.label(
            RichText::new("Resource Tree")
                .strong()
                .color(Color32::from_rgb(229, 233, 237)),
        );
        ui.add_space(8.0);

        if report.resource_entries.is_empty() {
            ui.label(
                RichText::new("No resource nodes were enumerated.")
                    .color(Color32::from_rgb(140, 149, 160)),
            );
            return;
        }

        let visible_rows = report.resource_entries.len().clamp(4, 12) as f32;
        let tree_height = 34.0 + visible_rows * 32.0;

        tabular_surface(ui, "resource_tree_table", 680.0, |ui| {
            let available = ui.available_width().max(680.0);
            let kind_width = 92.0;
            let size_width = 72.0;
            let code_page_width = 92.0;
            let name_width = (available - kind_width - size_width - code_page_width - 36.0).max(240.0);

            resource_tree_header(ui, name_width, kind_width, size_width, code_page_width);
            ui.add_space(8.0);

            vertical_surface_scroll(ui, "resource_tree_rows", tree_height, |ui| {
                for entry in &report.resource_entries {
                    resource_tree_row(ui, entry, name_width, kind_width, size_width, code_page_width);
                    ui.add_space(6.0);
                }
            });
        });
    });
}

fn render_resource_detail_stack(ui: &mut Ui, report: &BinaryReport) {
    if !report.pe_metadata_rows.is_empty() {
        framed_panel(ui, |ui| {
            ui.label(
                RichText::new("PE Build Signals")
                    .strong()
                    .color(Color32::from_rgb(229, 233, 237)),
            );
            ui.add_space(8.0);
            render_kv_rows(ui, "pe_build_signals_rows", &report.pe_metadata_rows);
        });

        ui.add_space(12.0);
    }

    framed_panel(ui, |ui| {
        ui.label(
            RichText::new("Version Info")
                .strong()
                .color(Color32::from_rgb(229, 233, 237)),
        );
        ui.add_space(8.0);

        if report.version_info_rows.is_empty() {
            ui.label(
                RichText::new("No version resource was extracted.")
                    .color(Color32::from_rgb(140, 149, 160)),
            );
        } else {
            vertical_surface_scroll(ui, "version_info_rows_scroll", 240.0, |ui| {
                render_kv_rows(ui, "version_info_rows", &report.version_info_rows);
            });
        }
    });

    ui.add_space(12.0);

    framed_panel(ui, |ui| {
        ui.label(
            RichText::new("Manifest")
                .strong()
                .color(Color32::from_rgb(229, 233, 237)),
        );
        ui.add_space(8.0);

        if report.manifest_text.is_none() {
            ui.label(
                RichText::new("No application manifest was extracted.")
                    .color(Color32::from_rgb(140, 149, 160)),
            );
            return;
        }

        if !report.manifest_rows.is_empty() {
            render_kv_rows(ui, "manifest_signal_rows", &report.manifest_rows);
            ui.add_space(10.0);
        }

        egui::Frame::new()
            .fill(Color32::from_rgb(7, 10, 15))
            .corner_radius(egui::CornerRadius::same(20))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(35, 44, 56)))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                vertical_surface_scroll(ui, "manifest_text_scroll", 260.0, |ui| {
                    if let Some(text) = &report.manifest_text {
                        ui.label(
                            RichText::new(text)
                                .monospace()
                                .color(Color32::from_rgb(194, 201, 211)),
                        );
                    }
                });
            });
    });
}

fn resource_tree_header(ui: &mut Ui, name_width: f32, kind_width: f32, size_width: f32, code_page_width: f32) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [name_width, 18.0],
            egui::Label::new(RichText::new("Name").small().color(Color32::from_rgb(145, 154, 166))),
        );
        ui.add_sized(
            [kind_width, 18.0],
            egui::Label::new(RichText::new("Kind").small().color(Color32::from_rgb(145, 154, 166))),
        );
        ui.add_sized(
            [size_width, 18.0],
            egui::Label::new(RichText::new("Size").small().color(Color32::from_rgb(145, 154, 166))),
        );
        ui.add_sized(
            [code_page_width, 18.0],
            egui::Label::new(RichText::new("CodePage").small().color(Color32::from_rgb(145, 154, 166))),
        );
    });
}

fn resource_tree_row(
    ui: &mut Ui,
    entry: &crate::analyzer::ResourceEntry,
    name_width: f32,
    kind_width: f32,
    size_width: f32,
    code_page_width: f32,
) {
    egui::Frame::new()
        .fill(Color32::from_rgb(10, 14, 19))
        .corner_radius(egui::CornerRadius::same(16))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(27, 35, 45)))
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(name_width, 22.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.add_space((entry.depth as f32 * 14.0).min(84.0));
                        let marker = if entry.kind == "Directory" { ">" } else { "-" };
                        ui.label(
                            RichText::new(format!("{marker} {}", entry.name))
                                .monospace()
                                .color(Color32::from_rgb(210, 216, 224)),
                        )
                        .on_hover_text(&entry.path);
                    },
                );
                ui.add_sized(
                    [kind_width, 22.0],
                    egui::Label::new(
                        RichText::new(&entry.kind)
                            .small()
                            .color(Color32::from_rgb(174, 183, 194)),
                    ),
                );
                ui.add_sized(
                    [size_width, 22.0],
                    egui::Label::new(
                        RichText::new(if entry.size == 0 {
                            "-".to_string()
                        } else {
                            entry.size.to_string()
                        })
                        .monospace()
                        .color(Color32::from_rgb(192, 198, 207)),
                    ),
                );
                ui.add_sized(
                    [code_page_width, 22.0],
                    egui::Label::new(
                        RichText::new(if entry.code_page == 0 {
                            "-".to_string()
                        } else {
                            format!("0x{:X}", entry.code_page)
                        })
                        .monospace()
                        .color(Color32::from_rgb(192, 198, 207)),
                    ),
                );
            });
        });
}

fn render_metric_strip(ui: &mut Ui, metrics: &[(&str, String, Color32)]) {
    if ui.available_width() >= 760.0 && metrics.len() >= 4 {
        ui.columns(2, |columns| {
            metric_tile(&mut columns[0], metrics[0].0, &metrics[0].1, metrics[0].2);
            metric_tile(&mut columns[1], metrics[1].0, &metrics[1].1, metrics[1].2);
        });
        ui.add_space(10.0);
        ui.columns(2, |columns| {
            metric_tile(&mut columns[0], metrics[2].0, &metrics[2].1, metrics[2].2);
            metric_tile(&mut columns[1], metrics[3].0, &metrics[3].1, metrics[3].2);
        });
    } else {
        for (index, (title, value, accent)) in metrics.iter().enumerate() {
            metric_tile(ui, title, value, *accent);
            if index + 1 < metrics.len() {
                ui.add_space(10.0);
            }
        }
    }
}

fn section_surface(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(7, 10, 15))
        .corner_radius(egui::CornerRadius::same(20))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(35, 44, 56)))
        .inner_margin(egui::Margin::same(12))
        .show(ui, add_contents);
}

fn tabular_surface(
    ui: &mut Ui,
    id_source: impl std::hash::Hash,
    min_width: f32,
    add_contents: impl FnOnce(&mut Ui),
) {
    section_surface(ui, |ui| {
        egui::ScrollArea::horizontal()
            .id_salt(ui.id().with(id_source).with("tabular_surface"))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_min_width(min_width);
                add_contents(ui);
            });
    });
}

fn vertical_surface_scroll(
    ui: &mut Ui,
    id_source: impl std::hash::Hash,
    max_height: f32,
    add_contents: impl FnOnce(&mut Ui),
) {
    egui::ScrollArea::vertical()
        .id_salt(ui.id().with(id_source).with("vertical_surface_scroll"))
        .max_height(max_height)
        .auto_shrink([false, false])
        .show(ui, add_contents);
}

fn render_sections(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Sections", "PE section layout, permissions, and entropy");

    let executable_sections = report
        .sections
        .iter()
        .filter(|section| section.characteristics.contains("EXECUTE"))
        .count();
    let writable_sections = report
        .sections
        .iter()
        .filter(|section| section.characteristics.contains("WRITE"))
        .count();
    let high_entropy_sections = report.sections.iter().filter(|section| section.entropy >= 7.0).count();

    render_metric_strip(
        ui,
        &[
            ("Count", report.sections.len().to_string(), Color32::from_rgb(90, 160, 255)),
            ("Executable", executable_sections.to_string(), Color32::from_rgb(92, 184, 92)),
            ("Writable", writable_sections.to_string(), Color32::from_rgb(210, 144, 72)),
            ("High Entropy", high_entropy_sections.to_string(), Color32::from_rgb(198, 122, 255)),
        ],
    );
    ui.add_space(12.0);

    framed_panel(ui, |ui| {
        tabular_surface(ui, "sections_table", 860.0, |ui| {
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
    });
}

fn render_imports(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Imports", "Grouped imported DLLs and resolved function names");

    let import_count = report.imports.iter().map(|dll| dll.functions.len()).sum::<usize>();
    let ordinal_count = report
        .imports
        .iter()
        .flat_map(|dll| dll.functions.iter())
        .filter(|func| func.ordinal != 0)
        .count();

    render_metric_strip(
        ui,
        &[
            ("DLLs", report.imports.len().to_string(), Color32::from_rgb(90, 160, 255)),
            ("APIs", import_count.to_string(), Color32::from_rgb(92, 184, 92)),
            ("Ordinals", ordinal_count.to_string(), Color32::from_rgb(210, 144, 72)),
            (
                "Empty Groups",
                report.imports.iter().filter(|dll| dll.functions.is_empty()).count().to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(12.0);

    framed_panel(ui, |ui| {
        section_surface(ui, |ui| {
            vertical_surface_scroll(ui, "imports_list_scroll", 560.0, |ui| {
                for dll in &report.imports {
                    egui::CollapsingHeader::new(format!("{} ({})", dll.name, dll.functions.len()))
                        .default_open(dll.functions.len() <= 12)
                        .show(ui, |ui| {
                            if dll.functions.is_empty() {
                                ui.label(RichText::new("Container or library reference only").small().color(Color32::GRAY));
                            }
                            for function in &dll.functions {
                                egui::Frame::new()
                                    .fill(Color32::from_rgb(9, 13, 18))
                                    .corner_radius(egui::CornerRadius::same(14))
                                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(28, 36, 46)))
                                    .inner_margin(egui::Margin::symmetric(10, 6))
                                    .show(ui, |ui| {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.monospace(&function.name);
                                            ui.label(
                                                RichText::new(format!("ordinal {}", function.ordinal))
                                                    .small()
                                                    .color(Color32::from_rgb(145, 154, 166)),
                                            );
                                        });
                                    });
                                ui.add_space(6.0);
                            }
                        });
                    ui.add_space(6.0);
                }
            });
        });
    });
}

fn render_exports(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Exports", "Exported names with offsets and RVAs");

    render_metric_strip(
        ui,
        &[
            ("Exports", report.exports.len().to_string(), Color32::from_rgb(90, 160, 255)),
            (
                "Named",
                report
                    .exports
                    .iter()
                    .filter(|export| export.name != "<ordinal>")
                    .count()
                    .to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "Ordinal",
                report
                    .exports
                    .iter()
                    .filter(|export| export.name == "<ordinal>")
                    .count()
                    .to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "Last RVA",
                report
                    .exports
                    .iter()
                    .map(|export| export.rva)
                    .max()
                    .map(|value| format!("0x{value:X}"))
                    .unwrap_or_else(|| "-".to_string()),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(12.0);

    framed_panel(ui, |ui| {
        tabular_surface(ui, "exports_table", 520.0, |ui| {
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
    let compact = ui.available_width() < 820.0;

    framed_panel(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Search").color(Color32::from_rgb(188, 195, 205)));
                ui.add_sized(
                    [if compact { (ui.available_width() - 80.0).max(180.0) } else { 340.0 }, 28.0],
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

    render_metric_strip(
        ui,
        &[
            ("Total", report.strings.len().to_string(), Color32::from_rgb(90, 160, 255)),
            ("Visible", filtered.len().to_string(), Color32::from_rgb(92, 184, 92)),
            (
                "ASCII",
                report.strings.iter().filter(|entry| entry.kind == "ASCII").count().to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "UTF-16LE",
                report
                    .strings
                    .iter()
                    .filter(|entry| entry.kind == "UTF-16LE")
                    .count()
                    .to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(10.0);

    ui.horizontal_wrapped(|ui| {
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
        tabular_surface(ui, "strings_table", 640.0, |ui| {
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
    });
}

fn render_disassembly(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "Disassembly",
        "Entry-point focused preview from .text or the containing section",
    );

    let first_address = report
        .disassembly
        .first()
        .map(|insn| format!("0x{:X}", insn.address))
        .unwrap_or_else(|| "-".to_string());
    let last_address = report
        .disassembly
        .last()
        .map(|insn| format!("0x{:X}", insn.address))
        .unwrap_or_else(|| "-".to_string());

    render_metric_strip(
        ui,
        &[
            ("Instructions", report.disassembly.len().to_string(), Color32::from_rgb(90, 160, 255)),
            ("Entry", format!("0x{:X}", report.entry_point), Color32::from_rgb(92, 184, 92)),
            ("First", first_address, Color32::from_rgb(210, 144, 72)),
            ("Last", last_address, Color32::from_rgb(198, 122, 255)),
        ],
    );
    ui.add_space(12.0);

    framed_panel(ui, |ui| {
        tabular_surface(ui, "disassembly_table", 780.0, |ui| {
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
    });
}

fn parse_offset_input(input: &str, len: usize) -> Result<usize, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() || len == 0 {
        return Ok(0);
    }

    let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).map_err(|_| "Invalid hex offset".to_string())?
    } else {
        trimmed.parse::<usize>().map_err(|_| "Invalid decimal offset".to_string())?
    };

    if parsed >= len {
        return Err(format!("Offset 0x{parsed:X} is outside the loaded file"));
    }

    Ok(parsed)
}

fn raw_offset_for_entry(report: &BinaryReport) -> usize {
    report
        .sections
        .iter()
        .find(|section| {
            let start = section.virtual_address as u64;
            let span = section.virtual_size.max(section.raw_size) as u64;
            let end = start.saturating_add(span);
            report.entry_point >= start && report.entry_point < end
        })
        .map(|section| {
            let delta = report.entry_point.saturating_sub(section.virtual_address as u64) as usize;
            section.raw_address as usize + delta
        })
        .unwrap_or_default()
}

fn raw_offset_from_rva(report: &BinaryReport, rva: u64) -> Option<usize> {
    report.sections.iter().find_map(|section| {
        let start = section.virtual_address as u64;
        let span = section.virtual_size.max(section.raw_size) as u64;
        let end = start.saturating_add(span);
        if rva >= start && rva < end {
            Some(section.raw_address as usize + (rva - start) as usize)
        } else {
            None
        }
    })
}

fn rva_from_raw_offset(report: &BinaryReport, raw_offset: usize) -> Option<u64> {
    report.sections.iter().find_map(|section| {
        let start = section.raw_address as usize;
        let end = start.saturating_add(section.raw_size as usize);
        if raw_offset >= start && raw_offset < end {
            Some(section.virtual_address as u64 + (raw_offset - start) as u64)
        } else {
            None
        }
    })
}

fn section_name_for_raw_offset(report: &BinaryReport, raw_offset: usize) -> Option<&str> {
    report.sections.iter().find_map(|section| {
        let start = section.raw_address as usize;
        let end = start.saturating_add(section.raw_size as usize);
        if raw_offset >= start && raw_offset < end {
            Some(section.name.as_str())
        } else {
            None
        }
    })
}

fn format_hex_bytes(row: &[u8], row_size: usize) -> String {
    let mut output = String::new();

    for index in 0..row_size {
        if index == 8 {
            output.push(' ');
        }
        if index > 0 {
            output.push(' ');
        }

        if let Some(byte) = row.get(index) {
            output.push_str(&format!("{byte:02X}"));
        } else {
            output.push_str("  ");
        }
    }

    output
}

fn format_ascii_preview(row: &[u8]) -> String {
    row.iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn render_archive(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Archive", "Container members for ZIP-like and package formats");

    let total_archive_size = report.archive_entries.iter().map(|entry| entry.size).sum::<u64>();
    render_metric_strip(
        ui,
        &[
            ("Entries", report.archive_entries.len().to_string(), Color32::from_rgb(90, 160, 255)),
            ("Total Size", total_archive_size.to_string(), Color32::from_rgb(92, 184, 92)),
            (
                "Kinds",
                report
                    .archive_entries
                    .iter()
                    .map(|entry| entry.kind.as_str())
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    .to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            ("Format", report.format_name.clone(), Color32::from_rgb(198, 122, 255)),
        ],
    );
    ui.add_space(12.0);

    framed_panel(ui, |ui| {
        if report.archive_entries.is_empty() {
            ui.label(
                RichText::new("No parsed archive member table for this file.")
                    .color(Color32::from_rgb(140, 149, 160)),
            );
            return;
        }

        tabular_surface(ui, "archive_table", 560.0, |ui| {
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
    });
}

fn render_headers(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Headers", "DOS, file, and optional header detail");

    render_metric_strip(
        ui,
        &[
            ("DOS Rows", report.dos_header.len().to_string(), Color32::from_rgb(90, 160, 255)),
            ("File Rows", report.file_header.len().to_string(), Color32::from_rgb(92, 184, 92)),
            ("Optional Rows", report.optional_header.len().to_string(), Color32::from_rgb(210, 144, 72)),
            ("Rich Rows", report.rich_headers.len().to_string(), Color32::from_rgb(198, 122, 255)),
        ],
    );
    ui.add_space(12.0);

    if ui.available_width() >= 1500.0 {
        framed_panel(ui, |ui| {
            ui.columns(3, |columns| {
                render_kv_group(&mut columns[0], "DOS Header", &report.dos_header);
                render_kv_group(&mut columns[1], "File Header", &report.file_header);
                render_kv_group(&mut columns[2], "Optional Header", &report.optional_header);
            });
        });
    } else if ui.available_width() >= 1060.0 {
        framed_panel(ui, |ui| {
            ui.columns(2, |columns| {
                render_kv_group(&mut columns[0], "DOS Header", &report.dos_header);
                render_kv_group(&mut columns[1], "File Header", &report.file_header);
            });
            ui.add_space(12.0);
            render_kv_group(ui, "Optional Header", &report.optional_header);
        });
    } else {
        framed_panel(ui, |ui| {
            render_kv_group(ui, "DOS Header", &report.dos_header);
            ui.add_space(12.0);
            render_kv_group(ui, "File Header", &report.file_header);
            ui.add_space(12.0);
            render_kv_group(ui, "Optional Header", &report.optional_header);
        });
    }

    ui.add_space(12.0);
    framed_panel(ui, |ui| {
        render_kv_group(ui, "Rich Header", &report.rich_headers);
    });
}

fn render_protection(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(ui, "Protection", "Mitigations, anti-debug indicators, and suspicious API heuristics");

    let enabled_mitigations = [
        report.protections.aslr,
        report.protections.dep_nx,
        report.protections.seh_enabled,
        report.protections.no_seh,
    ]
    .into_iter()
    .filter(|value| *value)
    .count();
    let high_findings = report
        .protection_findings
        .iter()
        .filter(|finding| finding.severity == "high")
        .count();

    let mitigations = [
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
    ];

    render_metric_strip(
        ui,
        &[
            ("Mitigations", enabled_mitigations.to_string(), Color32::from_rgb(90, 160, 255)),
            ("Findings", report.protection_findings.len().to_string(), Color32::from_rgb(92, 184, 92)),
            ("High", high_findings.to_string(), Color32::from_rgb(210, 144, 72)),
            ("TLS", report.protections.tls_callbacks.to_string(), Color32::from_rgb(198, 122, 255)),
        ],
    );
    ui.add_space(12.0);

    if ui.available_width() >= 1360.0 {
        ui.columns(2, |columns| {
            framed_panel(&mut columns[0], |ui| {
                render_kv_group(ui, "Mitigations", &mitigations);
            });

            framed_panel(&mut columns[1], |ui| {
                render_findings(ui, &report.protection_findings);
            });
        });
    } else {
        framed_panel(ui, |ui| {
            render_kv_group(ui, "Mitigations", &mitigations);
        });
        ui.add_space(12.0);
        framed_panel(ui, |ui| {
            render_findings(ui, &report.protection_findings);
        });
    }
}

fn render_xor(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "XOR Analysis",
        "Single-byte candidates, repeating multi-byte patterns, and common-key previews",
    );

    render_metric_strip(
        ui,
        &[
            ("Single-byte", report.xor_candidates.len().to_string(), Color32::from_rgb(90, 160, 255)),
            ("Common Keys", report.xor_common_key_hits.len().to_string(), Color32::from_rgb(92, 184, 92)),
            ("Patterns", report.xor_patterns.len().to_string(), Color32::from_rgb(210, 144, 72)),
            ("Strings", report.strings.len().to_string(), Color32::from_rgb(198, 122, 255)),
        ],
    );
    ui.add_space(12.0);

    if ui.available_width() >= 1360.0 {
        ui.columns(2, |columns| {
            framed_panel(&mut columns[0], |ui| {
                render_xor_candidates_panel(
                    ui,
                    "Single-byte XOR Candidates",
                    &report.xor_candidates,
                    "No high-confidence single-byte XOR candidates found.",
                );
            });

            framed_panel(&mut columns[1], |ui| {
                render_xor_candidates_panel(
                    ui,
                    "Common-Key Hits",
                    &report.xor_common_key_hits,
                    "No useful previews for common XOR keys.",
                );
            });
        });
    } else {
        framed_panel(ui, |ui| {
            render_xor_candidates_panel(
                ui,
                "Single-byte XOR Candidates",
                &report.xor_candidates,
                "No high-confidence single-byte XOR candidates found.",
            );
        });
        ui.add_space(12.0);
        framed_panel(ui, |ui| {
            render_xor_candidates_panel(
                ui,
                "Common-Key Hits",
                &report.xor_common_key_hits,
                "No useful previews for common XOR keys.",
            );
        });
    }

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
            tabular_surface(ui, "xor_patterns_table", 360.0, |ui| {
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
            });
        }
    });
}

fn render_kv_group(ui: &mut Ui, title: &str, rows: &[KeyValueRow]) {
    egui::Frame::new()
        .fill(Color32::from_rgb(11, 15, 20))
        .corner_radius(egui::CornerRadius::same(22))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(42, 52, 66)))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.label(
                RichText::new(title)
                    .strong()
                    .color(Color32::from_rgb(229, 233, 237)),
            );
            ui.add_space(8.0);
            render_kv_rows(ui, title, rows);
        });
}

fn render_kv_rows(ui: &mut Ui, id_source: impl std::hash::Hash, rows: &[KeyValueRow]) {
    egui::Grid::new(ui.id().with(id_source).with("kv_rows"))
        .num_columns(2)
        .min_col_width(if ui.available_width() >= 540.0 { 120.0 } else { 88.0 })
        .spacing([18.0, 10.0])
        .show(ui, |ui| {
            for row in rows {
                ui.label(
                    RichText::new(&row.key)
                        .monospace()
                        .color(Color32::from_rgb(137, 181, 255)),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(&row.value)
                            .monospace()
                            .color(Color32::from_rgb(202, 208, 216)),
                    )
                    .wrap(),
                );
                ui.end_row();
            }
        });
}

fn render_findings(ui: &mut Ui, findings: &[crate::analyzer::ProtectionFinding]) {
    ui.label(
        RichText::new("Findings")
            .strong()
            .color(Color32::from_rgb(229, 233, 237)),
    );
    ui.add_space(8.0);
    if findings.is_empty() {
        ui.label(
            RichText::new("No suspicious findings were emitted for this file.")
                .color(Color32::from_rgb(140, 149, 160)),
        );
        return;
    }

    vertical_surface_scroll(ui, "protection_findings_scroll", 320.0, |ui| {
        for finding in findings {
            let accent = match finding.severity {
                "high" => Color32::from_rgb(235, 104, 104),
                "medium" => Color32::from_rgb(233, 184, 97),
                _ => Color32::from_rgb(150, 180, 150),
            };

            egui::Frame::new()
                .fill(Color32::from_rgb(10, 14, 19))
                .corner_radius(egui::CornerRadius::same(16))
                .stroke(egui::Stroke::new(1.0, accent.gamma_multiply(0.55)))
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(finding.severity.to_uppercase())
                                .small()
                                .strong()
                                .color(accent),
                        );
                        ui.label(
                            RichText::new(&finding.title)
                                .strong()
                                .color(Color32::from_rgb(230, 234, 239)),
                        );
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(&finding.detail)
                            .color(Color32::from_rgb(176, 184, 194)),
                    );
                });
            ui.add_space(8.0);
        }
    });
}

fn xor_readability_color(readability: f32) -> Color32 {
    if readability >= 70.0 {
        Color32::from_rgb(124, 208, 156)
    } else if readability >= 45.0 {
        Color32::from_rgb(233, 184, 97)
    } else {
        Color32::from_rgb(145, 154, 166)
    }
}

fn render_xor_candidates_panel(
    ui: &mut Ui,
    title: &str,
    candidates: &[crate::analyzer::XorCandidate],
    empty_message: &str,
) {
    ui.label(
        RichText::new(title)
            .strong()
            .color(Color32::from_rgb(229, 233, 237)),
    );
    ui.add_space(8.0);
    if candidates.is_empty() {
        ui.label(RichText::new(empty_message).color(Color32::from_rgb(140, 149, 160)));
    } else {
        vertical_surface_scroll(ui, title, 320.0, |ui| {
            for candidate in candidates {
                let accent = xor_readability_color(candidate.readability);

                egui::Frame::new()
                    .fill(Color32::from_rgb(10, 14, 19))
                    .corner_radius(egui::CornerRadius::same(16))
                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(29, 38, 49)))
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(&candidate.source)
                                    .small()
                                    .color(Color32::from_rgb(145, 154, 166)),
                            );
                            ui.label(
                                RichText::new(format!("key={}", candidate.key))
                                    .monospace()
                                    .color(Color32::from_rgb(210, 216, 224)),
                            );
                            ui.label(
                                RichText::new(format!("{:.1}%", candidate.readability))
                                    .monospace()
                                    .color(accent),
                            );
                        });
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(&candidate.preview)
                                .monospace()
                                .color(Color32::from_rgb(186, 194, 204)),
                        );
                    });
                ui.add_space(8.0);
            }
        });
    }
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

fn framed_panel(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(9, 13, 18))
        .corner_radius(egui::CornerRadius::same(26))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(54, 66, 82)))
        .inner_margin(egui::Margin::same(16))
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
        Color32::from_rgb(10, 14, 19)
    };
    let stroke = if selected {
        Color32::from_rgb(255, 197, 175)
    } else {
        Color32::from_rgb(31, 39, 51)
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
        .corner_radius(egui::CornerRadius::same(18))
        .min_size(egui::vec2(ui.available_width(), 38.0)),
    )
}

fn pill(ui: &mut Ui, text: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(13, 17, 23))
        .corner_radius(egui::CornerRadius::same(30))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(31, 39, 51)))
        .inner_margin(egui::Margin::symmetric(14, 8))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(Color32::from_rgb(189, 196, 206)));
        });
}

fn sidebar_pill(ui: &mut Ui, text: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(12, 16, 22))
        .corner_radius(egui::CornerRadius::same(14))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(38, 47, 60)))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .small()
                    .color(Color32::from_rgb(196, 202, 212)),
            );
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
    .min_size(egui::vec2(38.0, 30.0))
    .fill(Color32::from_rgb(12, 16, 22))
    .corner_radius(egui::CornerRadius::same(14))
    .stroke(egui::Stroke::new(1.0, accent));

    let response = ui.add(button).on_hover_text(tooltip);
    if response.clicked() {
        on_click();
    }
}
