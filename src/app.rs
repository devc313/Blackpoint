use crate::analyzer::{analyze_file, bool_badge, BinaryReport, KeyValueRow};
use crate::report_export::{default_snapshot_path, write_snapshot};
use eframe::egui::{self, Color32, RichText, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

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

#[derive(Clone, Copy)]
enum AppIcon {
    Terminal,
    Info,
    Package,
    Code,
    Cube,
    Grid,
    Download,
    Upload,
    Keyboard,
    Shield,
    Chart,
    Archive,
    FileOpen,
    UploadFile,
    DragPan,
    Bolt,
    Analytics,
    DataObject,
    Memory,
    Password,
    CheckCircle,
    User,
    Minimize,
    Maximize,
    Close,
}

#[derive(Clone, Copy)]
enum CardFooter<'a> {
    Progress(f32),
    Action(&'a str),
    Badges(&'a [&'a str]),
    Histogram,
}

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

struct HexSelection {
    offset: usize,
    status: Option<String>,
}

enum LandingAction {
    None,
    Open,
    Retry,
}

#[derive(Clone, Copy)]
enum UiMessageTone {
    Info,
    Success,
    Warning,
    Error,
}

struct UiMessage {
    text: String,
    tone: UiMessageTone,
    expires_at: Instant,
}

const APP_VERSION: &str = "BLACKPOINT V2.4.0-STABLE";
const CANVAS_MAX_WIDTH: f32 = 1480.0;
const MAX_VISIBLE_STRING_ROWS: usize = 100;

#[derive(Clone, Copy)]
struct UiTheme {
    app_bg: Color32,
    shell_bg: Color32,
    panel: Color32,
    panel_alt: Color32,
    inset: Color32,
    border: Color32,
    border_soft: Color32,
    dashed_border: Color32,
    text: Color32,
    title: Color32,
    muted: Color32,
    status: Color32,
    primary: Color32,
    primary_soft: Color32,
    primary_border: Color32,
    primary_text: Color32,
    info: Color32,
    success: Color32,
    warning: Color32,
    danger: Color32,
}

fn theme() -> UiTheme {
    UiTheme {
        app_bg: Color32::from_rgb(24, 20, 18),
        shell_bg: Color32::from_rgb(30, 24, 21),
        panel: Color32::from_rgb(38, 30, 25),
        panel_alt: Color32::from_rgb(43, 34, 28),
        inset: Color32::from_rgb(31, 25, 21),
        border: Color32::from_rgb(78, 61, 49),
        border_soft: Color32::from_rgb(61, 49, 41),
        dashed_border: Color32::from_rgb(88, 68, 53),
        text: Color32::from_rgb(230, 225, 220),
        title: Color32::from_rgb(250, 246, 242),
        muted: Color32::from_rgb(151, 143, 135),
        status: Color32::from_rgb(118, 131, 164),
        primary: Color32::from_rgb(231, 126, 35),
        primary_soft: Color32::from_rgb(74, 46, 23),
        primary_border: Color32::from_rgb(140, 82, 32),
        primary_text: Color32::from_rgb(24, 18, 14),
        info: Color32::from_rgb(96, 150, 235),
        success: Color32::from_rgb(82, 200, 126),
        warning: Color32::from_rgb(224, 154, 76),
        danger: Color32::from_rgb(214, 92, 92),
    }
}

pub struct BlackpointApp {
    active_tab: ActiveTab,
    loaded_file: Option<PathBuf>,
    retry_path: Option<PathBuf>,
    report: Option<BinaryReport>,
    last_error: Option<String>,
    string_filter: String,
    import_filter: String,
    hex_offset_input: String,
    hex_rva_input: String,
    hex_status: Option<String>,
    hex_selected_offset: usize,
    strings_case_sensitive: bool,
    show_ascii_strings: bool,
    show_utf16_strings: bool,
    drag_hovering: bool,
    analysis_receiver: Option<Receiver<Result<BinaryReport, String>>>,
    analyzing_since: Option<Instant>,
    analyzing_path: Option<PathBuf>,
    recent_files: Vec<PathBuf>,
    ui_message: Option<UiMessage>,
    history_path: PathBuf,
}

impl BlackpointApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_theme(&cc.egui_ctx);

        let history_path = dirs().join("history.json");
        let recent_files = load_history(&history_path);

        Self {
            active_tab: ActiveTab::GeneralInfo,
            loaded_file: None,
            retry_path: None,
            report: None,
            last_error: None,
            string_filter: String::new(),
            import_filter: String::new(),
            hex_offset_input: "0x0".to_string(),
            hex_rva_input: "0x0".to_string(),
            hex_status: None,
            hex_selected_offset: 0,
            strings_case_sensitive: false,
            show_ascii_strings: true,
            show_utf16_strings: true,
            drag_hovering: false,
            analysis_receiver: None,
            analyzing_since: None,
            analyzing_path: None,
            recent_files,
            ui_message: None,
            history_path,
        }
    }

    fn pick_file(&mut self) {
        let file = rfd::FileDialog::new()
            .set_title("Open binary, archive, or raw blob")
            .pick_file();

        if let Some(path) = file {
            self.load_path(path);
        }
    }

    fn set_ui_message(&mut self, tone: UiMessageTone, text: impl Into<String>) {
        self.ui_message = Some(UiMessage {
            text: text.into(),
            tone,
            expires_at: Instant::now() + Duration::from_secs(6),
        });
    }

    fn prune_ui_message(&mut self) {
        if self
            .ui_message
            .as_ref()
            .is_some_and(|message| Instant::now() >= message.expires_at)
        {
            self.ui_message = None;
        }
    }

    fn copy_target_path(&mut self, ctx: &egui::Context, path: &Path) {
        ctx.copy_text(path.display().to_string());
        self.set_ui_message(
            UiMessageTone::Success,
            "Copied active target path to clipboard.",
        );
    }

    fn copy_hashes(&mut self, ctx: &egui::Context) {
        let Some(report) = self.report.as_ref() else {
            self.set_ui_message(UiMessageTone::Error, "No analyzed target is available yet.");
            return;
        };

        ctx.copy_text(format!(
            "MD5: {}\nSHA-1: {}\nSHA-256: {}",
            report.md5, report.sha1, report.sha256
        ));
        self.set_ui_message(UiMessageTone::Success, "Copied report hashes to clipboard.");
    }

    fn reveal_target_in_explorer(&mut self, path: &Path) {
        let result = if cfg!(target_os = "windows") {
            Command::new("explorer")
                .arg(format!("/select,{}", path.display()))
                .spawn()
        } else if cfg!(target_os = "macos") {
            Command::new("open").arg("-R").arg(path).spawn()
        } else {
            Command::new("xdg-open")
                .arg(path.parent().unwrap_or(path))
                .spawn()
        };

        match result {
            Ok(_) => {
                self.set_ui_message(
                    UiMessageTone::Info,
                    "Revealed active target in file manager.",
                );
            }
            Err(err) => {
                self.set_ui_message(
                    UiMessageTone::Error,
                    format!("Failed to reveal target in file manager: {err}"),
                );
            }
        }
    }

    fn export_snapshot(&mut self) {
        let Some(report) = self.report.as_ref() else {
            self.set_ui_message(UiMessageTone::Error, "No analyzed target is available yet.");
            return;
        };

        let suggested = default_snapshot_path(report);
        let default_name = suggested
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("analysis.blackpoint.json")
            .to_string();

        let mut dialog = rfd::FileDialog::new().set_title("Export analysis snapshot");
        if let Some(parent) = suggested.parent() {
            dialog = dialog.set_directory(parent);
        }
        dialog = dialog.set_file_name(&default_name);

        let Some(output_path) = dialog.save_file() else {
            return;
        };

        match write_snapshot(report, &output_path) {
            Ok(()) => {
                let exported_name = output_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or(default_name.as_str());
                self.set_ui_message(
                    UiMessageTone::Success,
                    format!("Exported snapshot to {exported_name}."),
                );
            }
            Err(err) => {
                self.set_ui_message(
                    UiMessageTone::Error,
                    format!("Snapshot export failed: {err}"),
                );
            }
        }
    }

    fn load_path(&mut self, path: PathBuf) {
        self.retry_path = Some(path.clone());
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                let size = metadata.len();
                const WARN_SIZE: u64 = 500 * 1024 * 1024;
                const BLOCK_SIZE: u64 = 2 * 1024 * 1024 * 1024;
                if size >= BLOCK_SIZE {
                    self.analysis_receiver = None;
                    self.analyzing_since = None;
                    self.analyzing_path = None;
                    self.drag_hovering = false;
                    self.last_error = Some(format!(
                        "{} is {:.1} MB which exceeds the 2 GB limit. Analysis is blocked for very large files.",
                        path.display(),
                        size as f64 / (1024.0 * 1024.0)
                    ));
                    return;
                }
                if size >= WARN_SIZE {
                    self.set_ui_message(
                        UiMessageTone::Warning,
                        format!(
                            "Large file ({:.1} MB). Analysis may be slow or use significant memory.",
                            size as f64 / (1024.0 * 1024.0)
                        ),
                    );
                }
            }
            Ok(_) => {
                self.analysis_receiver = None;
                self.analyzing_since = None;
                self.analyzing_path = None;
                self.drag_hovering = false;
                self.last_error = Some(format!(
                    "{} is not a regular file and cannot be analyzed.",
                    path.display()
                ));
                return;
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    self.remove_recent_file(&path);
                }
                self.analysis_receiver = None;
                self.analyzing_since = None;
                self.analyzing_path = None;
                self.drag_hovering = false;
                self.last_error = Some(format!("failed to open {}: {err}", path.display()));
                return;
            }
        }

        let (tx, rx) = mpsc::channel();
        let analyze_path = path.clone();

        self.active_tab = ActiveTab::GeneralInfo;
        self.loaded_file = Some(path.clone());
        self.report = None;
        self.analysis_receiver = Some(rx);
        self.analyzing_since = Some(Instant::now());
        self.analyzing_path = Some(path.clone());
        self.last_error = None;
        self.ui_message = None;
        self.reset_transient_view_state();
        self.drag_hovering = false;
        self.push_recent_file(path.clone());

        std::thread::spawn(move || {
            let result = analyze_file(&analyze_path).map_err(|err| err.to_string());
            let _ = tx.send(result);
        });
    }

    fn reset_transient_view_state(&mut self) {
        self.string_filter.clear();
        self.import_filter.clear();
        self.strings_case_sensitive = false;
        self.show_ascii_strings = true;
        self.show_utf16_strings = true;
        self.hex_status = None;
        self.hex_selected_offset = 0;
        self.hex_offset_input = "0x0".to_string();
        self.hex_rva_input = "0x0".to_string();
    }

    fn prime_report_view_state(&mut self, report: &BinaryReport) {
        let initial = resolve_initial_hex_selection(report);
        self.hex_selected_offset = initial.offset;
        self.hex_offset_input = format!("0x{:X}", initial.offset);
        self.hex_rva_input = if initial.status.is_some() {
            format!("0x{:X}", report.entry_point)
        } else {
            rva_from_raw_offset(report, initial.offset)
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_else(|| format!("0x{:X}", report.entry_point))
        };
        self.hex_status = initial.status;
    }

    fn poll_analysis(&mut self) {
        let Some(receiver) = &self.analysis_receiver else {
            return;
        };

        match receiver.try_recv() {
            Ok(Ok(report)) => {
                self.prime_report_view_state(&report);
                self.retry_path = Some(report.path.clone());
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

    fn push_recent_file(&mut self, path: PathBuf) {
        self.recent_files.retain(|existing| existing != &path);
        self.recent_files.insert(0, path);
        self.recent_files.truncate(50);
        save_history(&self.history_path, &self.recent_files);
    }

    fn remove_recent_file(&mut self, path: &std::path::Path) {
        self.recent_files.retain(|existing| existing != path);
        save_history(&self.history_path, &self.recent_files);
    }

    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        let mut open_file = false;
        let mut export_snap = false;
        let mut copy_path = false;
        let mut copy_h = false;

        ctx.input(|input| {
            if input.modifiers.ctrl && input.key_pressed(egui::Key::O) {
                open_file = true;
            }
            if input.modifiers.ctrl && input.key_pressed(egui::Key::E) {
                export_snap = true;
            }
            if input.modifiers.ctrl && input.key_pressed(egui::Key::C) && !input.modifiers.shift {
                copy_path = true;
            }
            if input.modifiers.ctrl && input.key_pressed(egui::Key::C) && input.modifiers.shift {
                copy_h = true;
            }
            for (key, tab) in [
                (egui::Key::Num1, ActiveTab::GeneralInfo),
                (egui::Key::Num2, ActiveTab::Resources),
                (egui::Key::Num3, ActiveTab::Hex),
                (egui::Key::Num4, ActiveTab::Sections),
                (egui::Key::Num5, ActiveTab::Imports),
                (egui::Key::Num6, ActiveTab::Exports),
                (egui::Key::Num7, ActiveTab::Disassembly),
                (egui::Key::Num8, ActiveTab::Strings),
                (egui::Key::Num9, ActiveTab::Protection),
            ] {
                if input.key_pressed(key) && !input.modifiers.ctrl && !input.modifiers.alt {
                    self.active_tab = tab;
                }
            }
        });

        if open_file {
            self.pick_file();
        }
        if export_snap {
            self.export_snapshot();
        }
        if copy_path {
            if let Some(path) = self.loaded_file.clone() {
                self.copy_target_path(ctx, &path);
            }
        }
        if copy_h {
            self.copy_hashes(ctx);
        }
    }

    fn render_title_bar(&mut self, ctx: &egui::Context) {
        let t = theme();
        egui::TopBottomPanel::top("title_bar")
            .exact_height(60.0)
            .frame(
                egui::Frame::new()
                    .fill(t.shell_bg)
                    .stroke(egui::Stroke::new(1.0, t.border_soft))
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ctx, |ui| {
                let rect = ui.max_rect();
                let drag_id = ui.id().with("title_drag_zone");
                let response = ui.interact(rect, drag_id, egui::Sense::click_and_drag());
                if response.is_pointer_button_down_on() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }

                ui.horizontal(|ui| {
                    icon_tile(ui, AppIcon::Terminal, t.primary, t.primary_soft, 34.0);
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Blackpoint")
                                .size(17.0)
                                .strong()
                                .color(t.title),
                        );
                        if ui.available_width() > 320.0 {
                            ui.label(
                                RichText::new("Static analysis workbench")
                                    .size(10.5)
                                    .color(t.muted),
                            );
                        }
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::Frame::new()
                            .fill(t.primary_soft)
                            .corner_radius(egui::CornerRadius::same(16))
                            .stroke(egui::Stroke::new(1.0, t.primary_border))
                            .inner_margin(egui::Margin::same(4))
                            .show(ui, |ui| {
                                let response = ui.allocate_exact_size(
                                    egui::vec2(28.0, 28.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(
                                    response.0.center(),
                                    13.0,
                                    t.primary.gamma_multiply(0.9),
                                );
                                paint_icon(
                                    ui.painter(),
                                    response.0.shrink2(egui::vec2(6.0, 6.0)),
                                    AppIcon::User,
                                    t.primary_text,
                                    1.6,
                                );
                            });
                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(12.0);
                        egui::Frame::new()
                            .fill(t.panel_alt)
                            .corner_radius(egui::CornerRadius::same(14))
                            .stroke(egui::Stroke::new(1.0, t.border_soft))
                            .inner_margin(egui::Margin::symmetric(6, 6))
                            .show(ui, |ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        titlebar_button(
                                            ui,
                                            AppIcon::Close,
                                            t.danger,
                                            "Close",
                                            true,
                                            || ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                                        );
                                        titlebar_button(
                                            ui,
                                            AppIcon::Maximize,
                                            t.muted,
                                            "Maximize",
                                            false,
                                            || {
                                                let maximized = ctx.input(|i| {
                                                    i.viewport().maximized.unwrap_or(false)
                                                });
                                                ctx.send_viewport_cmd(
                                                    egui::ViewportCommand::Maximized(!maximized),
                                                );
                                            },
                                        );
                                        titlebar_button(
                                            ui,
                                            AppIcon::Minimize,
                                            t.muted,
                                            "Minimize",
                                            false,
                                            || {
                                                ctx.send_viewport_cmd(
                                                    egui::ViewportCommand::Minimized(true),
                                                )
                                            },
                                        );
                                    },
                                );
                            });
                    });
                });
            });
    }

    fn render_sidebar(&mut self, ctx: &egui::Context) {
        let t = theme();
        egui::SidePanel::left("nav")
            .resizable(true)
            .default_width(252.0)
            .min_width(208.0)
            .frame(
                egui::Frame::new()
                    .fill(t.shell_bg)
                    .stroke(egui::Stroke::new(1.0, t.border_soft))
                    .inner_margin(egui::Margin {
                        left: 18,
                        right: 16,
                        top: 20,
                        bottom: 16,
                    }),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let compact_sidebar = ui.available_width() < 222.0;

                        sidebar_section_label(ui, "Analysis Session");
                        status_chip(ui, "Workspace: Active", t.primary);
                        ui.add_space(12.0);

                        if primary_button(ui, "Open Binary / Archive", Some(AppIcon::FileOpen))
                            .clicked()
                        {
                            self.pick_file();
                        }

                        if let Some(path) = self.loaded_file.clone() {
                            let has_report = self.report.is_some();
                            let mut copy_path_clicked = false;
                            let mut reveal_clicked = false;
                            let mut copy_hashes_clicked = false;
                            let mut export_snapshot_clicked = false;
                            ui.add_space(14.0);
                            egui::Frame::new()
                                .fill(t.panel)
                                .corner_radius(egui::CornerRadius::same(18))
                                .stroke(egui::Stroke::new(1.0, t.border_soft))
                                .inner_margin(egui::Margin::same(14))
                                .show(ui, |ui| {
                                    ui.label(RichText::new("Active Target").small().color(t.muted));
                                    ui.add_space(6.0);
                                    let file_name = path
                                        .file_name()
                                        .and_then(|name| name.to_str())
                                        .unwrap_or("Loaded target");
                                    ui.label(
                                        RichText::new(file_name).strong().size(19.0).color(t.title),
                                    );

                                    if !compact_sidebar {
                                        ui.add_space(8.0);
                                        egui::Frame::new()
                                            .fill(t.inset)
                                            .corner_radius(egui::CornerRadius::same(14))
                                            .stroke(egui::Stroke::new(1.0, t.border_soft))
                                            .inner_margin(egui::Margin::symmetric(12, 10))
                                            .show(ui, |ui| {
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(path.display().to_string())
                                                            .small()
                                                            .monospace()
                                                            .color(t.muted),
                                                    )
                                                    .wrap(),
                                                );
                                            });
                                    }

                                    ui.add_space(10.0);
                                    ui.horizontal_wrapped(|ui| {
                                        if let Some(report) = &self.report {
                                            sidebar_pill(ui, &report.format_name);
                                            sidebar_pill(
                                                ui,
                                                if report.is_64bit { "64-bit" } else { "32-bit" },
                                            );
                                            sidebar_pill(ui, report.subsystem.as_str());
                                        } else {
                                            sidebar_pill(ui, "Pending");
                                        }
                                    });

                                    if let Some(report) = &self.report {
                                        ui.add_space(6.0);
                                        let size_text = if report.file_size >= 1024 * 1024 {
                                            format!(
                                                "{:.1} MB",
                                                report.file_size as f64 / (1024.0 * 1024.0)
                                            )
                                        } else if report.file_size >= 1024 {
                                            format!("{:.1} KB", report.file_size as f64 / 1024.0)
                                        } else {
                                            format!("{} B", report.file_size)
                                        };
                                        ui.label(
                                            RichText::new(format!("Size: {size_text}"))
                                                .small()
                                                .color(t.muted),
                                        );
                                    }

                                    ui.add_space(10.0);
                                    ui.horizontal_wrapped(|ui| {
                                        if ghost_button(ui, "Copy Path").clicked() {
                                            copy_path_clicked = true;
                                        }
                                        if ghost_button(ui, "Reveal in Explorer").clicked() {
                                            reveal_clicked = true;
                                        }
                                        if has_report && ghost_button(ui, "Copy Hashes").clicked() {
                                            copy_hashes_clicked = true;
                                        }
                                        if has_report
                                            && ghost_button(ui, "Export Snapshot").clicked()
                                        {
                                            export_snapshot_clicked = true;
                                        }
                                    });
                                });

                            if copy_path_clicked {
                                self.copy_target_path(ctx, &path);
                            }
                            if reveal_clicked {
                                self.reveal_target_in_explorer(&path);
                            }
                            if copy_hashes_clicked {
                                self.copy_hashes(ctx);
                            }
                            if export_snapshot_clicked {
                                self.export_snapshot();
                            }
                        }

                        if let Some(error) = &self.last_error {
                            ui.add_space(14.0);
                            egui::Frame::new()
                                .fill(Color32::from_rgb(52, 24, 22))
                                .corner_radius(egui::CornerRadius::same(16))
                                .stroke(egui::Stroke::new(1.0, t.danger))
                                .inner_margin(egui::Margin::same(12))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(error)
                                            .small()
                                            .color(Color32::from_rgb(255, 187, 187)),
                                    );
                                });
                        }

                        ui.add_space(16.0);
                        sidebar_section_label(ui, "Navigation");
                        for tab in [
                            ActiveTab::GeneralInfo,
                            ActiveTab::Resources,
                            ActiveTab::Headers,
                            ActiveTab::Hex,
                            ActiveTab::Sections,
                            ActiveTab::Imports,
                            ActiveTab::Exports,
                            ActiveTab::Strings,
                            ActiveTab::Protection,
                            ActiveTab::Xor,
                            ActiveTab::Disassembly,
                            ActiveTab::Archive,
                        ] {
                            let (icon, label) = tab_meta(tab);
                            if nav_button(ui, icon, label, self.active_tab == tab).clicked() {
                                self.active_tab = tab;
                            }
                        }

                        if !self.recent_files.is_empty() {
                            ui.add_space(18.0);
                            sidebar_section_label(ui, "Recent");
                            let mut reopened_path = None;
                            for path in &self.recent_files {
                                let file_name = path
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("Recent target");
                                if ghost_button(ui, file_name)
                                    .on_hover_text(path.display().to_string())
                                    .clicked()
                                {
                                    reopened_path = Some(path.clone());
                                }
                            }
                            if let Some(path) = reopened_path {
                                self.load_path(path);
                            }
                        }
                    });
            });
    }

    fn render_main(&mut self, ctx: &egui::Context) {
        let t = theme();
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(t.app_bg)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                if self.report.is_none() {
                    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                        ui.set_width(ui.available_width().min(CANVAS_MAX_WIDTH));
                        let action = if let Some(error) = self.last_error.as_deref() {
                            render_error_state(ui, error, self.retry_path.is_some())
                        } else {
                            if render_empty_state(ui) {
                                LandingAction::Open
                            } else {
                                LandingAction::None
                            }
                        };
                        match action {
                            LandingAction::None => {}
                            LandingAction::Open => self.pick_file(),
                            LandingAction::Retry => {
                                if let Some(path) =
                                    self.retry_path.clone().or_else(|| self.loaded_file.clone())
                                {
                                    self.load_path(path);
                                }
                            }
                        }
                    });
                    render_help_fab(ui.ctx());
                    return;
                }

                let Some(report) = self.report.as_ref() else {
                    render_help_fab(ui.ctx());
                    return;
                };
                let active_tab = self.active_tab;

                egui::ScrollArea::vertical()
                    .id_salt("main_canvas_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let available = ui.available_width();
                        let canvas_width = available.min(CANVAS_MAX_WIDTH);
                        let side_pad = ((available - canvas_width) * 0.5).max(0.0);
                        ui.allocate_ui_with_layout(
                            egui::vec2(available, ui.available_height()),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                if side_pad > 0.0 {
                                    ui.horizontal(|ui| {
                                        ui.add_space(side_pad);
                                        render_report_shell(
                                            ui,
                                            report,
                                            active_tab,
                                            canvas_width,
                                            ActiveReportState {
                                                hex_offset_input: &mut self.hex_offset_input,
                                                hex_rva_input: &mut self.hex_rva_input,
                                                hex_status: &mut self.hex_status,
                                                hex_selected_offset: &mut self.hex_selected_offset,
                                                string_filter: &mut self.string_filter,
                                                import_filter: &mut self.import_filter,
                                                strings_case_sensitive: &mut self
                                                    .strings_case_sensitive,
                                                show_ascii_strings: &mut self.show_ascii_strings,
                                                show_utf16_strings: &mut self.show_utf16_strings,
                                            },
                                        );
                                    });
                                } else {
                                    render_report_shell(
                                        ui,
                                        report,
                                        active_tab,
                                        canvas_width,
                                        ActiveReportState {
                                            hex_offset_input: &mut self.hex_offset_input,
                                            hex_rva_input: &mut self.hex_rva_input,
                                            hex_status: &mut self.hex_status,
                                            hex_selected_offset: &mut self.hex_selected_offset,
                                            string_filter: &mut self.string_filter,
                                            import_filter: &mut self.import_filter,
                                            strings_case_sensitive: &mut self
                                                .strings_case_sensitive,
                                            show_ascii_strings: &mut self.show_ascii_strings,
                                            show_utf16_strings: &mut self.show_utf16_strings,
                                        },
                                    );
                                }
                            },
                        );
                        render_help_fab(ui.ctx());
                    });
            });
    }

    fn render_status_bar(&self, ctx: &egui::Context) {
        let t = theme();
        let is_analyzing = self.analysis_receiver.is_some();
        let (engine_status, status_icon) = if is_analyzing {
            ("Analyzing", AppIcon::Bolt)
        } else if self.last_error.is_some() {
            ("Recovery Ready", AppIcon::Info)
        } else {
            ("Engine Ready", AppIcon::CheckCircle)
        };
        let target_status = if is_analyzing {
            "Target Staged"
        } else if self.report.is_some() {
            "1 Target Loaded"
        } else if self.retry_path.is_some() || self.loaded_file.is_some() {
            "Target Selected"
        } else {
            "No Target Loaded"
        };
        let active_message = self.ui_message.as_ref().map(|message| {
            let color = match message.tone {
                UiMessageTone::Info => t.status,
                UiMessageTone::Success => t.success,
                UiMessageTone::Warning => t.warning,
                UiMessageTone::Error => t.danger,
            };
            (message.text.as_str(), color)
        });

        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(30.0)
            .frame(
                egui::Frame::new()
                    .fill(t.shell_bg)
                    .stroke(egui::Stroke::new(1.0, t.border_soft))
                    .inner_margin(egui::Margin::symmetric(14, 6)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let response =
                        ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                    paint_icon(ui.painter(), response.0, status_icon, t.primary, 1.5);
                    ui.label(RichText::new(engine_status).size(10.5).color(t.text));
                    ui.separator();
                    ui.label(RichText::new(target_status).size(10.0).color(t.status));
                    if let Some((message, color)) = active_message {
                        ui.separator();
                        ui.label(RichText::new(message).size(10.0).color(color));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(APP_VERSION)
                                .size(10.0)
                                .strong()
                                .color(t.status),
                        );
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
            "Drop target to analyze",
            egui::FontId::proportional(24.0),
            Color32::from_rgb(245, 245, 246),
        );
        painter.text(
            card.center_top() + egui::vec2(0.0, 86.0),
            egui::Align2::CENTER_TOP,
            "PE  ELF  MACH  ZIP  TGZ",
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

        let layer_id =
            egui::LayerId::new(egui::Order::Foreground, egui::Id::new("analysis_overlay"));
        let painter = ctx.layer_painter(layer_id);
        let rect = ctx.content_rect();
        painter.rect_filled(rect, 0.0, Color32::from_rgba_unmultiplied(0, 0, 0, 176));

        egui::Area::new("analysis_overlay_card".into())
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
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
        self.prune_ui_message();
        self.poll_analysis();
        if self.analysis_receiver.is_some() || self.ui_message.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        self.handle_drag_and_drop(ctx);
        self.handle_keyboard_shortcuts(ctx);
        self.render_title_bar(ctx);
        self.render_sidebar(ctx);
        self.render_main(ctx);
        self.render_status_bar(ctx);
        self.render_drag_overlay(ctx);
        self.render_analysis_overlay(ctx);

        let nav_id = egui::Id::new("hex_nav_request");
        if let Some(offset) = ctx.memory_mut(|m| m.data.remove_temp::<u32>(nav_id)) {
            self.active_tab = ActiveTab::Hex;
            self.hex_selected_offset = offset as usize;
            self.hex_offset_input = format!("0x{:X}", offset);
        }
    }
}

fn configure_theme(ctx: &egui::Context) {
    let t = theme();
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = t.app_bg;
    style.visuals.window_fill = t.shell_bg;
    style.visuals.extreme_bg_color = t.app_bg;
    style.visuals.faint_bg_color = t.panel;
    style.visuals.code_bg_color = t.inset;
    style.visuals.selection.bg_fill = t.primary;
    style.visuals.selection.stroke = egui::Stroke::new(1.0, t.primary_border);
    style.visuals.widgets.noninteractive.bg_fill = t.panel;
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, t.border_soft);
    style.visuals.widgets.inactive.bg_fill = t.panel_alt;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, t.border_soft);
    style.visuals.widgets.hovered.bg_fill = t.panel;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, t.primary_border);
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, t.title);
    style.visuals.widgets.active.bg_fill = t.primary_soft;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, t.primary_border);
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, t.primary_text);
    style.visuals.widgets.open.bg_fill = t.panel;
    style.visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0, t.border);
    style.visuals.window_stroke = egui::Stroke::new(1.0, t.border);
    style.visuals.window_corner_radius = egui::CornerRadius::same(26);
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(16.0, 10.0);
    style.spacing.window_margin = egui::Margin::same(16);
    ctx.set_style(style);
}

fn render_report_shell(
    ui: &mut Ui,
    report: &BinaryReport,
    active_tab: ActiveTab,
    canvas_width: f32,
    state: ActiveReportState<'_>,
) {
    let t = theme();
    ui.vertical(|ui| {
        ui.set_width(canvas_width);
        egui::Frame::new()
            .fill(t.shell_bg)
            .corner_radius(egui::CornerRadius::same(28))
            .stroke(egui::Stroke::new(1.0, t.border))
            .inner_margin(egui::Margin::same(20))
            .show(ui, |ui| {
                render_active_report(ui, active_tab, report, state);
            });
    });
}

fn render_active_report(
    ui: &mut Ui,
    active_tab: ActiveTab,
    report: &BinaryReport,
    state: ActiveReportState<'_>,
) {
    match active_tab {
        ActiveTab::GeneralInfo => render_overview(ui, report),
        ActiveTab::Resources => render_resources(ui, report),
        ActiveTab::Hex => render_hex_viewer(
            ui,
            report,
            state.hex_offset_input,
            state.hex_rva_input,
            state.hex_status,
            state.hex_selected_offset,
        ),
        ActiveTab::Sections => render_sections(ui, report),
        ActiveTab::Imports => render_imports(ui, report, state.import_filter),
        ActiveTab::Exports => render_exports(ui, report),
        ActiveTab::Disassembly => render_disassembly(ui, report),
        ActiveTab::Strings => render_strings(
            ui,
            report,
            state.string_filter,
            state.strings_case_sensitive,
            state.show_ascii_strings,
            state.show_utf16_strings,
        ),
        ActiveTab::Protection => render_protection(ui, report),
        ActiveTab::Xor => render_xor(ui, report),
        ActiveTab::Archive => render_archive(ui, report),
        ActiveTab::Headers => render_headers(ui, report),
    }
}

fn render_empty_state(ui: &mut Ui) -> bool {
    let t = theme();
    let width = ui.available_width();
    let compact = width < 920.0;
    let mut open_requested = false;
    let cards = [
        (
            AppIcon::Analytics,
            "Surface Analysis",
            "Initial triage and structure detection",
            t.primary,
            CardFooter::Progress(0.34),
        ),
        (
            AppIcon::DataObject,
            "Multi-Format",
            "Cross-platform parser engine",
            t.info,
            CardFooter::Action("Configure Engine"),
        ),
        (
            AppIcon::Memory,
            "Disassembly",
            "x86/x64 Capstone backend",
            t.success,
            CardFooter::Badges(&["x86", "x64"]),
        ),
        (
            AppIcon::Password,
            "Entropy Map",
            "Packed/Encrypted region visualizer",
            t.warning,
            CardFooter::Histogram,
        ),
    ];
    let available_height = ui.available_height();
    let cards_block_height = if width >= 1260.0 {
        180.0
    } else if width >= 820.0 {
        360.0
    } else {
        720.0
    };
    let hero_height = if compact {
        (available_height - cards_block_height - 18.0).clamp(280.0, 360.0)
    } else {
        (available_height - cards_block_height - 16.0).clamp(300.0, 390.0)
    };

    let hero_response = ui.allocate_ui_with_layout(
        egui::vec2(width, hero_height),
        egui::Layout::top_down(egui::Align::Center),
        |ui| {
            egui::Frame::new()
                .fill(t.panel)
                .stroke(egui::Stroke::new(1.0, t.border_soft))
                .corner_radius(egui::CornerRadius::same(28))
                .inner_margin(egui::Margin::same(if compact { 22 } else { 26 }))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.set_height(hero_height - if compact { 22.0 } else { 26.0 });
                    ui.vertical_centered(|ui| {
                        ui.add_space(if compact { 2.0 } else { 6.0 });
                        let glow_rect = ui.max_rect().shrink2(egui::vec2(200.0, 44.0));
                        ui.painter().circle_filled(
                            glow_rect.center_top() + egui::vec2(0.0, if compact { 76.0 } else { 88.0 }),
                            if compact { 74.0 } else { 98.0 },
                            t.primary.gamma_multiply(0.045),
                        );
                        icon_tile(ui, AppIcon::UploadFile, t.primary, t.panel_alt, if compact { 58.0 } else { 64.0 });
                        ui.add_space(if compact { 10.0 } else { 12.0 });
                        ui.label(
                            RichText::new("Static analysis for real-world targets")
                                .size(if compact { 19.0 } else { 22.0 })
                                .strong()
                                .color(t.title),
                        );
                        ui.add_space(4.0);
                        ui.set_max_width(if compact { 480.0 } else { 560.0 });
                        ui.label(
                            RichText::new("Drop a binary, archive, or raw blob to start analysis.\nSupports PE, ELF, Mach-O, ZIP/APK/JAR, tgz/npm, ISO images, and generic byte buffers.")
                                .size(if compact { 13.0 } else { 13.8 })
                                .color(t.status),
                        );
                        ui.add_space(if compact { 12.0 } else { 14.0 });
                        ui.horizontal_centered(|ui| {
                            if secondary_button_sized(ui, "Drag Target", Some(AppIcon::DragPan), 182.0).clicked() {
                                open_requested = true;
                            }
                            if primary_button_sized(ui, "Open Target", Some(AppIcon::Bolt), 224.0).clicked() {
                                open_requested = true;
                            }
                        });
                    });
                });
        },
    );
    draw_dashed_border(ui, hero_response.response.rect.shrink(6.0), t.dashed_border);

    ui.add_space(10.0);
    if width >= 1260.0 {
        ui.allocate_ui_with_layout(
            egui::vec2(width, 174.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.columns(4, |columns| {
                    for (index, card) in cards.iter().enumerate() {
                        capability_card(
                            &mut columns[index],
                            card.0,
                            card.1,
                            card.2,
                            card.3,
                            card.4,
                        );
                    }
                });
            },
        );
    } else if width >= 820.0 {
        ui.allocate_ui_with_layout(
            egui::vec2(width, 336.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.columns(2, |columns| {
                    capability_card(
                        &mut columns[0],
                        cards[0].0,
                        cards[0].1,
                        cards[0].2,
                        cards[0].3,
                        cards[0].4,
                    );
                    capability_card(
                        &mut columns[1],
                        cards[1].0,
                        cards[1].1,
                        cards[1].2,
                        cards[1].3,
                        cards[1].4,
                    );
                });
                ui.add_space(10.0);
                ui.columns(2, |columns| {
                    capability_card(
                        &mut columns[0],
                        cards[2].0,
                        cards[2].1,
                        cards[2].2,
                        cards[2].3,
                        cards[2].4,
                    );
                    capability_card(
                        &mut columns[1],
                        cards[3].0,
                        cards[3].1,
                        cards[3].2,
                        cards[3].3,
                        cards[3].4,
                    );
                });
            },
        );
    } else {
        for card in cards {
            capability_card(ui, card.0, card.1, card.2, card.3, card.4);
            ui.add_space(12.0);
        }
    }

    open_requested
}

fn render_error_state(ui: &mut Ui, error: &str, can_retry: bool) -> LandingAction {
    let t = theme();
    let width = ui.available_width();
    let compact = width < 920.0;
    let mut action = LandingAction::None;

    ui.allocate_ui_with_layout(
        egui::vec2(width, if compact { 332.0 } else { 360.0 }),
        egui::Layout::top_down(egui::Align::Center),
        |ui| {
            egui::Frame::new()
                .fill(t.panel)
                .stroke(egui::Stroke::new(1.0, t.danger))
                .corner_radius(egui::CornerRadius::same(28))
                .inner_margin(egui::Margin::same(if compact { 22 } else { 26 }))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.vertical_centered(|ui| {
                        ui.add_space(6.0);
                        icon_tile(
                            ui,
                            AppIcon::Info,
                            t.danger,
                            t.panel_alt,
                            if compact { 56.0 } else { 62.0 },
                        );
                        ui.add_space(12.0);
                        ui.label(
                            RichText::new("Analysis failed before report generation")
                                .size(if compact { 18.0 } else { 21.0 })
                                .strong()
                                .color(t.title),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(
                                "The parser hit a fatal edge-case. Choose another target or retry after correcting the input file.",
                            )
                            .size(if compact { 12.8 } else { 13.4 })
                            .color(t.status),
                        );
                        ui.add_space(14.0);
                        egui::Frame::new()
                            .fill(t.inset)
                            .corner_radius(egui::CornerRadius::same(18))
                            .stroke(egui::Stroke::new(1.0, t.border_soft))
                            .inner_margin(egui::Margin::same(14))
                            .show(ui, |ui| {
                                ui.set_max_width(if compact { 520.0 } else { 620.0 });
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(error)
                                            .small()
                                            .monospace()
                                            .color(Color32::from_rgb(255, 193, 193)),
                                    )
                                    .wrap(),
                                );
                            });
                        ui.add_space(16.0);
                        ui.horizontal_wrapped(|ui| {
                            if can_retry
                                && secondary_button_sized(
                                    ui,
                                    "Retry Current Target",
                                    Some(AppIcon::Bolt),
                                    240.0,
                                )
                                .clicked()
                            {
                                action = LandingAction::Retry;
                            }

                            if primary_button_sized(
                                ui,
                                "Open Another Target",
                                Some(AppIcon::FileOpen),
                                260.0,
                            )
                            .clicked()
                            {
                                action = LandingAction::Open;
                            }
                        });
                    });
                });
        },
    );

    action
}

fn render_overview(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "General Info",
        "Core file metadata, hashes, mitigations, and build signals",
    );

    let width = ui.available_width();
    let imported_api_count = report
        .imports
        .iter()
        .map(|dll| dll.functions.len())
        .sum::<usize>();
    let architecture = if report.is_64bit {
        "64-bit"
    } else {
        "32-bit / n.a."
    };
    let profile_rows = vec![
        ("Family".to_string(), report.format_family.clone()),
        (
            "Confidence".to_string(),
            report.detection_confidence.clone(),
        ),
        ("Architecture".to_string(), architecture.to_string()),
        ("Subsystem".to_string(), report.subsystem.clone()),
        ("Machine".to_string(), report.machine_type.clone()),
        (
            "Section Count".to_string(),
            report.section_count.to_string(),
        ),
        (
            "Timestamp".to_string(),
            format!("0x{:08X}", report.timestamp),
        ),
        (
            "File Size".to_string(),
            format!("{} bytes", report.file_size),
        ),
    ];
    let layout_rows = vec![
        (
            "Image Base".to_string(),
            format!("0x{:X}", report.image_base),
        ),
        (
            "Entry Point".to_string(),
            format!("0x{:X}", report.entry_point),
        ),
        (
            "Section Alignment".to_string(),
            format!("0x{:X}", report.section_alignment),
        ),
        (
            "File Alignment".to_string(),
            format!("0x{:X}", report.file_alignment),
        ),
        (
            "ASLR".to_string(),
            bool_badge(report.protections.aslr).to_string(),
        ),
        (
            "DEP / NX".to_string(),
            bool_badge(report.protections.dep_nx).to_string(),
        ),
        (
            "SEH".to_string(),
            bool_badge(report.protections.seh_enabled).to_string(),
        ),
        (
            "TLS Callbacks".to_string(),
            report.protections.tls_callbacks.to_string(),
        ),
    ];
    let hash_rows = vec![
        ("MD5".to_string(), report.md5.clone()),
        ("SHA-1".to_string(), report.sha1.clone()),
        ("SHA-256".to_string(), report.sha256.clone()),
    ];
    let file_name = report
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Unknown target");

    framed_panel(ui, |ui| {
        render_overview_identity(ui, report, file_name, architecture);
    });

    ui.add_space(12.0);
    render_overview_snapshot(ui, report, imported_api_count);

    ui.add_space(14.0);
    if width >= 980.0 {
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
    if width >= 980.0 {
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
    let t = theme();
    ui.label(RichText::new(title).strong().color(t.title));
    ui.add_space(8.0);
    egui::Grid::new(title)
        .num_columns(2)
        .min_col_width(if ui.available_width() >= 480.0 {
            140.0
        } else {
            96.0
        })
        .spacing([18.0, 10.0])
        .show(ui, |ui| {
            for (label, value) in rows {
                overview_row(ui, label, value);
            }
        });
}

fn render_overview_identity(
    ui: &mut Ui,
    report: &BinaryReport,
    file_name: &str,
    architecture: &str,
) {
    let t = theme();
    ui.label(RichText::new(file_name).size(28.0).strong().color(t.title));
    ui.add_space(4.0);

    egui::Frame::new()
        .fill(t.inset)
        .corner_radius(egui::CornerRadius::same(18))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(report.path.display().to_string())
                        .small()
                        .monospace()
                        .color(t.muted),
                )
                .wrap(),
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
    render_metric_strip(
        ui,
        &[
            (
                "Sections",
                report.sections.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "Imported APIs",
                imported_api_count.to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "Strings",
                total_extracted_string_count(report).to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "TLS Callbacks",
                report.protections.tls_callbacks.to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
}

fn render_notes_panel(ui: &mut Ui, notes: &[String]) {
    let t = theme();
    ui.label(RichText::new("Heuristic Notes").strong().color(t.title));
    ui.add_space(8.0);
    if notes.is_empty() {
        ui.label(RichText::new("No heuristic notes were emitted for this target.").color(t.muted));
        return;
    }
    for note in notes {
        ui.label(RichText::new(format!("* {note}")).color(t.muted));
    }
}

fn total_extracted_string_count(report: &BinaryReport) -> usize {
    report
        .ascii_string_count
        .saturating_add(report.utf16_string_count)
}

fn metric_tile(ui: &mut Ui, title: &str, value: &str, accent: Color32) {
    let t = theme();
    egui::Frame::new()
        .fill(t.panel)
        .corner_radius(egui::CornerRadius::same(20))
        .stroke(egui::Stroke::new(1.0, accent.gamma_multiply(0.45)))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            // use available column width, with a sensible floor
            ui.set_min_width(ui.available_width().max(80.0));
            ui.set_min_height(84.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(title).size(11.0).color(t.muted));
                ui.add_space(6.0);
                ui.label(RichText::new(value).size(20.0).strong().color(accent));
            });
        });
}

fn inline_fact(ui: &mut Ui, label: &str, value: &str) {
    let t = theme();
    egui::Frame::new()
        .fill(t.inset)
        .corner_radius(egui::CornerRadius::same(16))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(10.5).color(t.muted));
                ui.label(RichText::new(value).monospace().color(t.text));
            });
        });
}

fn render_hex_viewer(
    ui: &mut Ui,
    report: &BinaryReport,
    hex_offset_input: &mut String,
    hex_rva_input: &mut String,
    hex_status: &mut Option<String>,
    hex_selected_offset: &mut usize,
) {
    render_panel_title(
        ui,
        "Hex Viewer",
        "Raw byte view with offset jump and synchronized ASCII preview",
    );
    if report.raw_bytes.is_empty() {
        render_placeholder_panel(
            ui,
            "No byte buffer is available for this target.",
            "The file loaded without a raw byte slice, so the hex surface is intentionally suppressed.",
        );
        return;
    }

    let compact = ui.available_width() < 760.0;
    let max_offset = report.raw_bytes.len().saturating_sub(1);

    framed_panel(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Offset").color(Color32::from_rgb(188, 195, 205)));
            ui.add_sized(
                [
                    if compact {
                        (ui.available_width() - 120.0).max(140.0)
                    } else {
                        180.0
                    },
                    28.0,
                ],
                egui::TextEdit::singleline(hex_offset_input).hint_text("0x401000 or 16384"),
            );

            if ui.button("Jump").clicked() {
                match parse_offset_input(hex_offset_input, report.raw_bytes.len()) {
                    Ok(offset) => {
                        *hex_selected_offset = offset;
                        *hex_offset_input = format!("0x{offset:X}");
                        if let Some(rva) = rva_from_raw_offset(report, offset) {
                            *hex_rva_input = format!("0x{rva:X}");
                        }
                        *hex_status = Some(format!("Jumped to offset 0x{offset:X}"));
                    }
                    Err(err) => *hex_status = Some(err),
                }
            }

            if ui.button("Entry").clicked() {
                let selection = resolve_initial_hex_selection(report);
                *hex_selected_offset = selection.offset;
                *hex_offset_input = format!("0x{:X}", selection.offset);
                *hex_rva_input = if selection.status.is_some() {
                    format!("0x{:X}", report.entry_point)
                } else {
                    rva_from_raw_offset(report, selection.offset)
                        .map(|rva| format!("0x{rva:X}"))
                        .unwrap_or_else(|| format!("0x{:X}", report.entry_point))
                };
                *hex_status = selection.status.or_else(|| {
                    Some(format!(
                        "Jumped near entry point at raw offset 0x{:X}",
                        selection.offset
                    ))
                });
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
            ui.label(RichText::new(status).small().color(
                if status.starts_with("Invalid") || status.contains("outside") {
                    Color32::from_rgb(235, 104, 104)
                } else {
                    Color32::from_rgb(150, 180, 150)
                },
            ));
        }
    });

    if report.format_name == "PE" && !report.sections.is_empty() {
        ui.add_space(10.0);
        framed_panel(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("RVA").color(Color32::from_rgb(188, 195, 205)));
                ui.add_sized(
                    [
                        if compact {
                            (ui.available_width() - 120.0).max(140.0)
                        } else {
                            180.0
                        },
                        28.0,
                    ],
                    egui::TextEdit::singleline(hex_rva_input).hint_text("0x1130"),
                );

                if ui.button("Jump RVA").clicked() {
                    match parse_offset_input(hex_rva_input, usize::MAX) {
                        Ok(rva) => {
                            if let Some(offset) = raw_offset_from_rva(report, rva as u64) {
                                *hex_selected_offset = offset;
                                *hex_offset_input = format!("0x{offset:X}");
                                *hex_rva_input = format!("0x{:X}", rva);
                                *hex_status = Some(format!(
                                    "RVA 0x{rva:X} resolved to raw offset 0x{offset:X}"
                                ));
                            } else if let Some(section) = section_for_rva(report, rva as u64) {
                                *hex_status = Some(format!(
                                    "RVA 0x{rva:X} lands in the virtual-only tail of section {}; there are no backing file bytes to display.",
                                    section.name
                                ));
                            } else {
                                *hex_status =
                                    Some(format!("RVA 0x{rva:X} does not map to a loaded section"));
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
                        let offset = (section.raw_address as usize).min(max_offset);
                        *hex_selected_offset = offset;
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

    let selected_offset = (*hex_selected_offset).min(max_offset);
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
            RichText::new(
                "Offset        Hex Bytes                                              ASCII",
            )
            .monospace()
            .color(Color32::from_rgb(142, 151, 163)),
        );
        ui.add_space(6.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
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

    if report.resource_entries.is_empty()
        && report.version_info_rows.is_empty()
        && report.manifest_text.is_none()
    {
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
    let architecture = if report.is_64bit {
        "64-bit"
    } else {
        "32-bit / n.a."
    };

    framed_panel(ui, |ui| {
        render_resource_identity(ui, report, file_name, architecture);
    });

    ui.add_space(12.0);
    render_resource_snapshot(ui, report);
    ui.add_space(12.0);

    if width >= 1320.0 {
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

fn render_resource_identity(
    ui: &mut Ui,
    report: &BinaryReport,
    file_name: &str,
    architecture: &str,
) {
    let t = theme();
    ui.label(RichText::new(file_name).size(28.0).strong().color(t.title));
    ui.add_space(4.0);

    egui::Frame::new()
        .fill(t.inset)
        .corner_radius(egui::CornerRadius::same(18))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(report.path.display().to_string())
                        .small()
                        .monospace()
                        .color(t.muted),
                )
                .wrap(),
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
        inline_fact(
            ui,
            "Version Rows",
            &report.version_info_rows.len().to_string(),
        );
        inline_fact(
            ui,
            "Manifest",
            if report.manifest_text.is_some() {
                "Present"
            } else {
                "Missing"
            },
        );
        inline_fact(
            ui,
            "Build Signals",
            &report.pe_metadata_rows.len().to_string(),
        );
    });
}

fn render_resource_snapshot(ui: &mut Ui, report: &BinaryReport) {
    render_metric_strip(
        ui,
        &[
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
            (
                "Manifest",
                if report.manifest_text.is_some() {
                    "Present".to_string()
                } else {
                    "Missing".to_string()
                },
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "Build Signals",
                report.pe_metadata_rows.len().to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
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
            let name_width =
                (available - kind_width - size_width - code_page_width - 36.0).max(240.0);

            resource_tree_header(ui, name_width, kind_width, size_width, code_page_width);
            ui.add_space(8.0);

            vertical_surface_scroll(ui, "resource_tree_rows", tree_height, |ui| {
                for entry in &report.resource_entries {
                    resource_tree_row(
                        ui,
                        entry,
                        name_width,
                        kind_width,
                        size_width,
                        code_page_width,
                    );
                    ui.add_space(6.0);
                }
            });
        });
    });
}

fn render_resource_detail_stack(ui: &mut Ui, report: &BinaryReport) {
    let t = theme();
    if !report.pe_metadata_rows.is_empty() {
        framed_panel(ui, |ui| {
            ui.label(RichText::new("PE Build Signals").strong().color(t.title));
            ui.add_space(8.0);
            render_kv_rows(ui, "pe_build_signals_rows", &report.pe_metadata_rows);
        });

        ui.add_space(12.0);
    }

    framed_panel(ui, |ui| {
        ui.label(RichText::new("Version Info").strong().color(t.title));
        ui.add_space(8.0);

        if report.version_info_rows.is_empty() {
            ui.label(RichText::new("No version resource was extracted.").color(t.muted));
        } else {
            vertical_surface_scroll(ui, "version_info_rows_scroll", 240.0, |ui| {
                render_kv_rows(ui, "version_info_rows", &report.version_info_rows);
            });
        }
    });

    ui.add_space(12.0);

    framed_panel(ui, |ui| {
        ui.label(RichText::new("Manifest").strong().color(t.title));
        ui.add_space(8.0);

        if report.manifest_text.is_none() {
            ui.label(RichText::new("No application manifest was extracted.").color(t.muted));
            return;
        }

        if !report.manifest_rows.is_empty() {
            render_kv_rows(ui, "manifest_signal_rows", &report.manifest_rows);
            ui.add_space(10.0);
        }

        egui::Frame::new()
            .fill(t.inset)
            .corner_radius(egui::CornerRadius::same(20))
            .stroke(egui::Stroke::new(1.0, t.border_soft))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                vertical_surface_scroll(ui, "manifest_text_scroll", 260.0, |ui| {
                    if let Some(text) = &report.manifest_text {
                        ui.label(RichText::new(text).monospace().color(t.text));
                    }
                });
            });
    });
}

fn resource_tree_header(
    ui: &mut Ui,
    name_width: f32,
    kind_width: f32,
    size_width: f32,
    code_page_width: f32,
) {
    let t = theme();
    ui.horizontal(|ui| {
        ui.add_sized(
            [name_width, 18.0],
            egui::Label::new(RichText::new("Name").small().color(t.muted)),
        );
        ui.add_sized(
            [kind_width, 18.0],
            egui::Label::new(RichText::new("Kind").small().color(t.muted)),
        );
        ui.add_sized(
            [size_width, 18.0],
            egui::Label::new(RichText::new("Size").small().color(t.muted)),
        );
        ui.add_sized(
            [code_page_width, 18.0],
            egui::Label::new(RichText::new("CodePage").small().color(t.muted)),
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
    let t = theme();
    egui::Frame::new()
        .fill(t.inset)
        .corner_radius(egui::CornerRadius::same(16))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
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
                                .color(t.text),
                        )
                        .on_hover_text(&entry.path);
                    },
                );
                ui.add_sized(
                    [kind_width, 22.0],
                    egui::Label::new(RichText::new(&entry.kind).small().color(t.muted)),
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
                        .color(t.text),
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
                        .color(t.text),
                    ),
                );
            });
        });
}

fn render_metric_strip(ui: &mut Ui, metrics: &[(&str, String, Color32)]) {
    // Breakpoints adjusted: sidebar is ~252px so usable content width = window - sidebar
    if ui.available_width() >= 980.0 && metrics.len() == 4 {
        ui.columns(4, |columns| {
            for (column, (title, value, accent)) in columns.iter_mut().zip(metrics.iter()) {
                metric_tile(column, title, value, *accent);
            }
        });
    } else if ui.available_width() >= 560.0 && metrics.len() >= 4 {
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
    let t = theme();
    egui::Frame::new()
        .fill(t.inset)
        .corner_radius(egui::CornerRadius::same(20))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
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
    render_panel_title(
        ui,
        "Sections",
        "PE section layout, permissions, and entropy",
    );

    if report.sections.is_empty() {
        render_placeholder_panel(
            ui,
            "No section table was extracted for this target.",
            "Either the format has no section abstraction here, or the parser intentionally skipped malformed section metadata.",
        );
        return;
    }

    let executable_sections = report
        .sections
        .iter()
        .filter(|section| section.characteristics.contains("EXEC"))
        .count();
    let writable_sections = report
        .sections
        .iter()
        .filter(|section| section.characteristics.contains("WRITE"))
        .count();
    let high_entropy_sections = report
        .sections
        .iter()
        .filter(|section| section.entropy >= 7.0)
        .count();

    render_metric_strip(
        ui,
        &[
            (
                "Count",
                report.sections.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "Executable",
                executable_sections.to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "Writable",
                writable_sections.to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "High Entropy",
                high_entropy_sections.to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
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
                    for title in [
                        "Name",
                        "VA",
                        "VSZ",
                        "Raw",
                        "RSZ",
                        "Characteristics",
                        "Entropy",
                    ] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|mut body| {
                    for section in &report.sections {
                        body.row(22.0, |mut row| {
                            row.col(|ui| {
                                let name_response = ui.add(
                                    egui::Button::new(RichText::new(&section.name).monospace())
                                        .fill(Color32::TRANSPARENT)
                                        .stroke(egui::Stroke::NONE),
                                );
                                if name_response.clicked() {
                                    let nav_id = egui::Id::new("hex_nav_request");
                                    ui.memory_mut(|m| {
                                        m.data.insert_temp(nav_id, section.raw_address);
                                    });
                                }
                                if name_response.hovered() {
                                    name_response.on_hover_text("Click to view in Hex Viewer");
                                }
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

fn render_imports(ui: &mut Ui, report: &BinaryReport, filter: &mut String) {
    render_panel_title(
        ui,
        "Imports",
        "Grouped imported DLLs and resolved function names",
    );

    if report.imports.is_empty() {
        render_placeholder_panel(
            ui,
            "No import table is available.",
            "Static imports were not resolved for this binary. That can mean a stripped image, a non-PE target, or delayed/runtime import resolution.",
        );
        return;
    }

    let import_count = report
        .imports
        .iter()
        .map(|dll| dll.functions.len())
        .sum::<usize>();
    let ordinal_count = report
        .imports
        .iter()
        .flat_map(|dll| dll.functions.iter())
        .filter(|func| func.ordinal != 0)
        .count();

    render_metric_strip(
        ui,
        &[
            (
                "DLLs",
                report.imports.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "APIs",
                import_count.to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "Ordinals",
                ordinal_count.to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "Empty Groups",
                report
                    .imports
                    .iter()
                    .filter(|dll| dll.functions.is_empty())
                    .count()
                    .to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Search:")
                .small()
                .color(Color32::from_rgb(151, 143, 135)),
        );
        ui.add(
            egui::TextEdit::singleline(filter)
                .hint_text("Filter DLLs or functions...")
                .desired_width(260.0),
        );
        if ui.button(RichText::new("Clear").small()).clicked() {
            filter.clear();
        }
    });
    ui.add_space(8.0);

    let filter_lower = filter.to_ascii_lowercase();

    framed_panel(ui, |ui| {
        section_surface(ui, |ui| {
            vertical_surface_scroll(ui, "imports_list_scroll", 560.0, |ui| {
                for dll in &report.imports {
                    let dll_matches =
                        filter.is_empty() || dll.name.to_ascii_lowercase().contains(&filter_lower);
                    let matching_functions: Vec<_> = dll
                        .functions
                        .iter()
                        .filter(|func| {
                            filter.is_empty()
                                || dll_matches
                                || func.name.to_ascii_lowercase().contains(&filter_lower)
                        })
                        .collect();

                    if matching_functions.is_empty() && !filter.is_empty() {
                        continue;
                    }

                    let func_count = matching_functions.len();
                    egui::CollapsingHeader::new(format!("{} ({})", dll.name, func_count))
                        .default_open(func_count <= 12)
                        .show(ui, |ui| {
                            if matching_functions.is_empty() {
                                ui.label(
                                    RichText::new("Container or library reference only")
                                        .small()
                                        .color(Color32::GRAY),
                                );
                            }
                            for function in &matching_functions {
                                egui::Frame::new()
                                    .fill(Color32::from_rgb(9, 13, 18))
                                    .corner_radius(egui::CornerRadius::same(14))
                                    .stroke(egui::Stroke::new(1.0, Color32::from_rgb(28, 36, 46)))
                                    .inner_margin(egui::Margin::symmetric(10, 6))
                                    .show(ui, |ui| {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.monospace(&function.name);
                                            ui.label(
                                                RichText::new(format!(
                                                    "ordinal {}",
                                                    function.ordinal
                                                ))
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

    if report.exports.is_empty() {
        render_placeholder_panel(
            ui,
            "No exports were recovered from this target.",
            "This is expected for most executables and for binaries that do not expose an export directory.",
        );
        return;
    }

    render_metric_strip(
        ui,
        &[
            (
                "Exports",
                report.exports.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
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
    render_panel_title(
        ui,
        "Strings",
        "Searchable string extraction with format filters",
    );

    if report.strings.is_empty() {
        render_placeholder_panel(
            ui,
            "No ASCII or UTF-16LE strings crossed the extraction threshold.",
            "Lower-entropy blobs, compressed content, or binaries with aggressive obfuscation can legitimately produce an empty strings surface.",
        );
        return;
    }

    let compact = ui.available_width() < 820.0;

    framed_panel(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Search").color(Color32::from_rgb(188, 195, 205)));
            ui.add_sized(
                [
                    if compact {
                        (ui.available_width() - 80.0).max(180.0)
                    } else {
                        340.0
                    },
                    28.0,
                ],
                egui::TextEdit::singleline(string_filter)
                    .hint_text("needle, dll path, api key, domain..."),
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

    let normalized_needle =
        (!*case_sensitive && !string_filter.is_empty()).then(|| string_filter.to_ascii_lowercase());
    let filtered = collect_visible_strings(
        &report.strings,
        string_filter,
        normalized_needle.as_deref(),
        *case_sensitive,
        *show_ascii,
        *show_utf16,
    );
    let visible_count = filtered.rows.len();

    render_metric_strip(
        ui,
        &[
            (
                "Stored",
                report.strings.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "Visible",
                filtered.total_visible.to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "ASCII",
                report.ascii_string_count.to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "UTF-16LE",
                report.utf16_string_count.to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(10.0);

    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(format!(
                "showing {} of {} visible / {} stored",
                visible_count,
                filtered.total_visible,
                report.strings.len()
            ))
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
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(RichText::new("Export CSV").small()).clicked() {
                let report_clone = report.clone();
                let filter_clone = string_filter.clone();
                let case_clone = *case_sensitive;
                let ascii_clone = *show_ascii;
                let utf16_clone = *show_utf16;
                std::thread::spawn(move || {
                    let _filtered: Vec<_> = report_clone
                        .strings
                        .iter()
                        .filter(|s| {
                            if !ascii_clone && s.kind == "ASCII" {
                                return false;
                            }
                            if !utf16_clone && s.kind.starts_with("UTF-16") {
                                return false;
                            }
                            if !filter_clone.is_empty() {
                                let matches = if case_clone {
                                    s.value.contains(&filter_clone)
                                } else {
                                    s.value
                                        .to_ascii_lowercase()
                                        .contains(&filter_clone.to_ascii_lowercase())
                                };
                                if !matches {
                                    return false;
                                }
                            }
                            true
                        })
                        .collect();
                    let default_path = crate::report_export::default_strings_path(&report_clone);
                    let csv_path = default_path.with_extension("strings.csv");
                    if let Err(err) =
                        crate::report_export::write_strings_csv(&report_clone, &csv_path)
                    {
                        eprintln!("Failed to export CSV: {err}");
                    }
                });
            }
            if ui.button(RichText::new("Export TXT").small()).clicked() {
                let report_clone = report.clone();
                std::thread::spawn(move || {
                    let default_path = crate::report_export::default_strings_path(&report_clone);
                    if let Err(err) =
                        crate::report_export::write_strings_txt(&report_clone, &default_path)
                    {
                        eprintln!("Failed to export TXT: {err}");
                    }
                });
            }
        });
    });
    ui.add_space(8.0);

    if filtered.total_visible == 0 {
        let message = if !*show_ascii && !*show_utf16 {
            "Both format filters are disabled. Re-enable at least one string family to populate the table."
        } else {
            "No extracted strings matched the active search and format filters."
        };

        framed_panel(ui, |ui| {
            ui.label(RichText::new(message).color(Color32::from_rgb(140, 149, 160)));
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                if !string_filter.is_empty()
                    && secondary_button_sized(ui, "Clear Search", None, 150.0).clicked()
                {
                    string_filter.clear();
                }
                if (!*show_ascii || !*show_utf16)
                    && secondary_button_sized(ui, "Enable All Formats", None, 190.0).clicked()
                {
                    *show_ascii = true;
                    *show_utf16 = true;
                }
            });
        });
        return;
    }

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
                    for string in filtered.rows {
                        body.row(22.0, |mut row| {
                            row.col(|ui| {
                                ui.label(RichText::new(string.kind).color(match string.kind {
                                    "ASCII" => Color32::from_rgb(110, 174, 255),
                                    "UTF-16LE" => Color32::from_rgb(124, 208, 156),
                                    _ => Color32::LIGHT_GRAY,
                                }));
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

struct VisibleStrings<'a> {
    total_visible: usize,
    rows: Vec<&'a crate::analyzer::ExtractedString>,
}

fn collect_visible_strings<'a>(
    strings: &'a [crate::analyzer::ExtractedString],
    needle: &str,
    normalized_needle: Option<&str>,
    case_sensitive: bool,
    show_ascii: bool,
    show_utf16: bool,
) -> VisibleStrings<'a> {
    let mut rows = Vec::with_capacity(MAX_VISIBLE_STRING_ROWS);
    let mut total_visible = 0usize;

    for entry in strings {
        let kind_allowed = match entry.kind {
            "ASCII" => show_ascii,
            "UTF-16LE" => show_utf16,
            _ => true,
        };
        if !kind_allowed
            || !string_matches(
                entry.value.as_str(),
                needle,
                normalized_needle,
                case_sensitive,
            )
        {
            continue;
        }

        total_visible += 1;
        if rows.len() < MAX_VISIBLE_STRING_ROWS {
            rows.push(entry);
        }
    }

    VisibleStrings {
        total_visible,
        rows,
    }
}

fn render_disassembly(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "Disassembly",
        "Entry-point focused preview from .text or the containing section",
    );

    if report.disassembly.is_empty() {
        render_placeholder_panel(
            ui,
            "No entry-point disassembly preview is available.",
            "The image may be malformed, packed, or missing a decodable section around the declared entry RVA.",
        );
        return;
    }

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
            (
                "Instructions",
                report.disassembly.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "Entry",
                format!("0x{:X}", report.entry_point),
                Color32::from_rgb(92, 184, 92),
            ),
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

    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16).map_err(|_| "Invalid hex offset".to_string())?
    } else {
        trimmed
            .parse::<usize>()
            .map_err(|_| "Invalid decimal offset".to_string())?
    };

    if parsed >= len {
        return Err(format!("Offset 0x{parsed:X} is outside the loaded file"));
    }

    Ok(parsed)
}

fn resolve_initial_hex_selection(report: &BinaryReport) -> HexSelection {
    if report.raw_bytes.is_empty() {
        return HexSelection {
            offset: 0,
            status: None,
        };
    }

    if let Some(offset) = raw_offset_from_rva(report, report.entry_point) {
        return HexSelection {
            offset: offset.min(report.raw_bytes.len().saturating_sub(1)),
            status: None,
        };
    }

    if let Some(section) = section_for_rva(report, report.entry_point) {
        let offset = (section.raw_address as usize).min(report.raw_bytes.len().saturating_sub(1));
        return HexSelection {
            offset,
            status: Some(format!(
                "Entry RVA 0x{:X} lands in the virtual-only tail of section {}; showing the nearest file-backed bytes at raw offset 0x{:X}.",
                report.entry_point, section.name, offset
            )),
        };
    }

    HexSelection {
        offset: 0,
        status: Some(format!(
            "Entry RVA 0x{:X} does not map to a file-backed section; showing the file head.",
            report.entry_point
        )),
    }
}

fn section_for_rva(report: &BinaryReport, rva: u64) -> Option<&crate::analyzer::SectionInfo> {
    report.sections.iter().find(|section| {
        let start = section.virtual_address as u64;
        let span = section.virtual_size.max(section.raw_size) as u64;
        let end = start.saturating_add(span);
        rva >= start && rva < end
    })
}

fn raw_offset_from_rva(report: &BinaryReport, rva: u64) -> Option<usize> {
    section_for_rva(report, rva).and_then(|section| {
        let delta = rva.saturating_sub(section.virtual_address as u64) as usize;
        (delta < section.raw_size as usize).then_some(section.raw_address as usize + delta)
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
            let _ = write!(&mut output, "{byte:02X}");
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
    render_panel_title(
        ui,
        "Archive",
        "Container members for ZIP-like and package formats",
    );

    let total_archive_size = report
        .archive_entries
        .iter()
        .map(|entry| entry.size)
        .sum::<u64>();
    render_metric_strip(
        ui,
        &[
            (
                "Entries",
                report.archive_entry_total.to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "Stored",
                report.archive_entries.len().to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "Total Size",
                total_archive_size.to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "Format",
                report.format_name.clone(),
                Color32::from_rgb(198, 122, 255),
            ),
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

        if report.archive_entries_omitted > 0 {
            ui.label(
                RichText::new(format!(
                    "Showing the first {} member(s); {} additional entries were omitted to keep the UI responsive.",
                    report.archive_entries.len(),
                    report.archive_entries_omitted
                ))
                .small()
                .color(Color32::from_rgb(210, 170, 120)),
            );
            ui.add_space(8.0);
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

    if report.dos_header.is_empty()
        && report.file_header.is_empty()
        && report.optional_header.is_empty()
        && report.rich_headers.is_empty()
    {
        render_placeholder_panel(
            ui,
            "No structured header rows are available.",
            "This surface only renders when the parser can recover DOS, COFF, optional, or Rich header metadata.",
        );
        return;
    }

    render_metric_strip(
        ui,
        &[
            (
                "DOS Rows",
                report.dos_header.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "File Rows",
                report.file_header.len().to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "Optional Rows",
                report.optional_header.len().to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "Rich Rows",
                report.rich_headers.len().to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(12.0);

    if ui.available_width() >= 1060.0 {
        ui.columns(3, |columns| {
            render_kv_group(&mut columns[0], "DOS Header", &report.dos_header);
            render_kv_group(&mut columns[1], "File Header", &report.file_header);
            render_kv_group(&mut columns[2], "Optional Header", &report.optional_header);
        });
    } else if ui.available_width() >= 680.0 {
        ui.columns(2, |columns| {
            render_kv_group(&mut columns[0], "DOS Header", &report.dos_header);
            render_kv_group(&mut columns[1], "File Header", &report.file_header);
        });
        ui.add_space(12.0);
        render_kv_group(ui, "Optional Header", &report.optional_header);
    } else {
        render_kv_group(ui, "DOS Header", &report.dos_header);
        ui.add_space(12.0);
        render_kv_group(ui, "File Header", &report.file_header);
        ui.add_space(12.0);
        render_kv_group(ui, "Optional Header", &report.optional_header);
    }

    ui.add_space(12.0);
    render_kv_group(ui, "Rich Header", &report.rich_headers);
}

fn render_protection(ui: &mut Ui, report: &BinaryReport) {
    render_panel_title(
        ui,
        "Protection",
        "Mitigations, anti-debug indicators, and suspicious API heuristics",
    );

    let enabled_mitigations = [
        report.protections.aslr,
        report.protections.dep_nx,
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
            (
                "Mitigations",
                enabled_mitigations.to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "Findings",
                report.protection_findings.len().to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "High",
                high_findings.to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "TLS",
                report.protections.tls_callbacks.to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(12.0);

    if ui.available_width() >= 1080.0 {
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
            (
                "Single-byte",
                report.xor_candidates.len().to_string(),
                Color32::from_rgb(90, 160, 255),
            ),
            (
                "Common Keys",
                report.xor_common_key_hits.len().to_string(),
                Color32::from_rgb(92, 184, 92),
            ),
            (
                "Patterns",
                report.xor_patterns.len().to_string(),
                Color32::from_rgb(210, 144, 72),
            ),
            (
                "Strings",
                total_extracted_string_count(report).to_string(),
                Color32::from_rgb(198, 122, 255),
            ),
        ],
    );
    ui.add_space(12.0);

    if ui.available_width() >= 1080.0 {
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
    let t = theme();
    egui::Frame::new()
        .fill(t.panel)
        .corner_radius(egui::CornerRadius::same(22))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().color(t.title));
            ui.add_space(8.0);
            render_kv_rows(ui, title, rows);
        });
}

fn render_kv_rows(ui: &mut Ui, id_source: impl std::hash::Hash, rows: &[KeyValueRow]) {
    let t = theme();
    egui::Grid::new(ui.id().with(id_source).with("kv_rows"))
        .num_columns(2)
        .min_col_width(if ui.available_width() >= 540.0 {
            132.0
        } else {
            92.0
        })
        .spacing([16.0, 10.0])
        .show(ui, |ui| {
            for row in rows {
                ui.label(RichText::new(&row.key).size(11.5).color(t.muted));
                ui.add(
                    egui::Label::new(RichText::new(&row.value).monospace().color(t.text)).wrap(),
                );
                ui.end_row();
            }
        });
}

fn render_findings(ui: &mut Ui, findings: &[crate::analyzer::ProtectionFinding]) {
    let t = theme();
    ui.label(RichText::new("Findings").strong().color(t.title));
    ui.add_space(8.0);
    if findings.is_empty() {
        ui.label(
            RichText::new("No suspicious findings were emitted for this file.").color(t.muted),
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
                .fill(t.inset)
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
                        ui.label(RichText::new(&finding.title).strong().color(t.title));
                    });
                    ui.add_space(4.0);
                    ui.label(RichText::new(&finding.detail).color(t.muted));
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
    let t = theme();
    ui.label(RichText::new(label).size(11.5).color(t.muted));
    ui.label(
        RichText::new(value)
            .text_style(TextStyle::Monospace)
            .color(t.text),
    );
    ui.end_row();
}

fn icon_tile(ui: &mut Ui, icon: AppIcon, accent: Color32, fill: Color32, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    ui.painter().rect(
        rect,
        size / 5.0,
        fill,
        egui::Stroke::new(1.0, accent.gamma_multiply(0.35)),
        egui::StrokeKind::Outside,
    );
    paint_icon(
        ui.painter(),
        rect.shrink2(egui::vec2(size * 0.28, size * 0.28)),
        icon,
        accent,
        (size / 18.0).max(1.4),
    );
}

fn tab_meta(tab: ActiveTab) -> (AppIcon, &'static str) {
    match tab {
        ActiveTab::GeneralInfo => (AppIcon::Info, "General Info"),
        ActiveTab::Resources => (AppIcon::Package, "Resources"),
        ActiveTab::Hex => (AppIcon::Cube, "Hex Viewer"),
        ActiveTab::Sections => (AppIcon::Grid, "Sections"),
        ActiveTab::Imports => (AppIcon::Download, "Imports"),
        ActiveTab::Exports => (AppIcon::Upload, "Exports"),
        ActiveTab::Disassembly => (AppIcon::Terminal, "Disassembly"),
        ActiveTab::Strings => (AppIcon::Keyboard, "Strings"),
        ActiveTab::Protection => (AppIcon::Shield, "Protection"),
        ActiveTab::Xor => (AppIcon::Chart, "XOR Analysis"),
        ActiveTab::Archive => (AppIcon::Archive, "Archive"),
        ActiveTab::Headers => (AppIcon::Code, "Headers"),
    }
}

fn sidebar_section_label(ui: &mut Ui, text: &str) {
    shell_section_label(ui, text);
}

fn status_chip(ui: &mut Ui, text: &str, _accent: Color32) {
    workspace_status_chip(ui, text);
}

fn primary_button(ui: &mut Ui, label: &str, icon: Option<AppIcon>) -> egui::Response {
    primary_action_button(ui, label, icon, true)
}

fn primary_button_sized(
    ui: &mut Ui,
    label: &str,
    icon: Option<AppIcon>,
    width: f32,
) -> egui::Response {
    primary_action_button_with_width(ui, label, icon, width)
}

fn secondary_button_sized(
    ui: &mut Ui,
    label: &str,
    icon: Option<AppIcon>,
    width: f32,
) -> egui::Response {
    secondary_action_button_with_width(ui, label, icon, width)
}

fn ghost_button(ui: &mut Ui, label: &str) -> egui::Response {
    ghost_action_button(ui, label, false)
}

fn draw_dashed_border(ui: &mut Ui, rect: egui::Rect, color: Color32) {
    let painter = ui.painter();
    let stroke = egui::Stroke::new(1.0, color);
    let dash = 9.0;
    let gap = 7.0;
    let radius = 28.0;

    let draw_dashed_line = |start: egui::Pos2, end: egui::Pos2| {
        let vector = end - start;
        let length = vector.length();
        if length <= 0.0 {
            return;
        }
        let direction = vector / length;
        let mut distance = 0.0;
        while distance < length {
            let from = start + direction * distance;
            let to = start + direction * (distance + dash).min(length);
            painter.line_segment([from, to], stroke);
            distance += dash + gap;
        }
    };

    draw_dashed_line(
        egui::pos2(rect.left() + radius, rect.top()),
        egui::pos2(rect.right() - radius, rect.top()),
    );
    draw_dashed_line(
        egui::pos2(rect.right(), rect.top() + radius),
        egui::pos2(rect.right(), rect.bottom() - radius),
    );
    draw_dashed_line(
        egui::pos2(rect.right() - radius, rect.bottom()),
        egui::pos2(rect.left() + radius, rect.bottom()),
    );
    draw_dashed_line(
        egui::pos2(rect.left(), rect.bottom() - radius),
        egui::pos2(rect.left(), rect.top() + radius),
    );
    painter.rect_stroke(
        rect,
        radius,
        egui::Stroke::new(0.0, Color32::TRANSPARENT),
        egui::StrokeKind::Outside,
    );
}

fn shell_section_label(ui: &mut Ui, text: &str) {
    let t = theme();
    ui.label(
        RichText::new(text.to_ascii_uppercase())
            .small()
            .strong()
            .color(t.status),
    );
    ui.add_space(8.0);
}

fn workspace_status_chip(ui: &mut Ui, text: &str) {
    let t = theme();
    egui::Frame::new()
        .fill(t.primary_soft)
        .stroke(egui::Stroke::new(1.0, t.primary_border))
        .corner_radius(egui::CornerRadius::same(14))
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, t.primary);
                ui.label(RichText::new(text).strong().color(t.text));
            });
        });
}

fn primary_action_button(
    ui: &mut Ui,
    label: &str,
    icon: Option<AppIcon>,
    full_width: bool,
) -> egui::Response {
    let width = if full_width {
        ui.available_width()
    } else {
        // clamp to available width so button never overflows at narrow sidebar widths
        ui.available_width().clamp(100.0, 214.0)
    };
    primary_action_button_with_width(ui, label, icon, width)
}

fn primary_action_button_with_width(
    ui: &mut Ui,
    label: &str,
    icon: Option<AppIcon>,
    width: f32,
) -> egui::Response {
    let t = theme();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 52.0), egui::Sense::click());
    let hovered = response.hovered();
    let fill = if hovered {
        t.primary.gamma_multiply(1.06)
    } else {
        t.primary
    };
    let stroke = egui::Stroke::new(1.0, t.primary_border);
    ui.painter()
        .rect(rect, 18.0, fill, stroke, egui::StrokeKind::Outside);
    ui.painter().rect_filled(
        rect.translate(egui::vec2(0.0, 6.0)),
        18.0,
        t.primary.gamma_multiply(if hovered { 0.08 } else { 0.05 }),
    );

    let content_rect = rect.shrink2(egui::vec2(18.0, 12.0));
    let mut cursor_x = content_rect.left();
    if let Some(icon) = icon {
        let icon_rect = egui::Rect::from_min_size(
            egui::pos2(cursor_x, content_rect.center().y - 10.0),
            egui::vec2(20.0, 20.0),
        );
        paint_icon(ui.painter(), icon_rect, icon, t.primary_text, 1.8);
        cursor_x += 30.0;
    }
    ui.painter().text(
        egui::pos2(cursor_x, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(14.0),
        t.primary_text,
    );
    response
}

fn secondary_action_button_with_width(
    ui: &mut Ui,
    label: &str,
    icon: Option<AppIcon>,
    width: f32,
) -> egui::Response {
    let t = theme();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 48.0), egui::Sense::click());
    let fill = if response.hovered() {
        t.panel_alt
    } else {
        t.inset
    };
    ui.painter().rect(
        rect,
        18.0,
        fill,
        egui::Stroke::new(1.0, t.border),
        egui::StrokeKind::Outside,
    );
    let content_rect = rect.shrink2(egui::vec2(18.0, 12.0));
    let mut cursor_x = content_rect.left();
    if let Some(icon) = icon {
        let icon_rect = egui::Rect::from_min_size(
            egui::pos2(cursor_x, content_rect.center().y - 10.0),
            egui::vec2(20.0, 20.0),
        );
        paint_icon(ui.painter(), icon_rect, icon, t.title, 1.8);
        cursor_x += 30.0;
    }
    ui.painter().text(
        egui::pos2(cursor_x, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.8),
        t.title,
    );
    response
}

fn ghost_action_button(ui: &mut Ui, label: &str, full_width: bool) -> egui::Response {
    let t = theme();
    let mut button = egui::Button::new(RichText::new(label).size(13.0).color(t.text))
        .fill(t.panel_alt)
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .corner_radius(egui::CornerRadius::same(14));
    if full_width {
        button = button.min_size(egui::vec2(ui.available_width(), 34.0));
    }
    ui.add(button)
}

fn capability_card(
    ui: &mut Ui,
    icon: AppIcon,
    title: &str,
    subtitle: &str,
    accent: Color32,
    footer: CardFooter<'_>,
) {
    let t = theme();
    egui::Frame::new()
        .fill(t.panel)
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .corner_radius(egui::CornerRadius::same(22))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_height(154.0);
            icon_tile(ui, icon, accent, accent.gamma_multiply(0.12), 32.0);
            ui.add_space(12.0);
            ui.label(RichText::new(title).size(15.0).strong().color(t.title));
            ui.add_space(4.0);
            ui.label(RichText::new(subtitle).size(12.3).color(t.muted));
            ui.add_space(10.0);
            match footer {
                CardFooter::Progress(value) => {
                    let width = (ui.available_width() - 6.0).max(80.0);
                    let outer = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(width, 6.0));
                    let inner = egui::Rect::from_min_size(
                        outer.min,
                        egui::vec2(outer.width() * value.clamp(0.0, 1.0), 6.0),
                    );
                    ui.painter().rect_filled(outer, 4.0, t.inset);
                    ui.painter()
                        .rect_filled(inner, 4.0, accent.gamma_multiply(0.75));
                    ui.allocate_space(outer.size());
                }
                CardFooter::Action(text) => {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(text.to_ascii_uppercase())
                                .small()
                                .color(t.status),
                        );
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                        paint_icon(ui.painter(), rect, AppIcon::Upload, t.status, 1.3);
                    });
                }
                CardFooter::Badges(values) => {
                    ui.horizontal_wrapped(|ui| {
                        for value in values {
                            sidebar_pill(ui, value);
                        }
                    });
                }
                CardFooter::Histogram => {
                    let bars = [8.0, 15.0, 22.0, 12.0, 30.0, 18.0];
                    ui.horizontal(|ui| {
                        for bar in bars {
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(9.0, 30.0), egui::Sense::hover());
                            let bar_rect = egui::Rect::from_min_max(
                                egui::pos2(rect.left(), rect.bottom() - bar),
                                egui::pos2(rect.right(), rect.bottom()),
                            );
                            ui.painter()
                                .rect_filled(bar_rect, 2.0, accent.gamma_multiply(0.75));
                        }
                    });
                }
            }
        });
}

fn framed_panel(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    let t = theme();
    egui::Frame::new()
        .fill(t.panel)
        .corner_radius(egui::CornerRadius::same(24))
        .stroke(egui::Stroke::new(1.0, t.border))
        .inner_margin(egui::Margin::same(16))
        .show(ui, add_contents);
}

fn render_panel_title(ui: &mut Ui, title: &str, subtitle: &str) {
    let t = theme();
    ui.label(RichText::new(title).size(22.0).strong().color(t.title));
    ui.label(RichText::new(subtitle).small().color(t.status));
    ui.add_space(12.0);
}

fn render_placeholder_panel(ui: &mut Ui, title: &str, detail: &str) {
    let t = theme();
    framed_panel(ui, |ui| {
        ui.label(RichText::new(title).strong().color(t.title));
        ui.add_space(6.0);
        ui.label(RichText::new(detail).color(t.muted));
    });
}

fn string_matches(
    value: &str,
    needle: &str,
    normalized_needle: Option<&str>,
    case_sensitive: bool,
) -> bool {
    if needle.is_empty() {
        return true;
    }

    if case_sensitive {
        value.contains(needle)
    } else {
        normalized_needle
            .map(|needle| contains_ascii_case_insensitive(value, needle))
            .unwrap_or(true)
    }
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn nav_button(ui: &mut Ui, icon: AppIcon, label: &str, selected: bool) -> egui::Response {
    let t = theme();
    let fill = if selected {
        t.primary_soft
    } else {
        Color32::TRANSPARENT
    };
    let stroke = if selected {
        t.primary_border
    } else {
        Color32::TRANSPARENT
    };
    let text = if selected {
        t.primary
    } else {
        Color32::from_rgb(186, 193, 209)
    };
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 40.0), egui::Sense::click());
    let hover_fill = if response.hovered() && !selected {
        t.panel_alt.gamma_multiply(0.65)
    } else {
        fill
    };
    ui.painter().rect(
        rect,
        16.0,
        hover_fill,
        egui::Stroke::new(1.0, stroke),
        egui::StrokeKind::Outside,
    );
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 28.0, rect.center().y),
        egui::vec2(16.0, 16.0),
    );
    paint_icon(ui.painter(), icon_rect, icon, text, 1.6);
    ui.painter().text(
        egui::pos2(rect.left() + 54.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.6),
        text,
    );
    response
}

fn pill(ui: &mut Ui, text: &str) {
    let t = theme();
    egui::Frame::new()
        .fill(t.panel_alt)
        .corner_radius(egui::CornerRadius::same(30))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .inner_margin(egui::Margin::symmetric(14, 8))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(t.text));
        });
}

fn sidebar_pill(ui: &mut Ui, text: &str) {
    let t = theme();
    egui::Frame::new()
        .fill(t.inset)
        .corner_radius(egui::CornerRadius::same(12))
        .stroke(egui::Stroke::new(1.0, t.border_soft))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().color(t.text));
        });
}

fn titlebar_button(
    ui: &mut Ui,
    icon: AppIcon,
    accent: Color32,
    tooltip: &str,
    close_hover: bool,
    on_click: impl FnOnce(),
) {
    let t = theme();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(36.0, 30.0), egui::Sense::click());
    let fill = if response.hovered() {
        if close_hover {
            t.danger.gamma_multiply(0.18)
        } else {
            t.panel.gamma_multiply(1.1)
        }
    } else {
        t.panel_alt
    };
    ui.painter().rect(
        rect,
        12.0,
        fill,
        egui::Stroke::new(1.0, accent),
        egui::StrokeKind::Outside,
    );
    paint_icon(
        ui.painter(),
        rect.shrink2(egui::vec2(10.0, 8.0)),
        icon,
        if close_hover && response.hovered() {
            t.danger
        } else {
            t.title
        },
        1.5,
    );
    let response = response.on_hover_text(tooltip);
    if response.clicked() {
        on_click();
    }
}

fn render_help_fab(ctx: &egui::Context) {
    let t = theme();
    let about_open_id = egui::Id::new("about_dialog_open");

    egui::Area::new("help_fab".into())
        .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-20.0, -54.0))
        .show(ctx, |ui| {
            let (rect, response) =
                ui.allocate_exact_size(egui::vec2(52.0, 52.0), egui::Sense::click());
            let bg = if response.hovered() {
                t.panel
            } else {
                t.panel_alt
            };
            ui.painter().rect(
                rect,
                26.0,
                bg,
                egui::Stroke::new(1.0, t.border_soft),
                egui::StrokeKind::Outside,
            );
            paint_icon(
                ui.painter(),
                rect.shrink2(egui::vec2(16.0, 16.0)),
                AppIcon::Info,
                t.title,
                1.7,
            );
            if response.clicked() {
                let mut open = ctx
                    .memory_mut(|m| m.data.get_persisted::<bool>(about_open_id).unwrap_or(false));
                open = !open;
                ctx.memory_mut(|m| m.data.insert_persisted(about_open_id, open));
            }
        });

    let about_open =
        ctx.memory_mut(|m| m.data.get_persisted::<bool>(about_open_id).unwrap_or(false));
    if about_open {
        let mut open = true;
        egui::Window::new("About Blackpoint")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("BLACKPOINT V2.4.0-STABLE")
                            .strong()
                            .size(18.0)
                            .color(t.primary),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Static analysis workbench for reverse engineering, malware triage, and binary inspection.")
                            .small()
                            .color(t.muted),
                    );
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(RichText::new("Supported formats").strong().color(t.text));
                    ui.label(
                        RichText::new("PE, ELF, Mach-O, DEX, APK, IPA, JAR, ZIP, ISO9660, MS-DOS, COM, LE/LX, NPM, Amiga hunk, raw binary")
                            .small()
                            .color(t.muted),
                    );
                    ui.add_space(8.0);
                    ui.label(RichText::new("Built with Rust + eframe/egui").small().color(t.muted));
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        open = false;
                    }
                });
            });
        if !open {
            ctx.memory_mut(|m| m.data.insert_persisted(about_open_id, false));
        }
    }
}

fn paint_icon(
    painter: &egui::Painter,
    rect: egui::Rect,
    icon: AppIcon,
    color: Color32,
    stroke_width: f32,
) {
    let stroke = egui::Stroke::new(stroke_width, color);
    let c = rect.center();
    let w = rect.width();
    let h = rect.height();
    let left = rect.left();
    let right = rect.right();
    let top = rect.top();
    let bottom = rect.bottom();
    let mid_y = c.y;
    let mid_x = c.x;

    match icon {
        AppIcon::Terminal => {
            painter.rect_stroke(rect, 3.0, stroke, egui::StrokeKind::Inside);
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.2, top + h * 0.3),
                    egui::pos2(left + w * 0.38, mid_y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.38, mid_y),
                    egui::pos2(left + w * 0.2, bottom - h * 0.3),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.5, bottom - h * 0.28),
                    egui::pos2(right - w * 0.18, bottom - h * 0.28),
                ],
                stroke,
            );
        }
        AppIcon::Info => {
            painter.circle_stroke(c, w.min(h) * 0.48, stroke);
            painter.circle_filled(egui::pos2(mid_x, top + h * 0.26), stroke_width * 0.9, color);
            painter.line_segment(
                [
                    egui::pos2(mid_x, top + h * 0.42),
                    egui::pos2(mid_x, bottom - h * 0.22),
                ],
                stroke,
            );
        }
        AppIcon::Package => {
            painter.rect_stroke(
                rect.shrink2(egui::vec2(w * 0.12, h * 0.12)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.18, mid_y),
                    egui::pos2(right - w * 0.18, mid_y),
                ],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(mid_x, top + h * 0.18), egui::pos2(mid_x, mid_y)],
                stroke,
            );
        }
        AppIcon::Code => {
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.38, top + h * 0.22),
                    egui::pos2(left + w * 0.18, mid_y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.18, mid_y),
                    egui::pos2(left + w * 0.38, bottom - h * 0.22),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - w * 0.38, top + h * 0.22),
                    egui::pos2(right - w * 0.18, mid_y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - w * 0.18, mid_y),
                    egui::pos2(right - w * 0.38, bottom - h * 0.22),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x + w * 0.08, top + h * 0.18),
                    egui::pos2(mid_x - w * 0.08, bottom - h * 0.18),
                ],
                stroke,
            );
        }
        AppIcon::Cube => {
            painter.rect_stroke(
                rect.shrink2(egui::vec2(w * 0.18, h * 0.18)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.3, top + h * 0.22),
                    egui::pos2(left + w * 0.18, top + h * 0.34),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - w * 0.3, top + h * 0.22),
                    egui::pos2(right - w * 0.18, top + h * 0.34),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.3, bottom - h * 0.22),
                    egui::pos2(left + w * 0.18, bottom - h * 0.34),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - w * 0.3, bottom - h * 0.22),
                    egui::pos2(right - w * 0.18, bottom - h * 0.34),
                ],
                stroke,
            );
        }
        AppIcon::Grid => {
            for row in 0..2 {
                for col in 0..2 {
                    let cell = egui::Rect::from_min_size(
                        egui::pos2(
                            left + w * 0.1 + col as f32 * w * 0.42,
                            top + h * 0.1 + row as f32 * h * 0.42,
                        ),
                        egui::vec2(w * 0.26, h * 0.26),
                    );
                    painter.rect_stroke(cell, 2.0, stroke, egui::StrokeKind::Inside);
                }
            }
        }
        AppIcon::Download => {
            painter.line_segment(
                [
                    egui::pos2(mid_x, top + h * 0.14),
                    egui::pos2(mid_x, bottom - h * 0.28),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, bottom - h * 0.28),
                    egui::pos2(mid_x - w * 0.18, bottom - h * 0.46),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, bottom - h * 0.28),
                    egui::pos2(mid_x + w * 0.18, bottom - h * 0.46),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.18, bottom - h * 0.14),
                    egui::pos2(right - w * 0.18, bottom - h * 0.14),
                ],
                stroke,
            );
        }
        AppIcon::Upload => {
            painter.line_segment(
                [
                    egui::pos2(mid_x, bottom - h * 0.14),
                    egui::pos2(mid_x, top + h * 0.28),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, top + h * 0.28),
                    egui::pos2(mid_x - w * 0.18, top + h * 0.46),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, top + h * 0.28),
                    egui::pos2(mid_x + w * 0.18, top + h * 0.46),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.18, bottom - h * 0.14),
                    egui::pos2(right - w * 0.18, bottom - h * 0.14),
                ],
                stroke,
            );
        }
        AppIcon::Keyboard => {
            painter.rect_stroke(
                rect.shrink2(egui::vec2(w * 0.08, h * 0.2)),
                3.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            for row in 0..2 {
                for col in 0..4 {
                    let key = egui::Rect::from_min_size(
                        egui::pos2(
                            left + w * 0.18 + col as f32 * w * 0.16,
                            top + h * 0.32 + row as f32 * h * 0.18,
                        ),
                        egui::vec2(w * 0.08, h * 0.08),
                    );
                    painter.rect_filled(key, 1.0, color);
                }
            }
        }
        AppIcon::Shield => {
            let points = vec![
                egui::pos2(mid_x, top + h * 0.08),
                egui::pos2(right - w * 0.18, top + h * 0.22),
                egui::pos2(right - w * 0.24, bottom - h * 0.26),
                egui::pos2(mid_x, bottom - h * 0.08),
                egui::pos2(left + w * 0.24, bottom - h * 0.26),
                egui::pos2(left + w * 0.18, top + h * 0.22),
            ];
            painter.add(egui::Shape::closed_line(points, stroke));
        }
        AppIcon::Chart => {
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.12, bottom - h * 0.14),
                    egui::pos2(left + w * 0.36, mid_y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.36, mid_y),
                    egui::pos2(left + w * 0.56, bottom - h * 0.36),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.56, bottom - h * 0.36),
                    egui::pos2(right - w * 0.1, top + h * 0.18),
                ],
                stroke,
            );
        }
        AppIcon::Archive => {
            let box_rect = rect.shrink2(egui::vec2(w * 0.12, h * 0.18));
            painter.rect_stroke(box_rect, 2.0, stroke, egui::StrokeKind::Inside);
            painter.line_segment(
                [
                    egui::pos2(box_rect.left(), box_rect.top() + h * 0.16),
                    egui::pos2(box_rect.right(), box_rect.top() + h * 0.16),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x - w * 0.1, box_rect.top() + h * 0.08),
                    egui::pos2(mid_x + w * 0.1, box_rect.top() + h * 0.08),
                ],
                stroke,
            );
        }
        AppIcon::FileOpen | AppIcon::UploadFile => {
            let page = egui::Rect::from_min_max(
                egui::pos2(left + w * 0.18, top + h * 0.1),
                egui::pos2(right - w * 0.18, bottom - h * 0.12),
            );
            painter.rect_stroke(page, 2.0, stroke, egui::StrokeKind::Inside);
            painter.line_segment(
                [
                    egui::pos2(page.right() - w * 0.18, page.top()),
                    egui::pos2(page.right(), page.top() + h * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(page.right() - w * 0.18, page.top()),
                    egui::pos2(page.right() - w * 0.18, page.top() + h * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(page.right() - w * 0.18, page.top() + h * 0.18),
                    egui::pos2(page.right(), page.top() + h * 0.18),
                ],
                stroke,
            );
            if matches!(icon, AppIcon::FileOpen) {
                painter.line_segment(
                    [
                        egui::pos2(mid_x - w * 0.12, bottom - h * 0.28),
                        egui::pos2(mid_x + w * 0.12, bottom - h * 0.28),
                    ],
                    stroke,
                );
                painter.line_segment(
                    [
                        egui::pos2(mid_x + w * 0.12, bottom - h * 0.28),
                        egui::pos2(mid_x + w * 0.02, bottom - h * 0.4),
                    ],
                    stroke,
                );
            } else {
                painter.line_segment(
                    [
                        egui::pos2(mid_x, bottom - h * 0.22),
                        egui::pos2(mid_x, mid_y),
                    ],
                    stroke,
                );
                painter.line_segment(
                    [
                        egui::pos2(mid_x, mid_y),
                        egui::pos2(mid_x - w * 0.12, mid_y + h * 0.12),
                    ],
                    stroke,
                );
                painter.line_segment(
                    [
                        egui::pos2(mid_x, mid_y),
                        egui::pos2(mid_x + w * 0.12, mid_y + h * 0.12),
                    ],
                    stroke,
                );
            }
        }
        AppIcon::DragPan => {
            painter.line_segment(
                [
                    egui::pos2(mid_x, top + h * 0.12),
                    egui::pos2(mid_x, bottom - h * 0.12),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.12, mid_y),
                    egui::pos2(right - w * 0.12, mid_y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, top + h * 0.12),
                    egui::pos2(mid_x - w * 0.12, top + h * 0.24),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, top + h * 0.12),
                    egui::pos2(mid_x + w * 0.12, top + h * 0.24),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, bottom - h * 0.12),
                    egui::pos2(mid_x - w * 0.12, bottom - h * 0.24),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(mid_x, bottom - h * 0.12),
                    egui::pos2(mid_x + w * 0.12, bottom - h * 0.24),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.12, mid_y),
                    egui::pos2(left + w * 0.24, mid_y - h * 0.12),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.12, mid_y),
                    egui::pos2(left + w * 0.24, mid_y + h * 0.12),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - w * 0.12, mid_y),
                    egui::pos2(right - w * 0.24, mid_y - h * 0.12),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - w * 0.12, mid_y),
                    egui::pos2(right - w * 0.24, mid_y + h * 0.12),
                ],
                stroke,
            );
        }
        AppIcon::Bolt => {
            let points = vec![
                egui::pos2(mid_x - w * 0.08, top + h * 0.1),
                egui::pos2(mid_x + w * 0.02, top + h * 0.1),
                egui::pos2(mid_x - w * 0.04, mid_y),
                egui::pos2(mid_x + w * 0.1, mid_y),
                egui::pos2(mid_x - w * 0.02, bottom - h * 0.1),
                egui::pos2(mid_x + w * 0.02, bottom - h * 0.1),
            ];
            painter.add(egui::Shape::convex_polygon(
                points,
                color,
                egui::Stroke::NONE,
            ));
        }
        AppIcon::Analytics => {
            for (idx, bar) in [0.38, 0.62, 0.82].iter().enumerate() {
                let bar_rect = egui::Rect::from_min_max(
                    egui::pos2(left + w * (0.16 + idx as f32 * 0.22), bottom - h * *bar),
                    egui::pos2(left + w * (0.28 + idx as f32 * 0.22), bottom - h * 0.14),
                );
                painter.rect_filled(bar_rect, 1.5, color);
            }
        }
        AppIcon::DataObject => {
            painter.text(
                c,
                egui::Align2::CENTER_CENTER,
                "{}",
                egui::FontId::monospace((w * 0.72).max(10.0)),
                color,
            );
        }
        AppIcon::Memory => {
            let chip = rect.shrink2(egui::vec2(w * 0.22, h * 0.22));
            painter.rect_stroke(chip, 2.0, stroke, egui::StrokeKind::Inside);
            for idx in 0..4 {
                let x = chip.left() + idx as f32 * chip.width() / 3.0;
                painter.line_segment(
                    [
                        egui::pos2(x, chip.top()),
                        egui::pos2(x, chip.top() - h * 0.12),
                    ],
                    stroke,
                );
                painter.line_segment(
                    [
                        egui::pos2(x, chip.bottom()),
                        egui::pos2(x, chip.bottom() + h * 0.12),
                    ],
                    stroke,
                );
            }
            for idx in 0..4 {
                let y = chip.top() + idx as f32 * chip.height() / 3.0;
                painter.line_segment(
                    [
                        egui::pos2(chip.left(), y),
                        egui::pos2(chip.left() - w * 0.12, y),
                    ],
                    stroke,
                );
                painter.line_segment(
                    [
                        egui::pos2(chip.right(), y),
                        egui::pos2(chip.right() + w * 0.12, y),
                    ],
                    stroke,
                );
            }
        }
        AppIcon::Password => {
            for idx in 0..3 {
                let dot = egui::Rect::from_center_size(
                    egui::pos2(left + w * (0.24 + idx as f32 * 0.26), mid_y),
                    egui::vec2(w * 0.12, h * 0.12),
                );
                painter.rect_filled(dot, 2.0, color);
            }
        }
        AppIcon::CheckCircle => {
            painter.circle_stroke(c, w.min(h) * 0.46, stroke);
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.24, mid_y),
                    egui::pos2(left + w * 0.42, bottom - h * 0.28),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.42, bottom - h * 0.28),
                    egui::pos2(right - w * 0.2, top + h * 0.24),
                ],
                stroke,
            );
        }
        AppIcon::User => {
            painter.circle_stroke(egui::pos2(mid_x, top + h * 0.34), w.min(h) * 0.18, stroke);
            painter.add(egui::Shape::closed_line(
                vec![
                    egui::pos2(left + w * 0.22, bottom - h * 0.16),
                    egui::pos2(left + w * 0.34, top + h * 0.62),
                    egui::pos2(right - w * 0.34, top + h * 0.62),
                    egui::pos2(right - w * 0.22, bottom - h * 0.16),
                ],
                stroke,
            ));
        }
        AppIcon::Minimize => {
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.18, bottom - h * 0.2),
                    egui::pos2(right - w * 0.18, bottom - h * 0.2),
                ],
                stroke,
            );
        }
        AppIcon::Maximize => {
            painter.rect_stroke(
                rect.shrink2(egui::vec2(w * 0.2, h * 0.18)),
                1.0,
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        AppIcon::Close => {
            painter.line_segment(
                [
                    egui::pos2(left + w * 0.22, top + h * 0.22),
                    egui::pos2(right - w * 0.22, bottom - h * 0.22),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - w * 0.22, top + h * 0.22),
                    egui::pos2(left + w * 0.22, bottom - h * 0.22),
                ],
                stroke,
            );
        }
    }
}

fn dirs() -> PathBuf {
    let base = std::env::var("APPDATA")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join(".blackpoint")
}

fn load_history(path: &Path) -> Vec<PathBuf> {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json_like_parse(&content))
        .unwrap_or_default()
}

fn save_history(path: &Path, entries: &[PathBuf]) {
    let _ = fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")));
    let json_array: Vec<String> = entries
        .iter()
        .map(|p| {
            format!(
                "\"{}\"",
                p.display()
                    .to_string()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
            )
        })
        .collect();
    let content = format!("[{}]", json_array.join(","));
    let _ = fs::write(path, content.as_bytes());
}

fn serde_json_like_parse(content: &str) -> Option<Vec<PathBuf>> {
    let trimmed = content.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut paths = Vec::new();
    for item in inner.split(',') {
        let item = item
            .trim()
            .trim_matches('"')
            .replace("\\\\", "\\")
            .replace("\\\"", "\"");
        if !item.is_empty() {
            paths.push(PathBuf::from(item));
        }
    }
    Some(paths)
}

#[cfg(test)]
mod tests {
    use super::{
        contains_ascii_case_insensitive, raw_offset_from_rva, resolve_initial_hex_selection,
        string_matches,
    };
    use crate::analyzer::{BinaryReport, ProtectionFlags, SectionInfo};
    use std::path::PathBuf;

    fn sample_report(entry_point: u64) -> BinaryReport {
        BinaryReport {
            path: PathBuf::from("sample.bin"),
            file_size: 0x800,
            raw_bytes: vec![0; 0x800],
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            ascii_string_count: 0,
            utf16_string_count: 0,
            format_name: "PE".to_string(),
            format_family: "Portable Executable".to_string(),
            detection_confidence: "Signature".to_string(),
            machine_type: "x86".to_string(),
            section_count: 1,
            is_64bit: false,
            subsystem: "Windows GUI".to_string(),
            image_base: 0x400000,
            entry_point,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            timestamp: 0,
            sections: vec![SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_address: 0x400,
                raw_size: 0x200,
                characteristics: "EXEC | READ".to_string(),
                entropy: 5.0,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
            rich_headers: Vec::new(),
            dos_header: Vec::new(),
            file_header: Vec::new(),
            optional_header: Vec::new(),
            disassembly: Vec::new(),
            archive_entries: Vec::new(),
            archive_entry_total: 0,
            archive_entries_omitted: 0,
            resource_entries: Vec::new(),
            version_info_rows: Vec::new(),
            pe_metadata_rows: Vec::new(),
            manifest_rows: Vec::new(),
            manifest_text: None,
            notes: Vec::new(),
            protections: ProtectionFlags::default(),
            protection_findings: Vec::new(),
            xor_candidates: Vec::new(),
            xor_patterns: Vec::new(),
            xor_common_key_hits: Vec::new(),
        }
    }

    #[test]
    fn case_insensitive_match_reuses_precomputed_needle() {
        let needle = "kernel32".to_string();
        assert!(string_matches(
            "KERNEL32.dll",
            "kernel32",
            Some(needle.as_str()),
            false,
        ));
        assert!(!string_matches(
            "USER32.dll",
            "kernel32",
            Some(needle.as_str()),
            false,
        ));
    }

    #[test]
    fn ascii_case_insensitive_contains_handles_shorter_haystacks() {
        assert!(!contains_ascii_case_insensitive("pe", "portable"));
        assert!(contains_ascii_case_insensitive(
            "PortableExecutable",
            "exec"
        ));
    }

    #[test]
    fn raw_offset_translation_rejects_virtual_only_section_tail() {
        let report = sample_report(0x1300);
        assert_eq!(raw_offset_from_rva(&report, 0x1300), None);
    }

    #[test]
    fn entry_hex_selection_falls_back_to_nearest_file_backed_offset() {
        let report = sample_report(0x1300);
        let selection = resolve_initial_hex_selection(&report);
        assert_eq!(selection.offset, 0x400);
        assert!(selection
            .status
            .as_deref()
            .is_some_and(|status| status.contains("virtual-only tail")));
    }
}
