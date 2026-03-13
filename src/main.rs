mod analyzer;
mod app;

use app::BlackpointApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 820.0])
            .with_min_inner_size([960.0, 680.0])
            .with_title("Blackpoint")
            .with_decorations(false)
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "Blackpoint",
        options,
        Box::new(|cc| Ok(Box::new(BlackpointApp::new(cc)))),
    )
}
