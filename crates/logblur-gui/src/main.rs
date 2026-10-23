//! logblur GUI: drop a log archive onto the window and get a scrubbed archive back.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;

use eframe::egui;

fn main() -> eframe::Result {
    // LOGBLUR_LANG / LANGUAGE / LC_ALL / LANG take precedence, then the system locale
    logblur_core::i18n::init(None, sys_locale::get_locale().as_deref());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(logblur_core::t!("gui.title"))
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([760.0, 520.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native("logblur", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
