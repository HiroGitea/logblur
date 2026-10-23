//! logblur 图形界面：把日志压缩包拖进窗口，得到清洗后的压缩包。
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;

use eframe::egui;

fn main() -> eframe::Result {
    // LOGBLUR_LANG / LANGUAGE / LC_ALL / LANG 优先，其次是系统区域设置
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
