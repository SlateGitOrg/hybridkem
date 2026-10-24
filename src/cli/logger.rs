//! A minimal `log` backend that writes to stderr (keeps the dependency tree small).

use log::{Level, LevelFilter, Log, Metadata, Record};

struct StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            let tag = match record.level() {
                Level::Error => "error",
                Level::Warn => "warn",
                Level::Info => "info",
                Level::Debug => "debug",
                Level::Trace => "trace",
            };
            eprintln!("[{tag}] {}", record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

/// Install the logger; `verbosity` 0 = warnings, 1 = info, 2+ = debug.
pub fn init(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };
    // Ignoring the error is correct: it only fails if a logger is already installed.
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(level);
}
