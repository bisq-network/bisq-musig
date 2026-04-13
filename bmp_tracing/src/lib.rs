use std::error::Error as _;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

pub use tracing;
pub use tracing_subscriber;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{Layer, fmt};

#[derive(Debug, Clone)]
#[expect(clippy::exhaustive_enums)]
pub enum LogConfig {
    File(PathBuf),
    Stdout,
    Stderr,
}

impl LogConfig {
    pub fn layer<S>(self) -> Box<dyn Layer<S> + Send + Sync + 'static>
    where
        S: tracing_core::Subscriber,
        for<'a> S: LookupSpan<'a>,
    {
        // Shared configuration regardless of where logs are output to.
        let fmt_layer = fmt::layer()
            .with_line_number(true)
            .with_file(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .map_fmt_fields(tracing_subscriber::field::MakeExt::debug_alt);

        match self {
            Self::File(path) => {
                let file = File::create(&path)
                    .unwrap_or_else(|e| panic!("failed to create log file at {e}"));
                Box::new(fmt_layer.with_writer(file))
            }
            Self::Stdout => Box::new(fmt_layer.with_writer(io::stdout)),
            Self::Stderr => Box::new(fmt_layer.with_writer(io::stderr)),
        }
    }
}

/// Initialize tracing with default configuration
pub fn init(default_level: &str) {
    init_with_config(default_level, LogConfig::Stdout);
}

static TRACE_INIT: Mutex<()> = Mutex::new(());

/// Initialize tracing with custom output configuration.
pub fn init_with_config(default_level: &str, config: LogConfig) {
    // ignoring the error from lock with unit type is safe
    let _lock = TRACE_INIT.lock().unwrap_or_else(PoisonError::into_inner);
    if tracing::dispatcher::has_been_set() {
        return;
    }

    // Check if tracing is explicitly disabled
    if let Ok(val) = std::env::var("RUST_LOG")
        && (val.eq_ignore_ascii_case("off") || val.eq_ignore_ascii_case("none"))
    {
        return;
    }

    // Create the filter layer
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|e| {
        if matches!(e.source(), Some(s) if s.is::<tracing_subscriber::filter::ParseError>()) {
            eprintln!("Could not parse `RUST_LOG` environment variable: {e}");
        }
        EnvFilter::new(default_level)
    });

    // Build and init the subscriber
    tracing_subscriber::registry()
        .with(filter)
        .with(config.layer())
        .init();
}
