pub use tracing;
pub use tracing_subscriber::*;

use std::error::Error as _;

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

pub fn init(default_level: &str) {
    if tracing::dispatcher::has_been_set() {
        return;
    }

    if let Ok(val) = std::env::var("RUST_LOG")
        && (val.eq_ignore_ascii_case("off") || val.eq_ignore_ascii_case("none"))
    {
        return;
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|e| {
        if matches!(e.source(), Some(s) if s.is::<tracing_subscriber::filter::ParseError>()) {
            eprintln!("Could not parse `RUST_LOG` environment variable: {e}");
        }
        EnvFilter::new(default_level)
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .map_fmt_fields(tracing_subscriber::field::MakeExt::debug_alt)
                .with_writer(std::io::stderr),
        )
        .init();
}
