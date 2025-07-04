/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2025 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use log::{LevelFilter, Log, Metadata, Record};
use simplelog::{CombinedLogger, Config, ConfigBuilder, SharedLogger};

#[cfg(feature = "enable-filelog")]
use {
    file_rotate::{compression::Compression, suffix::AppendCount, ContentLimit, FileRotate},
    simplelog::WriteLogger,
    std::{path::PathBuf, thread::sleep, time::Duration},
};

// Measured in bytes
#[cfg(feature = "enable-filelog")]
const LOGFILE_MAXSIZE: usize = 5_000_000;

static MUTED_TARGETS: &[&'static str] = &[
    "sled",
    "rustls",
    "net::channel",
    "net::message_publisher",
    "net::hosts",
    "net::protocol",
    "net::session",
    "net::outbound_session",
    "net::tcp",
    "net::p2p::seed",
    "net::refinery::handshake_node()",
    "system::publisher",
    "event_graph::dag_sync()",
    "event_graph::dag_insert()",
    "event_graph::protocol",
];

static ALLOW_TRACE: &[&'static str] = &["ui", "app", "gfx"];

#[cfg(all(target_os = "android", feature = "enable-filelog"))]
fn logfile_path() -> PathBuf {
    use crate::android::get_external_storage_path;
    get_external_storage_path().join("darkfi-app.log")
}

#[cfg(all(not(target_os = "android"), feature = "enable-filelog"))]
fn logfile_path() -> PathBuf {
    dirs::cache_dir().unwrap().join("darkfi/darkfi-app.log")
}

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use android_logger::{AndroidLogger, Config as AndroidConfig};

    /// Implements a wrapper around the android logger so it's compatible with simplelog.
    pub struct AndroidLoggerWrapper {
        logger: AndroidLogger,
        level: LevelFilter,
        config: Config,
    }

    impl AndroidLoggerWrapper {
        pub fn new(level: LevelFilter, config: Config) -> Box<Self> {
            let cfg = AndroidConfig::default().with_max_level(level).with_tag("darkfi");
            Box::new(Self { logger: AndroidLogger::new(cfg), level, config })
        }
    }

    impl Log for AndroidLoggerWrapper {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            let target = metadata.target();
            for allow in ALLOW_TRACE {
                if target.starts_with(allow) {
                    return true
                }
            }
            for muted in MUTED_TARGETS {
                if target.starts_with(muted) {
                    return false
                }
            }
            if metadata.level() > self.level {
                return false
            }
            self.logger.enabled(metadata)
        }

        fn log(&self, record: &Record<'_>) {
            if self.enabled(record.metadata()) {
                self.logger.log(record)
            }
        }

        fn flush(&self) {}
    }

    impl SharedLogger for AndroidLoggerWrapper {
        fn level(&self) -> LevelFilter {
            self.level
        }

        fn config(&self) -> Option<&Config> {
            Some(&self.config)
        }

        fn as_log(self: Box<Self>) -> Box<dyn Log> {
            Box::new(*self)
        }
    }
}

#[cfg(not(target_os = "android"))]
mod desktop {
    use super::*;
    use simplelog::{ColorChoice, TermLogger, TerminalMode};

    /// Implements a wrapper around the android logger so it's compatible with simplelog.
    pub struct CustomTermLogger {
        logger: TermLogger,
    }

    impl CustomTermLogger {
        pub fn new(_level: LevelFilter, cfg: Config) -> Box<Self> {
            let logger =
                TermLogger::new(LevelFilter::Trace, cfg, TerminalMode::Mixed, ColorChoice::Auto);
            Box::new(Self { logger: *logger })
        }
    }

    impl Log for CustomTermLogger {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            let target = metadata.target();
            for allow in ALLOW_TRACE {
                if target.starts_with(allow) {
                    return true
                }
            }
            for muted in MUTED_TARGETS {
                if target.starts_with(muted) && metadata.level() > LevelFilter::Info {
                    return false
                }
            }
            if metadata.level() > self.level() {
                return false
            }
            self.logger.enabled(metadata)
        }

        fn log(&self, record: &Record<'_>) {
            if self.enabled(record.metadata()) {
                self.logger.log(record)
            }
        }

        fn flush(&self) {
            self.logger.flush()
        }
    }

    impl SharedLogger for CustomTermLogger {
        fn level(&self) -> LevelFilter {
            self.logger.level()
        }

        fn config(&self) -> Option<&Config> {
            self.logger.config()
        }

        fn as_log(self: Box<Self>) -> Box<dyn Log> {
            Box::new(self.logger).as_log()
        }
    }
}

pub fn setup_logging() {
    // https://gist.github.com/jb-alvarado/6e223936446bb88cd9a93e7028fc2c4f
    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![];

    let mut cfg = ConfigBuilder::new();

    #[cfg(feature = "enable-filelog")]
    {
        let mut cfg = cfg.clone();
        cfg.add_filter_ignore_str("sled");
        cfg.add_filter_ignore_str("rustls");
        let cfg = cfg.build();

        let log_file = FileRotate::new(
            logfile_path(),
            AppendCount::new(0),
            ContentLimit::BytesSurpassed(LOGFILE_MAXSIZE),
            Compression::None,
            #[cfg(unix)]
            None,
        );
        let file_logger = WriteLogger::new(LevelFilter::Trace, cfg, log_file);
        loggers.push(file_logger);
    }

    let cfg = cfg.build();

    #[cfg(target_os = "android")]
    {
        use android::AndroidLoggerWrapper;
        let android_logger = AndroidLoggerWrapper::new(LevelFilter::Trace, cfg);
        loggers.push(android_logger);
    }

    #[cfg(not(target_os = "android"))]
    {
        use desktop::CustomTermLogger;

        // For ANSI colors in the terminal
        colored::control::set_override(true);

        let term_logger = CustomTermLogger::new(LevelFilter::Debug, cfg);
        loggers.push(term_logger);
    }

    CombinedLogger::init(loggers).expect("logger");
}
