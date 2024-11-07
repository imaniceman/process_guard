use log4rs::{
    append::rolling_file::{
        policy::compound::{
            roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger, CompoundPolicy,
        },
        RollingFileAppender,
    },
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
};

pub fn configure_logging() -> Result<(), Box<dyn std::error::Error>> {
    let mut log_path = std::env::current_exe()?;
    log_path.set_file_name("process_guard.log");

    let window_roller = FixedWindowRoller::builder().build("process_guard.{}.log", 5)?; // Keep 5 backup files

    let size_trigger = SizeTrigger::new(20 * 1024 * 1024); // Rotate after 10 MB

    let compound_policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(window_roller));

    let logfile = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} - {l} - {m}\n",
        )))
        .build(log_path, Box::new(compound_policy))?;

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("logfile")
                .build(log::LevelFilter::Info),
        )?;

    log4rs::init_config(config)?;
    Ok(())
}
