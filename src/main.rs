mod config_manager;
mod db_manager;
mod logging;
mod process_manager;
mod system_info_printer;
mod tests;

use log::{error, info};
use process_manager::monitor_processes;
use std::sync::Arc;
use std::time::Duration;
use std::{ffi::OsString, thread};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::config_manager::Config;
use crate::logging::configure_logging;
use crate::system_info_printer::print_all_system_info;

const SERVICE_NAME: &str = "ProcessMonitorService";
const CONFIG_FILE_NAME: &str = "process_guard_config.json";

define_windows_service!(ffi_service_main, service_main);

fn load_config() -> Config {
    let mut current_path = std::env::current_exe().unwrap();
    current_path.set_file_name(CONFIG_FILE_NAME);
    let config_manager = config_manager::ConfigManager::new(current_path);
    config_manager.load_or_create_default()
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = configure_logging() {
        eprintln!("Failed to init logger: {}", e);
        return;
    }
    info!("{} starting...", SERVICE_NAME);
    print_all_system_info();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                info!("Service is stopping...");
                std::process::exit(0); // 立即退出程序
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to register service control handler: {}", e);
            return;
        }
    };

    let next_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    if let Err(e) = status_handle.set_service_status(next_status) {
        error!("Failed to set service status: {}", e);
        return;
    }
    let config = load_config();

    info!("{:#?}", config);
    // 启动一个独立的线程，进行数据库清理工作
    let db_cleanup_interval = config.db_config.cleanup_interval_hours;
    let db_cleanup_hours = config.db_config.db_cleanup_hours;
    let db_vacuum_threshold_mb = config.db_config.db_vacuum_threshold_mb;

    let db_connection = Arc::new(&db_manager::DB_CONNECTION);

    thread::spawn(move || {
        loop {
            {
                info!("Starting database cleanup...");
                let mut db_conn = db_connection.lock().unwrap();
                match db_conn.cleanup_old_data(db_cleanup_hours, db_vacuum_threshold_mb) {
                    Ok(_) => info!("Database cleanup completed successfully."),
                    Err(e) => error!("Database cleanup failed: {}", e),
                }
            }
            // 休眠指定的时间间隔
            thread::sleep(Duration::from_secs((db_cleanup_interval * 3600) as u64));
        }
    });
    monitor_processes(&config);
}

fn main() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}
