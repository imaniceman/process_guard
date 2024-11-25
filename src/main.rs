mod config_manager;
mod logging;
mod process_manager;
mod system_info_printer;
mod tests;
mod db_manager;

use log::{error, info};
use process_manager::monitor_processes;
use std::ffi::OsString;
use std::time::Duration;
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
    monitor_processes(&config);
}

fn main() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}
