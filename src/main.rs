use std::ffi::OsString;
use std::process::Command;
use std::thread;
use std::time::Duration;
// use sysinfo::{ProcessExt, System, SystemExt};
use sysinfo::{System};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use log::{info, warn, error};
use log4rs::{
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::RollingFileAppender;

const SERVICE_NAME: &str = "DWMMonitorService";
const MEMORY_THRESHOLD: u64 = 1000 * 1024 * 1024; // 1000 MB in bytes
const INTERVAL: u64 = 60; // 60 seconds

define_windows_service!(ffi_service_main, service_main);

fn restart_dwm() {
    info!("正在重启 dwm.exe 进程...");

    // 首先尝试结束 dwm.exe 进程
    match Command::new("taskkill").args(&["/F", "/IM", "dwm.exe"]).output() {
        Ok(_) => info!("成功执行 taskkill 命令"),
        Err(e) => error!("执行 taskkill 命令失败: {}", e),
    }

    // 等待一段时间，让系统有机会自动重启 dwm.exe
    let wait_time = Duration::from_secs(10); // 等待10秒
    info!("等待系统自动重启 dwm.exe，等待时间：{} 秒", wait_time.as_secs());
    thread::sleep(wait_time);

    // 检查 dwm.exe 是否已经重启
    let mut system = System::new_all();
    system.refresh_all();

    if system.processes_by_exact_name("dwm.exe".as_ref()).next().is_some() {
        info!("dwm.exe 已成功重启");
    } else {
        warn!("dwm.exe 未自动重启，等待系统处理...");
        // 持续检查，直到 dwm.exe 重新出现
        loop {
            thread::sleep(Duration::from_secs(1));
            system.refresh_all();
            if system.processes_by_exact_name("dwm.exe".as_ref()).next().is_some() {
                info!("dwm.exe 已成功启动");
                break;
            }
        }
    }
}

fn wait_for_dwm_restart() {
    let mut system = System::new_all();

    loop {
        system.refresh_all();
        if system.processes_by_exact_name("dwm.exe".as_ref()).next().is_some() {
            info!("dwm.exe 进程已成功启动");
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
}
fn monitor_dwm() {
    let mut system = System::new_all();

    loop {
        system.refresh_all();

        match system.processes_by_exact_name("dwm.exe".as_ref()).next() {
            Some(process) => {
                let memory_usage = process.memory();
                info!("当前 dwm.exe 内存使用: {} MB", memory_usage / 1024 / 1024);

                if memory_usage > MEMORY_THRESHOLD {
                    warn!("内存使用超过阈值 {} MB，正在重启 dwm.exe", MEMORY_THRESHOLD / 1024 / 1024);
                    restart_dwm();
                }
            }
            None => {
                warn!("未找到 dwm.exe 进程，等待系统自动重启...");
                wait_for_dwm_restart();
            }
        }
        thread::sleep(Duration::from_secs(INTERVAL));
    }
}
fn configure_logging() -> Result<(), Box<dyn std::error::Error>> {
    let mut log_path = std::env::current_exe()?;
    log_path.set_file_name("dwm_monitor.log");

    let window_roller = FixedWindowRoller::builder()
        .build("dwm_monitor.{}.log", 5)?; // Keep 5 backup files

    let size_trigger = SizeTrigger::new(20 * 1024 * 1024); // Rotate after 10 MB

    let compound_policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(window_roller));

    let logfile = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} - {l} - {m}\n")))
        .build(log_path, Box::new(compound_policy))?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(log::LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = configure_logging() {
        eprintln!("Failed to init logger: {}", e);
        return;
    }
    info!("DWM Monitor Service starting...");

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                info!("Service is stopping...");
                // ServiceControlHandlerResult::NoError
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

    monitor_dwm();
}

fn main() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}
