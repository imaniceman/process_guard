mod system_info_printer;
mod config_manager;

use std::ffi::OsString;
use std::{thread};
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
use log::{info, warn, error};
use log4rs::{
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
};
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::RollingFileAppender;
use winapi::um::processthreadsapi::{OpenProcess};
use winapi::um::psapi::{EnumProcessModules, EnumProcesses, GetModuleBaseNameW, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::um::errhandlingapi::GetLastError;
use crate::config_manager::{Config, ProcessType};
use crate::system_info_printer::{print_all_system_info, print_memory_status};

const SERVICE_NAME: &str = "ProcessMonitorService";
// const DEFAULT_MEMORY_THRESHOLD: u64 = 1000 * 1024 * 1024; // 1000 MB in bytes
const CONFIG_FILE_NAME: &str = "process_guard_config.json";

define_windows_service!(ffi_service_main, service_main);

struct MemoryInfo {
    private_bytes: usize,
    working_set: usize,
}
fn get_process_memory_info(pid: DWORD) -> Option<MemoryInfo> {
    let mut result = MemoryInfo {
        private_bytes: 0,
        working_set: 0,
    };
    unsafe {
        // 打开进程
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if process_handle.is_null() {
            let error_code = GetLastError();
            error!("Failed to open process: {}. Error code: {}", pid,error_code);
            return None;
        }

        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();

        // 获取进程的内存信息
        if GetProcessMemoryInfo(
            process_handle,
            &mut pmc,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) != 0
        {
            info!("Working Set Size: {} MB", pmc.WorkingSetSize / 1024 / 1024);
            info!("Private Bytes: {} MB", pmc.PagefileUsage / 1024 / 1024);
            result.private_bytes = pmc.PagefileUsage;
            result.working_set = pmc.WorkingSetSize;
        } else {
            error!("Failed to get process memory information");
        }

        // 关闭进程句柄
        CloseHandle(process_handle);
    }
    Some(result)
}

/// 获取进程运行状态,返回 PID
///
/// # Arguments
///
/// * `name`:
///
/// returns: Option<u32>
///
/// # Examples
///
/// ```
///
/// ```
fn is_process_running(name: &str) -> Option<DWORD> {
    let mut process_ids: [DWORD; 1024] = [0; 1024];
    let mut bytes_returned: DWORD = 0;

    unsafe {
        if EnumProcesses(
            process_ids.as_mut_ptr(),
            std::mem::size_of_val(&process_ids) as DWORD,
            &mut bytes_returned,
        ) == 0
        {
            error!("Failed to enumerate processes");
            return None;
        }

        let num_processes = bytes_returned / std::mem::size_of::<DWORD>() as DWORD;

        for i in 0..num_processes as usize {
            let pid = process_ids[i];
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if process_handle.is_null() {
                continue;
            }

            let mut module: HMODULE = std::ptr::null_mut();
            let mut cb_needed: DWORD = 0;
            if EnumProcessModules(process_handle, &mut module, std::mem::size_of::<HMODULE>() as DWORD, &mut cb_needed) != 0 {
                let mut process_name: [u16; 260] = [0; 260];
                if GetModuleBaseNameW(process_handle, module, process_name.as_mut_ptr(), process_name.len() as DWORD) > 0 {
                    let process_name = String::from_utf16_lossy(&process_name);
                    if process_name.trim_end_matches('\0').eq_ignore_ascii_case(name) {
                        CloseHandle(process_handle);
                        return Some(pid);
                    }
                }
            }
            CloseHandle(process_handle);
        }
    }
    None
}

fn restart_processing(name: &str, process_type: &ProcessType) {
    info!("正在重启 {} 进程...",name);
    let result = process_type.kill_process(name);
    match result {
        Err(e) => {
            error!("执行 taskkill 命令失败: {:?}", e);
            return;
        }
        Ok(output) => info!("成功执行 taskkill 命令: {:?}", output),
    }

    let result = process_type.execute();
    match result {
        Ok(output) => {info!("成功执行命令:{:?}",output)}
        Err(error) => {error!("执行命令失败：{:?}",error)}
    }
    // 等待 10 s
    thread::sleep(Duration::from_secs(10));
    if is_process_running(name).is_some() {
        info!("{} 进程已成功重启",name);
    } else {
        warn!("{} 进程未自动重启，等待系统处理...",name);
        let mut loop_count = 0;
        loop {
            thread::sleep(Duration::from_secs(1));
            if is_process_running(name).is_some() {
                info!("{} 进程已成功启动",name);
                break;
            }
            loop_count += 1;
            if loop_count > 30 {
                warn!("{} 进程未自动重启，等待系统处理...",name);
                break;
            }
        }
    }
}

fn monitor_process(config: &Config) {
    for process in config.get_monitor_processes() {
        if let Some(pid) = is_process_running(&process.name) {
            info!("{} 进程 ID: {}, memory_threshold_MB：{}", &process.name,pid,process.memory_threshold_bytes/1024/1024);
            let info = get_process_memory_info(pid).unwrap_or(MemoryInfo { private_bytes: 0, working_set: 0 });
            let private_bytes = info.private_bytes as u64;
            if private_bytes > process.memory_threshold_bytes {
                warn!("内存使用超过阈值 {} MB，正在重启 {}", process.memory_threshold_bytes / 1024 / 1024,&process.name);
                restart_processing(&process.name, &process.process_type);
            }
        } else {
            warn!("未找到 {} 进程...",&process.name);
            if process.auto_start {
                info!("正在启动 {} 进程...", &process.name);
                let result = process.process_type.execute();
                match result {
                    Ok(output) => {info!("成功执行命令:{:?}",output)}
                    Err(error) => {error!("执行命令失败：{:?}",error)}
                }
            }
        }
    }
}

fn monitor_processes() {
    // let memory_threshold = get_memory_threshold();
    // 在当前路径下
    let mut current_path = std::env::current_exe().unwrap();
    current_path.set_file_name(CONFIG_FILE_NAME);
    let config_manager = config_manager::ConfigManager::new(current_path);
    let config = config_manager.load_or_create_default();
    loop {
        monitor_process(&config);
        print_memory_status();
        thread::sleep(Duration::from_secs(config.interval_seconds));
    }
}

fn configure_logging() -> Result<(), Box<dyn std::error::Error>> {
    let mut log_path = std::env::current_exe()?;
    log_path.set_file_name("process_guard.log");

    let window_roller = FixedWindowRoller::builder()
        .build("process_guard.{}.log", 5)?; // Keep 5 backup files

    let size_trigger = SizeTrigger::new(20 * 1024 * 1024); // Rotate after 10 MB

    let compound_policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(window_roller));

    let logfile = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} - {l} - {m}\n")))
        .build(log_path, Box::new(compound_policy))?;

    let config = log4rs::Config::builder()
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
    info!("{} starting...",SERVICE_NAME);
    print_all_system_info();
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

    monitor_processes();
}

fn main() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}
