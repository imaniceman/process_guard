use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{
    ffi::OsStr, io, os::windows::ffi::OsStrExt, process::Command, ptr::null_mut, thread,
    time::Duration,
};
use winapi::{
    shared::minwindef::{DWORD, HMODULE},
    um::{
        handleapi::CloseHandle,
        processthreadsapi::{CreateProcessAsUserW, OpenProcess, PROCESS_INFORMATION, STARTUPINFOW},
        psapi::{
            EnumProcessModules, EnumProcesses, GetModuleBaseNameW, GetProcessMemoryInfo,
            PROCESS_MEMORY_COUNTERS,
        },
        securitybaseapi::DuplicateTokenEx,
        tlhelp32::*,
        userenv::CreateEnvironmentBlock,
        winbase::CREATE_UNICODE_ENVIRONMENT,
        winnt::*,
        wtsapi32::*,
    },
};

use crate::config_manager::Config;
use crate::db_manager::DB_CONNECTION;
use crate::system_info_printer::print_memory_status;
use log::{error, info, warn};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
#[derive(Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: DWORD,
    pub thread_count: i32,
    pub private_bytes: usize,
    pub working_set: usize,
}

impl ProcessInfo {
    fn print_process_memory_info(&self) {
        info!("Working Set Size: {} MB", self.working_set / 1024 / 1024);
        info!("Private Bytes: {} MB", self.private_bytes / 1024 / 1024);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ProcessType {
    System,
    Service(String),
    User(String, u32),
}
impl Default for ProcessType {
    fn default() -> Self {
        ProcessType::System
    }
}
impl ProcessType {
    fn execute_cmd(cmd: &str) -> Result<String, io::Error> {
        let output = Command::new("powershell")
            .args(&["-Command", cmd])
            .output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Command execution failed with error: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ))
        }
    }

    pub fn kill_process(&self, name: &str) -> Result<String, io::Error> {
        let terminate_cmd = format!("taskkill /F /IM {}", name);
        ProcessType::execute_cmd(&terminate_cmd)
    }

    pub fn execute(&self) -> Result<String, io::Error> {
        match self {
            ProcessType::System => Ok("".to_string()),
            ProcessType::Service(cmd) => ProcessType::execute_cmd(cmd),
            ProcessType::User(cmd, sid) => {
                ProcessType::launch_process_as_user(*sid, cmd)?;
                Ok("".to_string())
            }
        }
    }

    fn launch_process_as_user(session_id: u32, powershell_cmd: &str) -> Result<(), io::Error> {
        let full_command = format!("powershell -Command \"{}\"", powershell_cmd);
        unsafe {
            println!("Launching process as user: {}", full_command);
            let mut h_token = null_mut();
            if WTSQueryUserToken(session_id, &mut h_token) == 0 {
                return Err(io::Error::last_os_error());
            }
            println!("WTSQueryUserToken success");
            let mut duplicate_token = null_mut();
            if DuplicateTokenEx(
                h_token,
                MAXIMUM_ALLOWED,
                null_mut(),
                SecurityIdentification,
                TokenPrimary,
                &mut duplicate_token,
            ) == 0
            {
                CloseHandle(h_token);
                return Err(io::Error::last_os_error());
            }
            println!("DuplicateTokenEx success");
            let mut env_block = std::ptr::null_mut();
            if CreateEnvironmentBlock(&mut env_block, duplicate_token, 0) == 0 {
                CloseHandle(h_token);
                CloseHandle(duplicate_token);
                return Err(io::Error::last_os_error());
            }
            println!("CreateEnvironmentBlock success");
            let mut startup_info = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                lpDesktop: to_wide_string("winsta0\\default").as_ptr() as *mut u16,
                lpReserved: null_mut(),
                lpTitle: null_mut(),
                dwX: 0,
                dwY: 0,
                dwXSize: 0,
                dwYSize: 0,
                dwXCountChars: 0,
                dwYCountChars: 0,
                dwFillAttribute: 0,
                dwFlags: 0,
                wShowWindow: 0,
                cbReserved2: 0,
                lpReserved2: null_mut(),
                hStdInput: null_mut(),
                hStdOutput: null_mut(),
                hStdError: null_mut(),
            };
            let mut process_info = PROCESS_INFORMATION {
                hProcess: null_mut(),
                hThread: null_mut(),
                dwProcessId: 0,
                dwThreadId: 0,
            };
            let command_line = to_wide_string(&full_command);
            let success = CreateProcessAsUserW(
                duplicate_token,
                null_mut(),
                command_line.as_ptr() as *mut u16,
                null_mut(),
                null_mut(),
                0,
                CREATE_UNICODE_ENVIRONMENT,
                env_block,
                null_mut(),
                &mut startup_info,
                &mut process_info,
            );
            CloseHandle(h_token);
            CloseHandle(duplicate_token);
            if success == 0 {
                return Err(io::Error::last_os_error());
            }
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
        }
        Ok(())
    }
}

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub fn is_process_running(name: &str, processes: &[ProcessInfo]) -> Option<ProcessInfo> {
    for process in processes {
        if process.name.eq_ignore_ascii_case(name) {
            return Some(process.clone());
        }
    }
    None
}

pub fn restart_processing(name: &str, process_type: &ProcessType) {
    info!("正在重启 {} 进程...", name);
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
        Ok(output) => {
            info!("成功执行命令:{:?}", output)
        }
        Err(error) => {
            error!("执行命令失败：{:?}", error)
        }
    }
    thread::sleep(Duration::from_secs(10));
    let process_infos = match get_all_processes() {
        Some(infos) => infos,
        None => {
            error!("Failed to retrieve process information");
            return;
        }
    };
    if is_process_running(name, process_infos.as_slice()).is_some() {
        info!("{} 进程已成功重启", name);
    } else {
        warn!("{} 进程未自动重启，等待系统处理...", name);
        let mut loop_count = 0;
        loop {
            thread::sleep(Duration::from_secs(1));

            let process_infos = match get_all_processes() {
                Some(infos) => infos,
                None => {
                    error!("Failed to retrieve process information");
                    return;
                }
            };
            if is_process_running(name, process_infos.as_slice()).is_some() {
                info!("{} 进程已成功启动", name);
                break;
            }
            loop_count += 1;
            if loop_count > 30 {
                warn!("{} 进程未自动重启，等待系统处理...", name);
                break;
            }
        }
    }
}
fn get_pid_thread_count_map() -> HashMap<DWORD, i32> {
    unsafe {
        let mut result = HashMap::new();
        // Create a snapshot of the processes to get thread count
        let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            eprintln!("Failed to create snapshot of threads");
            return result;
        }

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as DWORD,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };

        if Thread32First(snapshot, &mut thread_entry) != 0 {
            loop {
                *result.entry(thread_entry.th32OwnerProcessID).or_insert(0) += 1;
                if Thread32Next(snapshot, &mut thread_entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        return result;
    }
}
pub fn get_all_processes() -> Option<Vec<ProcessInfo>> {
    let mut process_ids: [DWORD; 2048] = [0; 2048];
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
        let mut result = Vec::new();

        info!("Found {} processes", num_processes);
        let mut can_not_open_count = 0;
        let pid_thread_count_map = get_pid_thread_count_map();
        for i in 0..num_processes as usize {
            let pid = process_ids[i];
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if process_handle.is_null() {
                // let error_code =  winapi::um::errhandlingapi::GetLastError() ;
                // error!("Failed to open process with PID {}: Error code {}", pid, error_code);
                can_not_open_count += 1;
                continue;
            }

            let mut module: HMODULE = std::ptr::null_mut();
            let mut cb_needed: DWORD = 0;
            if EnumProcessModules(
                process_handle,
                &mut module,
                std::mem::size_of::<HMODULE>() as DWORD,
                &mut cb_needed,
            ) != 0
            {
                let mut process_name: [u16; 260] = [0; 260];
                if GetModuleBaseNameW(
                    process_handle,
                    module,
                    process_name.as_mut_ptr(),
                    process_name.len() as DWORD,
                ) > 0
                {
                    let name = String::from_utf16_lossy(&process_name)
                        .trim_end_matches('\0')
                        .to_string();
                    // info!("Found process: {}", name);
                    // Get memory information
                    let mut mem_counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                    let mut private_bytes = 0;
                    let mut working_set = 0;
                    if GetProcessMemoryInfo(
                        process_handle,
                        &mut mem_counters as *mut _,
                        std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as DWORD,
                    ) != 0
                    {
                        private_bytes = mem_counters.PagefileUsage as usize;
                        working_set = mem_counters.WorkingSetSize as usize;
                    }
                    let thread_count = match pid_thread_count_map.get(&pid) {
                        Some(count) => *count,
                        None => 0,
                    };
                    result.push(ProcessInfo {
                        name,
                        pid,
                        thread_count,
                        private_bytes,
                        working_set,
                    });
                }
            }
            CloseHandle(process_handle);
        }
        info!(
            "Finaly open {} processes ,{} can not open",
            result.len(),
            can_not_open_count
        );
        Some(result)
    }
}
pub fn monitor_process(config: &Config) {
    let process_infos = match get_all_processes() {
        Some(infos) => infos,
        None => {
            error!("Failed to retrieve process information");
            return;
        }
    };

    if config.db_config.insert_into_db {
        match DB_CONNECTION.lock() {
            Ok(mut conn) => {
                if let Err(e) = conn.execute_batch_insert(process_infos.as_slice()) {
                    error!("Failed to insert process info into DB: {:?}", e)
                }
            }
            Err(e) => error!("Failed to get DB connection: {:?}", e),
        }
    }

    for process_config in config.get_monitor_processes() {
        if let Some(process) = is_process_running(&process_config.name, process_infos.as_slice()) {
            info!(
                "{} 进程 ID: {}, memory_threshold_MB：{}",
                &process_config.name,
                process.pid,
                process_config.memory_threshold_bytes / 1024 / 1024
            );
            process.print_process_memory_info();
            let private_bytes = process.private_bytes as u64;
            if private_bytes > process_config.memory_threshold_bytes {
                warn!(
                    "内存使用超过阈值 {} MB，正在重启 {}",
                    process_config.memory_threshold_bytes / 1024 / 1024,
                    &process_config.name
                );
                restart_processing(&process_config.name, &process_config.process_type);
            }
        } else {
            warn!("未找到 {} 进程...", &process_config.name);
            if process_config.auto_start {
                info!("正在启动 {} 进程...", &process_config.name);
                let result = process_config.process_type.execute();
                match result {
                    Ok(output) => {
                        info!("成功执行命令:{:?}", output)
                    }
                    Err(error) => {
                        error!("执行命令失败：{:?}", error)
                    }
                }
            }
        }
    }
}

pub fn monitor_processes(config: &Config) {
    loop {
        monitor_process(config);
        print_memory_status();
        thread::sleep(Duration::from_secs(config.interval_seconds));
    }
}
