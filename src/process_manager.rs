use std::{
    ffi::OsStr, io, os::windows::ffi::OsStrExt, process::Command, ptr::null_mut, thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use winapi::{
    shared::minwindef::{DWORD, HMODULE},
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        processthreadsapi::{CreateProcessAsUserW, OpenProcess, PROCESS_INFORMATION, STARTUPINFOW},
        psapi::{
            EnumProcessModules, EnumProcesses, GetModuleBaseNameW, GetProcessMemoryInfo,
            PROCESS_MEMORY_COUNTERS,  
        },
        securitybaseapi::DuplicateTokenEx,
        userenv::CreateEnvironmentBlock,
        winbase::CREATE_UNICODE_ENVIRONMENT,
        winnt::*,
        wtsapi32::*,
    },
};

use log::{error, info, warn};

use crate::config_manager::Config;
use crate::system_info_printer::print_memory_status;

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
pub struct MemoryInfo {
    pub private_bytes: usize,
    pub working_set: usize,
}

pub fn get_process_memory_info(pid: DWORD) -> Option<MemoryInfo> {
    let mut result = MemoryInfo {
        private_bytes: 0,
        working_set: 0,
    };
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if process_handle.is_null() {
            let error_code = GetLastError();
            error!(
                "Failed to open process: {}. Error code: {}",
                pid, error_code
            );
            return None;
        }

        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();

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

        CloseHandle(process_handle);
    }
    Some(result)
}

pub fn is_process_running(name: &str) -> Option<DWORD> {
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
                    let process_name = String::from_utf16_lossy(&process_name);
                    if process_name
                        .trim_end_matches('\0')
                        .eq_ignore_ascii_case(name)
                    {
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
    if is_process_running(name).is_some() {
        info!("{} 进程已成功重启", name);
    } else {
        warn!("{} 进程未自动重启，等待系统处理...", name);
        let mut loop_count = 0;
        loop {
            thread::sleep(Duration::from_secs(1));
            if is_process_running(name).is_some() {
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

pub fn monitor_process(config: &Config) {
    for process in config.get_monitor_processes() {
        if let Some(pid) = is_process_running(&process.name) {
            info!(
                "{} 进程 ID: {}, memory_threshold_MB：{}",
                &process.name,
                pid,
                process.memory_threshold_bytes / 1024 / 1024
            );
            let info = get_process_memory_info(pid).unwrap_or(MemoryInfo {
                private_bytes: 0,
                working_set: 0,
            });
            let private_bytes = info.private_bytes as u64;
            if private_bytes > process.memory_threshold_bytes {
                warn!(
                    "内存使用超过阈值 {} MB，正在重启 {}",
                    process.memory_threshold_bytes / 1024 / 1024,
                    &process.name
                );
                restart_processing(&process.name, &process.process_type);
            }
        } else {
            warn!("未找到 {} 进程...", &process.name);
            if process.auto_start {
                info!("正在启动 {} 进程...", &process.name);
                let result = process.process_type.execute();
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
