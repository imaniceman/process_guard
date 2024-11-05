use std::{io, ptr};
use std::path::PathBuf;
use std::process::Command;
use serde::{Deserialize, Serialize};

use std::ptr::null_mut;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::um::processthreadsapi::*;
use winapi::um::wtsapi32::*;
use winapi::um::winbase::CREATE_UNICODE_ENVIRONMENT;
use winapi::um::winnt::*;
use winapi::um::handleapi::CloseHandle;
// use winapi::shared::minwindef::*;
use winapi::um::userenv::CreateEnvironmentBlock;
use winapi::um::securitybaseapi::DuplicateTokenEx;
use crate::config_manager;
use crate::config_manager::ProcessType::{System};

#[derive(Serialize, Deserialize, Debug)]
pub struct MonitoredProcess {
    pub name: String,
    pub memory_threshold_bytes: u64, // Bytes
    #[serde(default)]
    pub process_type: ProcessType,
    #[serde(default = "default_auto_start")]
    pub auto_start: bool,
}
fn default_auto_start() -> bool {
    false
}
#[derive(Serialize, Deserialize, Debug)]
pub enum ProcessType {
    System,
    Service(String),
    User(String, u32),
}

impl ProcessType {
    fn execute_cmd(cmd: &str) -> Result<String, std::io::Error> {
        let output = Command::new("powershell")
            .args(["-Command", cmd])
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
    pub fn kill_process(&self, name: &str) -> Result<String, std::io::Error> {
        let terminate_cmd = format!("taskkill /F /IM {}", name);
        config_manager::ProcessType::execute_cmd(&terminate_cmd)
    }
    pub fn execute(&self) -> Result<String, std::io::Error> {
        match self {
            System => { Ok("".to_string()) }
            ProcessType::Service(cmd) => {
                ProcessType::execute_cmd(cmd)
            }
            ProcessType::User(cmd, sid) => {
                // self.launch_process_as_user(cmd)?;
                ProcessType::launch_process_as_user(*sid, cmd)?;
                Ok("".to_string())
            }
        }
    }
    fn launch_process_as_user(session_id: u32, powershell_cmd: &str) -> Result<(), std::io::Error> {
        let full_command = format!("powershell -Command \"{}\"", powershell_cmd);
        unsafe {
            println!("Launching process as user: {}", full_command);
            let mut h_token = null_mut();
            if WTSQueryUserToken(session_id, &mut h_token) == 0 {
                return Err(io::Error::last_os_error());
            }
            println!("WTSQueryUserToken success");
            let mut duplicate_token = null_mut();
            if DuplicateTokenEx(h_token,
                                MAXIMUM_ALLOWED,
                                null_mut(),
                                SecurityIdentification,
                                TokenPrimary,
                                &mut duplicate_token) == 0 {
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
                lpReserved: ptr::null_mut(),
                lpTitle: ptr::null_mut(),
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
                lpReserved2: ptr::null_mut(),
                hStdInput: ptr::null_mut(),
                hStdOutput: ptr::null_mut(),
                hStdError: ptr::null_mut(),
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
            if success == 0  {
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
impl Default for ProcessType {
    fn default() -> Self {
        System
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    processes: Vec<MonitoredProcess>,
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
}
fn default_interval_seconds() -> u64 {
    60
}

impl Config {
    fn default() -> Config {
        Config {
            processes: vec![
                MonitoredProcess {
                    name: "dwm.exe".to_string(),
                    memory_threshold_bytes: 1000 * 1024 * 1024, // 1000 MB
                    process_type: Default::default(),
                    auto_start: false,
                }
            ],
            interval_seconds: 60,
        }
    }

    pub fn get_monitor_processes(&self) -> &Vec<MonitoredProcess> {
        &self.processes
    }
}
pub struct ConfigManager {
    path: PathBuf,
}
impl ConfigManager {
    pub fn new(path: PathBuf) -> ConfigManager {
        ConfigManager { path }
    }
    pub fn load_or_create_default(&self) -> Config {
        let config_str = std::fs::read_to_string(&self.path).unwrap_or_else(|_| {
            let default_config = Config::default();
            let default_config_str = serde_json::to_string_pretty(&default_config).unwrap();
            std::fs::write(&self.path, &default_config_str).unwrap();
            default_config_str
        });
        serde_json::from_str(&config_str).unwrap()
    }
    #[allow(dead_code)]
    fn save(&self, config: &Config) {
        let config_str = serde_json::to_string_pretty(config).unwrap();
        std::fs::write(&self.path, &config_str).unwrap();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_config_manager_create_default_and_save() {
        // bak and delete config.json
        if std::fs::metadata("config.json").is_ok() {
            std::fs::rename("config.json", "config.json.bak").unwrap();
        }
        let path = PathBuf::from("config.json");
        let config_manager = ConfigManager::new(path);
        let config = config_manager.load_or_create_default();
        assert_eq!(config.processes.len(), 1);
        assert_eq!(config.processes[0].name, "dwm.exe");
        assert_eq!(config.processes[0].memory_threshold_bytes, 1000 * 1024 * 1024);
        let mut config = config_manager.load_or_create_default();
        config.processes.push(MonitoredProcess {
            name: "RF_Guide.exe".to_string(),
            memory_threshold_bytes: 50 * 1024 * 1024,
            process_type: ProcessType::User("powershell -Command \"Start-Process -FilePath 'D:\\ISV\\rf_guide\\RF_Guide.exe' -WorkingDirectory 'D:\\ISV\\rf_guide'\"".to_string(), 1),
            auto_start: true,
        });
        config_manager.save(&config);
        let config = config_manager.load_or_create_default();
        assert_eq!(config.processes.len(), 2);
        assert_eq!(config.processes[1].name, "RF_Guide.exe");
        assert_eq!(config.processes[1].memory_threshold_bytes, 50 * 1024 * 1024);

        // delete config.json
        // std::fs::remove_file("config.json").unwrap();
    }
    #[test]
    fn test_config_manager_load_exist_config() {
        // Write a Config
        let path = PathBuf::from("config.json");
        let config_manager = ConfigManager::new(path);
        let config = config_manager.load_or_create_default();
        assert_eq!(config.processes.len(), 1);
        assert_eq!(config.processes[0].name, "dwm.exe");
        assert_eq!(config.processes[0].memory_threshold_bytes, 1000 * 1024 * 1024);
        assert_eq!(config.interval_seconds, 60);
    }
    #[test]
    fn test_launch_process_as_user(){
        let session_id = 1;
        let powershell_cmd = r#"Start-Process -FilePath "D:\ISV\rf_guide\RF_Guide.exe" -WorkingDirectory "D:\ISV\rf_guide""#;
        let result = ProcessType::launch_process_as_user(session_id, powershell_cmd);
        match result {
            Ok(_) => {}
            Err(e) => {println!("{:?}", e)}
        }
        // assert!(result.is_ok());
    }
}