use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct MonitoredProcess {
    pub name: String,
    pub memory_threshold_bytes: u64, // Bytes
    #[serde(default)]
    pub restart_command: Option<String>,
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
                    restart_command: None,
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
            name: "test.exe".to_string(),
            memory_threshold_bytes: 500 * 1024 * 1024,
            restart_command: None,
        });
        config_manager.save(&config);
        let config = config_manager.load_or_create_default();
        assert_eq!(config.processes.len(), 2);
        assert_eq!(config.processes[1].name, "test.exe");
        assert_eq!(config.processes[1].memory_threshold_bytes, 500 * 1024 * 1024);

        // delete config.json
        std::fs::remove_file("config.json").unwrap();
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
}