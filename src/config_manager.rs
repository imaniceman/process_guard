use crate::process_manager::ProcessType;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/default_config.rs"));
// Structs and Enums
#[derive(Serialize, Deserialize, Debug)]
pub struct MonitoredProcess {
    pub name: String,
    pub memory_threshold_bytes: u64, // Bytes
    #[serde(default)]
    pub process_type: ProcessType,
    #[serde(default = "default_auto_start")]
    pub auto_start: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub processes: Vec<MonitoredProcess>,
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default)]
    pub insert_into_db: bool,
}

pub struct ConfigManager {
    path: PathBuf,
}

fn default_auto_start() -> bool {
    false
}

fn default_interval_seconds() -> u64 {
    60
}

// Config Methods
impl Config {
    fn default() -> Config {
      serde_json::from_str(DEFAULT_CONFIG_JSON).unwrap()
     }

    pub fn get_monitor_processes(&self) -> &Vec<MonitoredProcess> {
        &self.processes
    }
}

// ConfigManager Methods
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
    pub fn save(&self, config: &Config) {
        let config_str = serde_json::to_string_pretty(config).unwrap();
        std::fs::write(&self.path, &config_str).unwrap();
    }
}
