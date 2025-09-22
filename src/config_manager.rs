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
    #[serde(default = "default_restart_all_on_threshold")]
    pub restart_all_on_threshold: bool,
    #[serde(default = "default_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub processes: Vec<MonitoredProcess>,
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default = "default_db_config")]
    pub db_config: DBConfig,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct DBConfig {
    #[serde(default)]
    pub insert_into_db: bool,
    #[serde(default = "default_db_cleanup_hours")]
    pub db_cleanup_hours: i64,
    #[serde(default = "default_db_vacuum_threshold_mb")]
    pub db_vacuum_threshold_mb: u64,
    #[serde(default = "default_cleanup_interval_hours")]
    pub cleanup_interval_hours: i64,
}

pub struct ConfigManager {
    path: PathBuf,
}

pub fn default_db_config() -> DBConfig {
    DBConfig {
        insert_into_db: true,
        db_cleanup_hours: default_db_cleanup_hours(),
        db_vacuum_threshold_mb: default_db_vacuum_threshold_mb(),
        cleanup_interval_hours: default_cleanup_interval_hours(),
    }
}

pub fn default_cleanup_interval_hours() -> i64 {
    12
}

fn default_db_cleanup_hours() -> i64 {
    24 * 30
}

fn default_db_vacuum_threshold_mb() -> u64 {
    500
}

fn default_auto_start() -> bool {
    false
}

fn default_restart_all_on_threshold() -> bool {
    false
}

fn default_cooldown_seconds() -> u64 {
    60
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
