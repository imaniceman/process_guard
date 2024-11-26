// Tests
#[cfg(test)]
mod tests {
    use crate::config_manager::*;
    use crate::process_manager::*;
    use log::info;
    use std::path::PathBuf;
    #[test]
    fn test_config_manager_create_default_and_save() {
        // bak and delete config.json
        if std::fs::metadata("config.json").is_ok() {
            std::fs::rename("config.json", "config.json.bak").unwrap();
        }
        let path = PathBuf::from("config.json");
        let config_manager = ConfigManager::new(path);
        let config = config_manager.load_or_create_default();
        info!("{:#?}", config);
        assert_eq!(config.processes.len(), 2);
        assert_eq!(config.processes[0].name, "dwm.exe");
        assert_eq!(
            config.processes[0].memory_threshold_bytes,
            1000 * 1024 * 1024
        );
        let mut config = config_manager.load_or_create_default();
        config.processes.push(MonitoredProcess {
            name: "RF_Guide.exe".to_string(),
            memory_threshold_bytes: 50 * 1024 * 1024,
            process_type: ProcessType::User("powershell -Command \"Start-Process -FilePath 'D:\\ISV\\rf_guide\\RF_Guide.exe' -WorkingDirectory 'D:\\ISV\\rf_guide'\"".to_string(), 1),
            auto_start: true,
        });
        config_manager.save(&config);
        let config = config_manager.load_or_create_default();
        assert_eq!(config.processes.len(), 3);
        assert_eq!(config.processes[2].name, "RF_Guide.exe");
        assert_eq!(config.processes[2].memory_threshold_bytes, 50 * 1024 * 1024);

        // delete config.json
        std::fs::remove_file("config.json").unwrap();
    }

    #[test]
    fn test_config_manager_load_exist_config() {
        // Delete Config first
        if std::fs::metadata("config.json").is_ok() {
            std::fs::remove_file("config.json").unwrap();
        }
        // Write a Config
        let path = PathBuf::from("config.json");
        let config_manager = ConfigManager::new(path);
        let config = config_manager.load_or_create_default();
        assert_eq!(config.processes.len(), 2);
        assert_eq!(config.processes[0].name, "dwm.exe");
        assert_eq!(
            config.processes[0].memory_threshold_bytes,
            1000 * 1024 * 1024
        );
        assert_eq!(config.interval_seconds, 60);
    }
    #[test]
    fn test_get_all_process() {
        // 开始计时
        let start = std::time::Instant::now();
        let result = get_all_processes();
        let duration = std::time::Instant::now().duration_since(start);
        info!("get_all_processes() duration: {:?}", duration);
        assert!(result.is_some());
    }
    #[test]
    fn test_monitor_processes() {
        let config = Config {
            processes: vec![MonitoredProcess {
                name: "dwm.exe".to_string(),
                memory_threshold_bytes: 1000 * 1024 * 1024,
                process_type: ProcessType::System,
                auto_start: false,
            }],
            interval_seconds: 10,
            db_config: default_db_config(),
        };
        monitor_process(&config);
    }
}
