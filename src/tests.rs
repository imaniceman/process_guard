// Tests
#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config_manager::*;
    use crate::process_manager::*;

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
        assert_eq!(config.processes.len(), 2);
        assert_eq!(config.processes[1].name, "RF_Guide.exe");
        assert_eq!(config.processes[1].memory_threshold_bytes, 50 * 1024 * 1024);

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
}
