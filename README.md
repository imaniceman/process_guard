# ProcessGuard

ProcessGuard 是一个用于监控和管理系统进程的工具。

## 功能

- 打印系统信息
- 打印操作系统版本
- 打印内存状态
- 打印显示驱动程序版本
- 监控进程内存使用情况并在超过阈值时重启进程
- 将进程信息插入数据库并定期清理旧数据

## 依赖

- windows-service
- log4rs
- log
- wmi
- serde
- serde_json
- rusqlite
- lazy_static

## 项目结构

```
 .
├──  build.rs
├──  Cargo.lock
├──  Cargo.toml
├──  config
│   └──  default_config.json   
├──  justfile
├──  pack
│   ├──  pack.py
│   ├──  pack_dwm_monitor.iss  
│   ├──  readme.txt
│   ├──  start_service.bat     
│   └──  stop_service.bat      
├──  README.md
└──  src
    ├──  config_manager.rs     
    ├──  db_manager.rs
    ├──  logging.rs
    ├──  main.rs
    ├──  process_manager.rs    
    ├──  system_info_printer.rs
    └──  tests.rs
```

## 构建和运行

### 构建

要构建项目，请运行以下命令：

```sh
cargo build --release
```

### 打包

要打包项目，请运行以下命令：

```sh
just package
```

### 运行

无法直接运行，打包后生成安装程序，安装后作为服务运行。

### 配置

默认配置文件位于 `config/default_config.json`。配置文件的结构如下：

```json
{
  "processes": [
    {
      "name": "dwm.exe",
      "memory_threshold_bytes": 1048576000,
      "process_type": "System",
      "auto_start": false
    },
    {
      "name": "Microsoft.photos.exe",
      "memory_threshold_bytes": 2048576000,
      "process_type": "System",
      "auto_start": false
    }
  ],
  "interval_seconds": 60,
  "db_config": {
    "insert_into_db": true,
    "db_cleanup_hours": 720,
    "db_vacuum_threshold_mb": 500,
    "cleanup_interval_hours": 12
  }
}
```

- `processes`: 监控的进程列表。
  - `name`: 进程名称。
  - `memory_threshold_bytes`: 内存阈值，单位为字节。
  - `process_type`: 进程类型，可以是 `System`, `Service(String)` 或 `User(String, u32)`。
  - `auto_start`: 是否自动启动进程。
- `interval_seconds`: 监控间隔时间，单位为秒。
- `db_config`: 数据库配置。
  - `insert_into_db`: 是否将进程信息插入数据库。
  - `db_cleanup_hours`: 数据库清理时间间隔，单位为小时。
  - `db_vacuum_threshold_mb`: 数据库真空操作的阈值，单位为MB。
  - `cleanup_interval_hours`: 数据库清理操作的时间间隔，单位为小时。

> 安装成功后，会在安装目录下自动生成 `config.json` 文件，可以在此文件中修改配置。

### 测试

要运行测试，请执行以下命令：

```sh
cargo test
```

## 使用

1. 安装后无需操作，服务会自动运行。
2. 如果需要手动启动或停止服务，可以运行 `pack/start_service.bat` 和 `pack/stop_service.bat`。

## 许可证

此项目使用 MIT 许可证 - 有关详细信息，请参阅 [LICENSE](LICENSE) 文件。