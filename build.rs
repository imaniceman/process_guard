// build.rs
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // 读取默认配置文件
    let default_config_path = "config/default_config.json";
    let config_contents =
        fs::read_to_string(default_config_path).expect("Failed to read default config file");

    // 将配置内容写入到输出目录中
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("default_config.rs");
    fs::write(
        &dest_path,
        format!(
            "pub const DEFAULT_CONFIG_JSON: &str = r#\"{}\"#;",
            config_contents
        ),
    )
    .unwrap();
}
