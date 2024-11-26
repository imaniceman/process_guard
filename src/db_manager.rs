use lazy_static::lazy_static;
use log::info;
use rusqlite::{params, Connection, Result};
use std::{fs, path::PathBuf, sync::Mutex};

use crate::process_manager::ProcessInfo;

lazy_static! {
    pub static ref DB_CONNECTION: Mutex<DBConnection> = Mutex::new(DBConnection::new().unwrap());
}

pub struct DBConnection {
    conn: Connection,
    file_path: PathBuf,
}
impl DBConnection {
    fn new() -> Result<Self> {
        let mut file_path = std::env::current_exe().unwrap();
        file_path.set_file_name("process_info.db");
        DBConnection::from_path(file_path)
    }
    fn from_path(file_path: PathBuf) -> Result<Self> {
        let conn = Connection::open(&file_path)?;
        let result = DBConnection {
            conn,
            file_path: file_path.clone(),
        };
        result.create_table()?;
        Ok(result)
    }
    fn create_table(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS process_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            pid INTEGER NOT NULL,
            thread_count INTEGER NOT NULL,
            private_bytes INTEGER,
            working_set INTEGER
        )",
            [],
        )?;
        Ok(())
    }
    pub fn execute_batch_insert(&mut self, process_infos: &[ProcessInfo]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO process_info (pid, name,thread_count, private_bytes, working_set ) VALUES (?1, ?2, ?3, ?4, ?5 )",
            )?;
            for process_info in process_infos {
                stmt.execute(params![
                    process_info.pid,
                    process_info.name,
                    process_info.thread_count,
                    process_info.private_bytes,
                    process_info.working_set,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub fn cleanup_old_data(&mut self, hours: i64, vacuum_threshold_mb: u64) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let changes = tx.execute(
                "DELETE FROM process_info WHERE timestamp < datetime('now', ?1 || ' hours')",
                params![-hours],
            )?;
            info!("Deleted rows: {}", changes);
        }
        tx.commit()?;
        let metadata = fs::metadata(&self.file_path);
        let file_size_mb = metadata.unwrap().len() / 1024 / 1024;
        if file_size_mb > vacuum_threshold_mb {
            info!("Vacuuming database");
            self.conn.execute("VACUUM", [])?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::windows::fs::MetadataExt, time::{Duration, SystemTime}};

    fn insert_test_data(conn: &mut DBConnection, days_ago: i64) -> Result<()> {
        let timestamp = SystemTime::now() - Duration::from_secs(days_ago as u64 * 24 * 60 * 60);
        let datetime = chrono::DateTime::<chrono::Utc>::from(timestamp)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        let process_infos = vec![ProcessInfo {
            pid: 1234,
            name: "P1".to_string(),
            thread_count: 10,
            private_bytes: 2048,
            working_set: 4096,
        }];

        let tx = conn.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO process_info (pid, name, thread_count, private_bytes, working_set, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for process_info in process_infos {
                stmt.execute(params![
                    process_info.pid,
                    process_info.name,
                    process_info.thread_count,
                    process_info.private_bytes,
                    process_info.working_set,
                    datetime,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    #[test]
    fn test_cleanup_old_data() {
        // Remove the test database file if it exists
        std::fs::remove_file("test_process_info.db").unwrap_or_default();

        let test_db = "test_process_info.db";
        let mut conn = DBConnection::from_path(PathBuf::from(test_db)).unwrap();

        // Insert data older than 30 days
        insert_test_data(&mut conn, 31).unwrap();

        // Insert data within the last 30 days
        insert_test_data(&mut conn, 29).unwrap();

        // Call cleanup_old_data to remove data older than 30 days
        conn.cleanup_old_data(30, 100).unwrap();

        // Verify that only the data within the last 30 days remains
        let count: i64 = conn
            .conn
            .query_row("SELECT COUNT(*) FROM process_info", [], |row| row.get(0))
            .unwrap();

        assert_eq!(count, 1, "Expected 1 row to remain in the database");
    }
    #[test]
    fn test_vacuum_db() {
        // 已经预先准备好一个大于 10MB 的DB 文件 process_info_over_10.db
        // Remove the test database file if it exists
        let file = "process_info_over_10.db";
        std::fs::remove_file(file).unwrap_or_default();
        std::fs::copy("process_info-copy.db", file).unwrap();
        let file_size = fs::metadata(file).unwrap().file_size();
        //  let test_db = "test_process_info.db";
        let mut conn = DBConnection::from_path(PathBuf::from(file)).unwrap();

        // 删除旧数据

        conn.cleanup_old_data(8, 20).unwrap();
        // 此时数据库大小未被修改
        let expected_size = fs::metadata(file).unwrap().file_size();
        assert_eq!(file_size,expected_size);
        conn.cleanup_old_data(8, 10).unwrap();

        let expected_size = fs::metadata(file).unwrap().file_size();
        assert_ne!(file_size,expected_size);
        
    }
    #[test]
    fn test_execute_batch_insert() {
        // remove db first
        std::fs::remove_file("test_process_info.db").unwrap_or_default();

        let test_db = "test_process_info.db";
        let mut conn = DBConnection::from_path(PathBuf::from(test_db)).unwrap();

        let process_infos = vec![
            ProcessInfo {
                pid: 1234,
                name: "P1".to_string(),
                thread_count: 10,
                private_bytes: 2048,
                working_set: 4096,
            },
            ProcessInfo {
                pid: 5678,
                name: "P2".to_string(),
                thread_count: 20,
                private_bytes: 4096,
                working_set: 8192,
            },
        ];

        conn.execute_batch_insert(&process_infos).unwrap();
        conn.execute_batch_insert(&process_infos).unwrap();

        let mut stmt = conn
            .conn
            .prepare("SELECT COUNT(*) FROM process_info")
            .unwrap();
        let count: i64 = stmt.query_row([], |row| row.get(0)).unwrap();

        assert_eq!(count, 4);
    }
}
