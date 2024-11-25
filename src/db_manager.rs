use lazy_static::lazy_static;
use rusqlite::{params, Connection, Result};
use std::sync::Mutex;

use crate::process_manager::ProcessInfo;

lazy_static! {
    pub static ref DB_CONNECTION: Mutex<DBConnection> =
        Mutex::new(DBConnection::new().unwrap());
}


pub struct DBConnection {
    conn: Connection,
}
impl DBConnection {
    fn new() -> Result<Self> {
        let mut exe_path = std::env::current_exe().unwrap();
        exe_path.set_file_name("process_info.db");
        let conn = Connection::open(exe_path)?;
        let result = DBConnection { conn };
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
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_batch_insert() {
        // remove db first
        std::fs::remove_file("test_process_info.db").unwrap_or_default();

        let test_db = "test_process_info.db";
        let mut conn = DBConnection::new(PathBuf::from(test_db)).unwrap();

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
