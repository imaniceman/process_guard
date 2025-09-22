from datetime import datetime, timezone
import os
import sqlite3
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk


def fetch_data(file, name):
    # 连接到SQLite数据库
    conn = sqlite3.connect(file)
    cursor = conn.cursor()

    # 查询数据
    cursor.execute('''
        SELECT timestamp, private_bytes, working_set
        FROM process_info
        WHERE name = ?
        ORDER BY timestamp
    ''', (name,))

    data = cursor.fetchall()

    # 关闭数据库连接
    conn.close()

    return data


def plot_data(data):
    if not data:
        print("No data found for the given name.")
        return

    timestamps = [datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%m-%d %H:%M:%S') for row in data]
    private_bytes = [row[1] / (1024 * 1024) for row in data]  # 转换为MB
    working_set = [row[2] / (1024 * 1024) for row in data]    # 转换为MB

    root = tk.Tk()
    root.state('zoomed')  # 全屏显示

    fig, ax = plt.subplots(figsize=(10, 5))

    ax.plot(timestamps, private_bytes, label='Private Bytes')
    ax.plot(timestamps, working_set, label='Working Set')

    ax.set_xlabel('Timestamp')
    ax.set_ylabel('Bytes')
    ax.set_title('Private Bytes and Working Set Over Time')
    ax.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()

    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    tk.mainloop()


if __name__ == "__main__":
    # name = input("Enter the process name: ")
    name = 'tivis_data_sync_server.exe'
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file = os.path.join(script_dir, 'process_info.db')
    # file = "f:/ProjectIssues/系统测试/统计分析/20241129内存泄漏相关测试/1204/process_info.db"
    data = fetch_data(file, name)
    plot_data(data)
