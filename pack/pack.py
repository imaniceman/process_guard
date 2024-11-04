import shutil
import os
import subprocess

# 定义源文件路径和目标文件路径
exe_src = './target/release/process_guard.exe'
exe_dst = './pack/process_guard.exe'

# 定义 ISS 文件路径
iss_file = './pack/pack_dwm_monitor.iss'  # 确保这个路径指向你的 .iss 文件

# 复制文件
try:
    shutil.copy(exe_src, exe_dst)
    print(f"Copied {exe_src} to {exe_dst}")
except FileNotFoundError:
    print(f"{exe_src} not found. Make sure to run 'just build' first.")

# 打包 .exe 文件
if os.path.exists(iss_file):
    try:
        # 调用 Inno Setup 编译器
        result = subprocess.run(['iscc', iss_file], capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)
    except Exception as e:
        print(f"Failed to compile {iss_file}: {e}")
else:
    print(f"{iss_file} not found. Please ensure the path is correct.")
