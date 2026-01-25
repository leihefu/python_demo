import os
import tkinter as tk
from os import write
from tkinter import filedialog


def print_hex_array(arr, bytes_per_line=16, prefix=False, uppercase=True):
    """
    打印十六进制数组，每行固定字节数

    Args:
        arr: 整数列表
        bytes_per_line: 每行显示的字节数（默认16）
        prefix: 是否带0x前缀
        uppercase: 是否大写字母
    """
    fmt = 'X' if uppercase else 'x'

    # 按照指定字节数分块
    for i in range(0, len(arr), bytes_per_line):
        chunk = arr[i:i + bytes_per_line]

        # 转换为十六进制字符串
        if prefix:
            hex_str = ' '.join(f'0x{x:02{fmt}}' for x in chunk)
        else:
            hex_str = ' '.join(f'{x:02{fmt}}' for x in chunk)

        print(hex_str)

    return True

# 选择文件
root = tk.Tk()
root.withdraw()  # 隐藏主窗口
file_path = filedialog.askopenfilename(filetypes=[("所有文件", "*.*")])

# 写文件
write_buf = os.urandom(16)
with open(file_path, 'wb') as file:
    file.write(write_buf)

# 读取文件
with open(file_path, 'rb') as f:
    read_buf = f.read()
if  write_buf == read_buf:
    print("长度：" + str(hex(len(read_buf))))
    print_hex_array(read_buf, bytes_per_line=16, uppercase=False)
    print(read_buf.hex())
else:
    print("error")

input("按Enter键退出")