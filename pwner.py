#!/usr/bin/env python3

# pwnerTool V2.0
# 作者：归海言诺
# 功能：
# 1. 自动分析 pwn 题目 ELF 文件的基本特征和保护机制。
# 2. 修补动态库（libc 文件）和动态链接器（操作系统库）。
# 3. 自动生成基础的 Pwn 工具文件。
# 使用方法：
# 基础： pwner ./pwnfile
# 修补动态库： pwner ./pwnfile --setLib ./libc.so
# 设置动态库路径： pwner ./pwnfile --setOS ./ld.so

import argparse
import subprocess
import os
from colorama import Fore
import logging

# 定义 ELF 文件的基本特征及其解释
fileInfoDict: dict[str, str] = {
    "ELF": "可执行文件",
    "64-bit": Fore.RED + "64位文件" + Fore.WHITE,
    "32-bit": "32位文件",
    "LSB": "小端序",
    "BSB": Fore.RED + "大端序" + Fore.WHITE,
}

# 定义文件保护机制信息及其解释
fileProtectionInfoDict: dict[str, str] = {
    "Partial RELRO": Fore.RED + "可写GOT表" + Fore.WHITE,
    "Full RELR": Fore.GREEN + "不可写GOT表" + Fore.WHITE,
    "Canary found": Fore.GREEN + "有金丝雀" + Fore.WHITE,
    "No canary found": Fore.RED + "无金丝雀" + Fore.WHITE,
    "NX disabled": Fore.RED + "栈可运行" + Fore.WHITE,
    "NX enabled": Fore.GREEN + "栈不可运行" + Fore.WHITE,
    "NX unknown": Fore.RED + "栈有可能可运行" + Fore.WHITE,
    "Executable": Fore.RED + "栈可运行" + Fore.WHITE,
    "PIE enabled": Fore.GREEN + "随机位置(PIE)开启" + Fore.WHITE,
    "No PIE (0x400000)": Fore.RED + "固定位置" + Fore.WHITE,
    "Has RWX segments": Fore.RED + "存在可读写可执行的内存段" + Fore.WHITE,
}

# 配置日志输出格式
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

# 定义日志输出的辅助函数


def logInfo(message):
    print(Fore.GREEN + "[信息] " + message + Fore.WHITE)


def logError(message):
    print(Fore.RED + "[错误] " + message + Fore.WHITE)


def logWarning(message):
    print(Fore.YELLOW + "[警告] " + message + Fore.WHITE)

# 解析命令行参数


def parseCommandLine():
    parser = argparse.ArgumentParser(description='pwnerTool 2.0')
    parser.add_argument('pwnFilePath', type=str, help='待分析的 pwn 文件路径')
    parser.add_argument('--setLib', type=str,
                        required=False, help='指定 libc 文件路径')
    parser.add_argument('--setOS', type=str,
                        required=False, help='指定动态链接器文件路径')
    args: argparse.Namespace = parser.parse_args()

    # 检查路径参数是否存在
    if not args.pwnFilePath:
        logWarning("请提供待分析的文件路径。")
        parser.print_help()
        exit(-1)
    validateFilePath(args.pwnFilePath, "pwnFilePath")
    if args.setLib:
        validateFilePath(args.setLib, '--setLib')
    if args.setOS:
        validateFilePath(args.setOS, '--setOS')

    return args

# 验证文件路径是否存在


def validateFilePath(filePath: str, argName: str):
    if not os.path.exists(filePath):
        logError(f"参数 {argName} 指定的文件 {filePath} 不存在。")
        exit(-1)

# 执行 Shell 命令并捕获输出


def runShellCmd(args: str):
    try:
        res = subprocess.Popen(
            args=args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True
        )
        stdout, _ = res.communicate()
        return stdout.strip().split("\n")
    except Exception as e:
        logError(f"执行命令时出错: {e}")
        exit(-1)

# 检查 ELF 文件的保护机制


def getFileProtectionInfo(pwnFilePath: str):
    fileProtectionInfoList = runShellCmd(args=f"checksec --file={pwnFilePath}")
    returnFileProtectionInfoList = []
    for line in fileProtectionInfoList[1:]:  # 跳过第一行标题
        parts = line.split(":")
        key = parts[1].strip()

        if key in fileProtectionInfoDict:
            print(f"{line.strip():40} => {fileProtectionInfoDict[key]}")
            returnFileProtectionInfoList.append(key)
        else:
            print(line.strip())
    return returnFileProtectionInfoList

# 获取 ELF 文件的基本特征信息


def getFileInfo(pwnFilePath: str):
    fileInfoStr = runShellCmd(f"file {pwnFilePath}")[0]
    fileInfoList = fileInfoStr.split(" ")
    if "ELF" not in fileInfoList:
        logError(f"{pwnFilePath} 不是 ELF 文件!")
        logError(f"{fileInfoStr}")
        exit(-1)
    returnFileInfoList = []
    for i in fileInfoList:
        if i in fileInfoDict:
            print("{:40} => {}".format(i, fileInfoDict[i]))
            returnFileInfoList.append(i)
    return returnFileInfoList

# 生成 ROPgadget 工具的辅助文件


def generateX64ROPArgsToolFile(pwnFilePath: str):
    logInfo("已生成 64 位传参工具到 tools.txt")
    runShellCmd(args=f"ROPgadget --binary {pwnFilePath} > tools.txt")

# 为文件设置可执行权限


def setExecutablePermission(pwnFilePath: str):
    logInfo("已为目标文件设置可执行权限")
    runShellCmd(args=f"chmod +x {pwnFilePath}")

# 自动生成基础 Pwn 脚本文件


def generatePyFile(pwnFilePath: str, fileInfoList: list[str]):
    if os.path.exists("tool.py"):
        overwrite = input(
            Fore.YELLOW + "文件 tool.py 已存在，是否覆盖？(y/n): " + Fore.WHITE)
        if overwrite.lower() != 'y':
            print(Fore.RED + "未生成新文件。" + Fore.WHITE)
            return

    pyFile: str = f"""
from pwn import *
context(os='linux', arch='AMD64', log_level='debug')

# 修改为目标地址和端口
TARGET_IP = "127.0.0.1"
TARGET_PORT = 1337

io = remote(TARGET_IP, TARGET_PORT)
file = ELF('{pwnFilePath}')

# 接收直到某字符
io.recvuntil(b'A')
# 接收指定字节数
data = io.recv(numb=6)
# 发送数据
io.send(data)

# 获取交互 shell
io.interactive()
""".format(pwnFilePath)

    if "64-bit" in fileInfoList:
        pyFile += """
# 构造 64 位 ROP 链
def amd64(io):
    payload = flat([
        file.search(asm('pop rax; ret;')).__next__(),
        59,
        file.search(asm('pop rdi; ret;')).__next__(),
        file.search(b'/bin/sh').__next__(),
        file.search(asm('pop rsi; ret;')).__next__(),
        0,
        file.search(asm('pop rdx; ret')).__next__(),
        0,
        file.search(asm('syscall')).__next__()
    ])
"""

    logInfo("正在生成基础 Pwn 脚本到 tool.py")
    with open("tool.py", "w") as file:
        file.write(pyFile)
    logInfo("tool.py 已生成。")

# 检查 ELF 文件的动态库依赖


def checkDynamicLibraries(pwnFilePath: str):
    print("\n动态库:")
    resList: list[str] = runShellCmd(args=f"ldd {pwnFilePath}")
    for i in resList:
        print(i.strip("\t"))
    print()

# 替换动态库或链接器


def setDynamicLibraries(pwnFilePath: str, libcPath: str = None, osPath: str = None):
    if libcPath:
        logWarning(f"正在替换 libc 动态库为: {libcPath}")
        runShellCmd(
            args=f"patchelf --replace-needed libc.so.6 {libcPath} {pwnFilePath}")
    if osPath:
        logWarning(f"正在替换操作系统动态库为: {osPath}")
        runShellCmd(args=f"patchelf --set-interpreter {osPath} {pwnFilePath}")

# 主函数，负责整合各模块功能


def main():
    args = parseCommandLine()
    fileInfoList = []
    logInfo(f"文件路径: {args.pwnFilePath}")
    fileInfoList += getFileInfo(args.pwnFilePath)
    fileInfoList += getFileProtectionInfo(args.pwnFilePath)
    checkDynamicLibraries(args.pwnFilePath)
    setExecutablePermission(args.pwnFilePath)
    generatePyFile(args.pwnFilePath,fileInfoList)
    if args.setLib or args.setOS:
        setDynamicLibraries(args.pwnFilePath, args.setLib, args.setOS)
    generateX64ROPArgsToolFile(args.pwnFilePath)


if __name__ == "__main__":
    main()