# CTF中自动对pen题目文件进行信息收集，并且生成基础做题py文件

随手写的，写的不好请轻喷.
一个用于ctf对pen题目文件进行信息收集，打包了检查文件类型、检查类型保护、新建py文件、寻找传参工具的过程。
安装脚本也可用于ubuntu从0开始到可以打pwn的安装

# 下载方法
```
git clone https://github.com/shelbyy54/pwnerTool.git

cd ./pwnerTool

#ubuntu 24.04 以后
sudo install.sh

#ubuntu 24.04 以前
sudo install_old.sh

#查看示例
pwner ./lockedshell
```

#具体干了什么
安装脚本：
1. 更换源为清华源
2. 更新系统
4. 安装中文和中文输入法
5. 安装python、gcc等基础编译环境
6. 安装pwn工具等
7. 安装pwntools、ROPgadget等python库
8. cp pwn.py /usr/local/bin/pwner

pwn
1. file ./pwn
2. checksec --file=./pwn
3. chmod +x ./pwn
4. ldd ./pwn

# 使用方法
```
cd 题目文件路径
pwner ./pwn
```

# 卸载
```
sudo mv /usr/local/bin/pwner
```

