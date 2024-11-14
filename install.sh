#!/bin/bash

echo "一键部署pwn环境到ubuntu上，制作者：归海言诺";
echo "本脚本主要干以下事：";
echo "1.更换源为清华源";
echo "2.更新系统";
echo "4.安装中文和中文输入法";
echo "5.安装python、gcc等基础编译环境";
echo "6.安装pwn工具等";
echo "7.安装pwntools、ROPgadget等python库";
read -p "本脚本尽力做到傻瓜化，追求能运行就不用管,但是没办法保证100%成功，接受开始安装(yes/no/quit):" input;
if [ "$input" == "yes" ]; then
        echo "开始干活"
    else
        echo "已经安全的退出脚本"
        exit 0
    fi


echo "更换源为清华源";
# 备份原有的sources.list文件
cp /etc/apt/sources.list /etc/apt/sources.list.bak
# 将新的源列表写入sources.list文件
sudo echo " " > /etc/apt/sources.list

NEW_SOURCES_LIST="Types: deb
URIs: https://mirrors.tuna.tsinghua.edu.cn/ubuntu
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

# 默认注释了源码镜像以提高 apt update 速度，如有需要可自行取消注释
# Types: deb-src
# URIs: https://mirrors.tuna.tsinghua.edu.cn/ubuntu
# Suites: noble noble-updates noble-backports
# Components: main restricted universe multiverse
# Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

# 以下安全更新软件源包含了官方源与镜像站配置，如有需要可自行修改注释切换
Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

# Types: deb-src
# URIs: http://security.ubuntu.com/ubuntu/
# Suites: noble-security
# Components: main restricted universe multiverse
# Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

# 预发布软件源，不建议启用

# Types: deb
# URIs: https://mirrors.tuna.tsinghua.edu.cn/ubuntu
# Suites: noble-proposed
# Components: main restricted universe multiverse
# Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

# # Types: deb-src
# # URIs: https://mirrors.tuna.tsinghua.edu.cn/ubuntu
# # Suites: noble-proposed
# # Components: main restricted universe multiverse
# # Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"
# 备份原有的sources.list文件
cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.bak
# 将新的源列表写入sources.list文件
sudo echo "$NEW_SOURCES_LIST" > /etc/apt/sources.list.d/ubuntu.sources

# 更新软件源列表
sudo apt update -y
echo "更换源为清华源完毕";
 

echo "更新系统";
sudo apt install update-manager-core -y
sudo apt update -y
sudo apt dist-upgrade -y
sudo do-release-upgrade -y
echo "更新系统完毕";

echo "安装中文和中文输入法";
sudo apt install -y language-pack-zh-hans
sudo update-locale LANG=zh_CN.UTF-8
sudo apt install -y ibus
sudo apt install -y ibus-pinyin
echo "安装中文和中文输入法完毕";
 

echo "安装python、gcc等基础编译环境";
sudo apt install -y python3 python3-pip python3-dev
sudo apt install -y gcc g++
sudo apt install -y gdb
echo "Python、GCC、调试工具已安装完毕。"
sudo apt-get install -y gcc-multilib 



echo "安装pwn工具等";
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
python3 -m pip install --upgrade pip
sudo apt install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
pip3 install --upgrade pwntools
sudo apt-get install python3-pwntools
git clone https://gitclone.com/github.com/matrix1001/glibc-all-in-one
sudo apt-get install -y autoconf automake libtool
sudo apt install -y patchelf 
sudo apt install -y checksec 

echo "安装pwntools、ROPgadget等python库";
pip install ROPgadget
pip install argparse
pip install ast
pip install subprocess
pip install colorama
sudo apt-get install -y python3-ROPgadget
sudo apt-get install -y python3-argparse
sudo apt-get install -y python3-ast
sudo apt-get install -y python3-subprocess
sudo apt-get install -y python3-colorama




echo "搞定！,现在安装pwn小工具"
chmod +x ./pwn.py
sudo cp pwn.py /usr/local/bin/pwn
echo "全部完成，记得重新启动哦"