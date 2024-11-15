echo "一键部署pwn环境到ubuntu上，制作者：归海言诺";
echo "本脚本主要干以下事：";
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

# 更新软件源列表
sudo apt update -y
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
chmod +x ./pwner.py
sudo cp pwner.py /usr/local/bin/pwner
echo "全部完成，记得重新启动哦"