# CTF中自动对Pwn题目文件进行信息收集，并且生成基础做题py文件的Pwn工具

随手写的，写的不好请轻喷.
一个用于ctf对Pwn题目文件进行信息收集，打包了检查文件类型、检查类型保护、新建py文件、寻找传参工具的过程。
安装脚本也可用于ubuntu从0开始到可以打pwn的安装

# 效果

运行结果

![image](https://github.com/user-attachments/assets/83b9a31a-d33b-4a69-9cf8-469807395ec9)

运行结果2

![image](https://github.com/user-attachments/assets/db40fe99-83c4-42d0-912c-326cd4fc5c84)

生成的做题py文件

![image](https://github.com/user-attachments/assets/79d99438-19ab-4912-854c-3c10cd0e105c)

生成的传参文件

![image](https://github.com/user-attachments/assets/6bf684d4-8090-4e17-a640-965e130d5016)


# 下载方法
```
git clone https://github.com/shelbyy54/pwnerTool.git

cd ./pwnerTool

lsb_release -a
#查看ubuntu版本
```
![image](https://github.com/user-attachments/assets/9b41646f-469b-453d-8c81-70efa3dd5e19)

```
#ubuntu 24.04 以后
sudo install.sh

#ubuntu 24.04 以前
sudo install_old.sh

#查看示例
pwner ./lockedshell
pwner ./preshellcode
```

# 具体干了什么
安装脚本：
1. 更换源为清华源
2. 更新系统
4. 安装中文和中文输入法
5. 安装python、gcc等基础编译环境
6. 安装pwn工具等
7. 安装pwntools、ROPgadget等python库
8. cp pwn.py /usr/local/bin/pwner

pwner
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

