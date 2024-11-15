# CTF中自动对Pwn题目文件进行信息收集，并且生成基础做题py文件的Pwn工具，适用于Ubuntu

随手写的，写的不好请轻喷.
一个用于ctf对Pwn题目文件进行信息收集，打包了检查文件类型、检查类型保护、新建py文件、寻找传参工具的过程。
同时可以修补题目给出的动态库和libc文件保证本体环境和远程一样。


安装脚本会自动安装所需要的依赖（一路确定即可）
完整安装脚本也可用于ubuntu从0开始到可以打pwn的安装

# 效果

运行结果

![image](https://github.com/user-attachments/assets/7147fd53-b3d3-4197-9a05-525bb8f7b8ef)


运行结果2

![image](https://github.com/user-attachments/assets/158c3d84-2447-4363-a9c8-baba96a7ba85)

修补文件

![image](https://github.com/user-attachments/assets/221fe35a-a8cb-49d6-9fa7-16eaf8be18d6)



生成的做题py文件

![image](https://github.com/user-attachments/assets/79d99438-19ab-4912-854c-3c10cd0e105c)

生成的传参文件

![image](https://github.com/user-attachments/assets/6bf684d4-8090-4e17-a640-965e130d5016)


# 下载方法
```
git clone https://github.com/shelbyy54/pwnerTool.git

cd ./pwnerTool
chmod +x ./install.sh
sudo ./install.sh

#查看示例
pwner ./lockedshell
pwner ./preshellcode
pwner ./prelibc --setLibc=./libc.so.6 --setOS=./ld-linux-x86-64.so.2
```
如果有直接从零开始安装的需求
```
git clone https://github.com/shelbyy54/pwnerTool.git

cd ./pwnerTool
chmod +x ./completeInstallation.sh
chmod +x ./completeInstallation_old.sh

lsb_release -a

#Ubuntu 20.4以上用这个
sudo ./completeInstallation.sh

#Ubuntu 20.4以下用这个
sudo ./completeInstallation_old.sh

#查看示例
pwner ./lockedshell
pwner ./preshellcode
pwner ./prelibc --setLibc=./libc.so.6 --setOS=./ld-linux-x86-64.so.2
```
# 具体干了什么
安装脚本：
1. 更换源为清华源
2. 更新系统
4. 安装中文和中文输入法
5. 安装python、gcc等基础编译环境
6. 安装pwn工具等
7. 安装pwntools、ROPgadget等python库
8. cp pwner.py /usr/local/bin/pwner

pwner运行原理
1. file ./pwn
2. checksec --file=./pwn
3. chmod +x ./pwn
4. ldd ./pwn

# 使用方法
1. 查看pwn题目文件信息并且生成脚本
```
cd 题目文件路径
pwner ./pwn
```
2. 修补文件
~~~
cd 题目文件路径
pwner ./pwn --setOS ./动态库文件
pwner ./pwn --setLib ./libc文件
~~~

# 卸载
```
sudo mv /usr/local/bin/pwner
```

