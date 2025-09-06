#!/bin/bash
set -e

ROOT_DIR="/root/aws_ssh_panel"
TEMPLATES_DIR="$ROOT_DIR/templates"

echo "[INFO] 更新系统并安装依赖..."
sudo apt update -y
sudo apt install -y wget curl git build-essential libssl-dev zlib1g-dev \
libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev libffi-dev \
libbz2-dev

# ------------------ Python 3.13.6 ------------------
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
if [ "$PYTHON_VERSION" != "3.13.6" ]; then
    echo "[INFO] 安装 Python 3.13.6..."
    cd /tmp
    wget https://www.python.org/ftp/python/3.13.6/Python-3.13.6.tgz
    tar xzf Python-3.13.6.tgz
    cd Python-3.13.6
    ./configure --enable-optimizations
    make -j$(nproc)
    sudo make altinstall
fi

# ------------------ 安装 pip3 和库 ------------------
echo "[INFO] 安装 pip3 和 Python 库..."
python3.13 -m ensurepip --upgrade
python3.13 -m pip install --upgrade pip
python3.13 -m pip install flask paramiko boto3

# ------------------ 创建目录 ------------------
echo "[INFO] 创建项目目录..."
sudo mkdir -p $TEMPLATES_DIR

# ------------------ 下载文件 ------------------
echo "[INFO] 下载 app.py..."
sudo wget -O $ROOT_DIR/app.py https://raw.githubusercontent.com/shishen12138/ssh/main/app.py

echo "[INFO] 下载 index.html..."
sudo wget -O $TEMPLATES_DIR/index.html https://raw.githubusercontent.com/shishen12138/ssh/main/templates/index.html

echo "[INFO] 下载 hosts.json..."
sudo wget -O $ROOT_DIR/hosts.json https://raw.githubusercontent.com/shishen12138/ssh/main/hosts.json

echo "[INFO] 下载 logs.txt..."
sudo wget -O $ROOT_DIR/logs.txt https://raw.githubusercontent.com/shishen12138/ssh/main/logs.txt

# ------------------ 设置权限 ------------------
echo "[INFO] 设置权限为 777..."
sudo chmod -R 777 $ROOT_DIR

# ------------------ 后台运行 ------------------
echo "[INFO] 启动 Flask 面板（端口12138）后台运行..."
nohup python3.13 $ROOT_DIR/app.py > $ROOT_DIR/panel.log 2>&1 &

echo "[INFO] 安装完成！"
echo "访问 Web 面板：http://<服务器IP>:12138"
echo "日志查看：tail -f $ROOT_DIR/panel.log"