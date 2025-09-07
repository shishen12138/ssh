#!/bin/bash

PROJECT_DIR="/root/aws_panel"

echo "=== 创建部署目录 $PROJECT_DIR ==="
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

echo "=== 更新系统 ==="
DEBIAN_FRONTEND=noninteractive apt update -y
DEBIAN_FRONTEND=noninteractive apt upgrade -y

echo "=== 安装依赖 ==="
DEBIAN_FRONTEND=noninteractive apt install -y python3-pip python3-venv sshpass sysstat curl git

echo "=== 拉取项目文件 ==="
curl -s -O https://raw.githubusercontent.com/shishen12138/ssh/main/backend.py
curl -s -O https://raw.githubusercontent.com/shishen12138/ssh/main/hosts.json
mkdir -p static
curl -s -o static/index.html https://raw.githubusercontent.com/shishen12138/ssh/main/static/index.html

echo "=== 创建虚拟环境 ==="
python3 -m venv venv
source venv/bin/activate

echo "=== 安装 Python 包 ==="
pip install --upgrade pip
pip install fastapi uvicorn paramiko boto3 asyncio

echo "=== 检查 mpstat ==="
if ! command -v mpstat &> /dev/null; then
    echo "mpstat 不存在，安装 sysstat"
    DEBIAN_FRONTEND=noninteractive apt install -y sysstat
fi

echo "=== 启动服务 ==="
nohup $PROJECT_DIR/venv/bin/uvicorn backend:app --host 0.0.0.0 --port 12138 > $PROJECT_DIR/panel.log 2>&1 &

echo "=== 部署完成 ==="
echo "访问面板: http://<服务器IP>:12138/"
echo "日志文件: $PROJECT_DIR/panel.log"
