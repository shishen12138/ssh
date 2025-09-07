#!/bin/bash

# ===============================
# AWS SSH 管理面板 root 目录自动部署脚本
# ===============================

# 部署目录
PROJECT_DIR="/root/aws_panel"

echo "=== 创建部署目录 $PROJECT_DIR ==="
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

echo "=== 安装系统依赖 ==="
apt update && apt upgrade -y
apt install -y python3-pip python3-venv sshpass sysstat curl unzip git

echo "=== 拉取最新项目文件 ==="
# 拉取 backend.py
curl -O https://raw.githubusercontent.com/shishen12138/ssh/main/backend.py
# 拉取 static 目录
mkdir -p static
curl -o static/index.html https://raw.githubusercontent.com/shishen12138/ssh/main/static/index.html

echo "=== 创建 Python 虚拟环境 ==="
python3 -m venv venv
source venv/bin/activate

echo "=== 安装 Python 包 ==="
pip install --upgrade pip
pip install fastapi uvicorn paramiko boto3 asyncio

echo "=== 检查 mpstat 是否可用 ==="
if ! command -v mpstat &> /dev/null; then
    echo "mpstat 不存在，安装 sysstat"
    apt install -y sysstat
else
    echo "mpstat 已安装"
fi

echo "=== 启动后端服务 ==="
echo "服务将运行在 http://0.0.0.0:12138/"

# 后台启动并写日志
nohup $PROJECT_DIR/venv/bin/uvicorn backend:app --host 0.0.0.0 --port 12138 > $PROJECT_DIR/panel.log 2>&1 &

echo "=== 部署完成 ==="
echo "日志文件: $PROJECT_DIR/panel.log"
echo "访问面板: http://<服务器IP>:12138/"
