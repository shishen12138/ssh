#!/bin/bash

PROJECT_DIR="/root/aws_panel"
PORT=12138

echo "=== 创建部署目录 $PROJECT_DIR ==="
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR


echo "=== 拉取项目文件 ==="
curl -s -O https://raw.githubusercontent.com/shishen12138/ssh/main/backend.py
curl -s -O https://raw.githubusercontent.com/shishen12138/ssh/main/hosts.json
mkdir -p static
curl -s -o static/index.html https://raw.githubusercontent.com/shishen12138/ssh/main/static/index.html

chmod -R 777 backend.py hosts.json static
echo "=== 文件拉取完成，权限已设置为 777 ==="

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

# 🔹 停掉旧的 uvicorn 进程
echo "=== 停止旧进程 ==="
PIDS=$(ps -ef | grep "uvicorn backend:app" | grep -v grep | awk '{print $2}')
if [ -n "$PIDS" ]; then
    echo "找到旧进程: $PIDS"
    kill -9 $PIDS
    echo "已杀掉旧进程"
else
    echo "未找到旧进程，跳过"
fi

# 🔹 启动新服务
echo "=== 启动新服务 ==="
nohup $PROJECT_DIR/venv/bin/uvicorn backend:app --host 0.0.0.0 --port $PORT > $PROJECT_DIR/panel.log 2>&1 &

echo "=== 部署完成 ==="
echo "访问面板: http://<服务器IP>:$PORT/"
echo "日志文件: $PROJECT_DIR/panel.log"
