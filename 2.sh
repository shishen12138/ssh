#!/bin/bash
set -e

ROOT_DIR="/root/aws_ssh_panel"
TEMPLATES_DIR="$ROOT_DIR/templates"

echo "[INFO] 停止旧的 Flask 进程..."
pkill -f "$ROOT_DIR/app.py" || true

# ------------------ 重新下载文件 ------------------
echo "[INFO] 下载最新 app.py..."
sudo wget -O $ROOT_DIR/app.py https://raw.githubusercontent.com/shishen12138/ssh/main/app.py

echo "[INFO] 下载最新 index.html..."
sudo wget -O $TEMPLATES_DIR/index.html https://raw.githubusercontent.com/shishen12138/ssh/main/templates/index.html

echo "[INFO] 下载最新 hosts.json..."
sudo wget -O $ROOT_DIR/hosts.json https://raw.githubusercontent.com/shishen12138/ssh/main/hosts.json

echo "[INFO] 下载最新 logs.txt..."
sudo wget -O $ROOT_DIR/logs.txt https://raw.githubusercontent.com/shishen12138/ssh/main/logs.txt

# ------------------ 设置权限 ------------------
echo "[INFO] 设置权限为 777..."
sudo chmod -R 777 $ROOT_DIR

# ------------------ 重启 Flask ------------------
echo "[INFO] 启动 Flask 面板（端口12138）后台运行..."
nohup python3.13 $ROOT_DIR/app.py > $ROOT_DIR/panel.log 2>&1 &

echo "[INFO] 更新完成！"
echo "访问 Web 面板：http://<服务器IP>:12138"
echo "日志查看：tail -f $ROOT_DIR/panel.log"
