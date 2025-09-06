#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

PYTHON_VERSION=3.13.6
APP_DIR=/root/aws-ssh-panel
VENV_DIR=$APP_DIR/venv
REPO_URL="https://raw.githubusercontent.com/shishen12138/ssh/main"
SERVICE_FILE="/etc/systemd/system/aws-panel.service"

echo "[1/9] 更新系统（非交互）..."
apt update -y
apt upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
apt install -y build-essential wget curl git libssl-dev zlib1g-dev \
    libncurses5-dev libffi-dev libsqlite3-dev libbz2-dev libreadline-dev \
    liblzma-dev tk-dev -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

echo "[2/9] 下载并编译 Python $PYTHON_VERSION..."
cd /usr/src
if [ ! -f Python-${PYTHON_VERSION}.tgz ]; then
    wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz
fi
tar xzf Python-${PYTHON_VERSION}.tgz
cd Python-${PYTHON_VERSION}
./configure --enable-optimizations
make -j$(nproc)
make altinstall

echo "[3/9] 创建应用目录..."
mkdir -p $APP_DIR
cd $APP_DIR

echo "[4/9] 下载后端文件..."
for file in backend.py frontend.html hosts.json; do
    curl -s -O ${REPO_URL}/$file
done

echo "[5/9] 设置文件权限 777..."
chmod 777 backend.py frontend.html hosts.json

echo "[6/9] 创建虚拟环境并安装依赖..."
/usr/local/bin/python3.13 -m venv $VENV_DIR
source $VENV_DIR/bin/activate
pip install --upgrade pip
pip install flask flask-socketio eventlet paramiko boto3

echo "[7/9] 创建 systemd 服务（后台运行）..."
cat > $SERVICE_FILE <<EOF
[Unit]
Description=AWS SSH Web Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=$VENV_DIR/bin/python $APP_DIR/backend.py
Restart=always
RestartSec=5
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[8/9] 启动服务并开机自启..."
systemctl daemon-reload
systemctl enable aws-panel
systemctl start aws-panel

echo "[9/9] 安装完成 ✅"
echo "后台运行中，访问面板: http://<服务器IP>:12138/frontend.html"
echo "查看实时日志: journalctl -u aws-panel -f"
