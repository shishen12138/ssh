#!/bin/bash
set -e

# -------------------- 配置 --------------------
PYTHON_VERSION=3.13.6
APP_DIR=/root/aws-ssh-panel
VENV_DIR=$APP_DIR/venv
REPO_URL="https://raw.githubusercontent.com/shishen12138/ssh/main"
SERVICE_FILE="/etc/systemd/system/aws-panel.service"

# 使用非交互模式
export DEBIAN_FRONTEND=noninteractive

# -------------------- 安装依赖 --------------------
echo "[1/5] 安装必需依赖..."
apt install -y build-essential wget curl git libssl-dev zlib1g-dev \
    libncurses5-dev libffi-dev libsqlite3-dev libbz2-dev libreadline-dev \
    liblzma-dev tk-dev -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# -------------------- 安装 Python --------------------
echo "[2/5] 下载并编译 Python $PYTHON_VERSION..."
cd /usr/src
if [ ! -f Python-${PYTHON_VERSION}.tgz ]; then
    wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz
fi
tar xzf Python-${PYTHON_VERSION}.tgz
cd Python-${PYTHON_VERSION}
./configure --enable-optimizations
make -j$(nproc)
make altinstall

# -------------------- 下载项目文件 --------------------
echo "[3/5] 创建应用目录并下载文件..."
mkdir -p $APP_DIR
cd $APP_DIR

for file in backend.py frontend.html hosts.json; do
    curl -s -O ${REPO_URL}/$file
done

chmod 777 backend.py frontend.html hosts.json

# -------------------- 虚拟环境 + 依赖 --------------------
echo "[4/5] 创建虚拟环境并安装 Python 包..."
/usr/local/bin/python3.13 -m venv $VENV_DIR
source $VENV_DIR/bin/activate
pip install --upgrade pip
pip install flask flask-socketio eventlet paramiko boto3

# -------------------- 创建 systemd 服务 --------------------
echo "[5/5] 创建 systemd 服务并启动..."
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

systemctl daemon-reload
systemctl enable aws-panel
systemctl start aws-panel

echo "✅ 安装完成！服务已后台运行并开机自启。"
echo "访问面板: http://<服务器IP>:12138/frontend.html"
echo "实时日志: journalctl -u aws-panel -f"
