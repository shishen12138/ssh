"""
backend.py

功能：
- 提供 REST API（/hosts, /add_host, /import_aws, /run_command）
- 使用 Paramiko 与每台主机保持长 SSH 会话，实现实时 CPU/MEM 推送
- 使用 Flask-SocketIO 将 host_metrics 与 log 事件推送给前端
- 支持顺序逐台执行命令（队列），每台执行完再执行下一台，输出实时推送到日志框
- 保存 hosts 到 hosts.json（含用户名/密码/metadata）
"""

import json
import os
import threading
import time
import uuid
from queue import Queue
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_socketio import SocketIO
import paramiko
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# ---------- 配置 ----------
HOSTS_FILE = 'hosts.json'
WEB_PORT = 12138
DEFAULT_USERNAME = 'root'
DEFAULT_PASSWORD = 'Qcy1994@06'
RECONNECT_DELAY = 5
VMSTAT_INTERVAL = 2

# Flask + SocketIO
app = Flask(__name__, static_url_path='', static_folder='.')
app.config['SECRET_KEY'] = 'replace-with-secure-key'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')

# ---------- 存储 ----------
hosts_lock = threading.Lock()
hosts = []
connection_managers = {}
command_queue = Queue()

# ---------- 工具 ----------
def now_ts():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def emit_log(msg):
    payload = {'ts': now_ts(), 'msg': msg}
    socketio.emit('log', payload)
    print(f"[LOG] {payload['ts']} {msg}")

def save_hosts():
    with hosts_lock:
        with open(HOSTS_FILE, 'w') as f:
            json.dump(hosts, f, indent=2)

def load_hosts():
    global hosts
    if os.path.exists(HOSTS_FILE):
        try:
            with open(HOSTS_FILE, 'r') as f:
                hosts = json.load(f)
        except:
            hosts = []
    else:
        hosts = []

def make_host(ip, user=None, password=None):
    return {
        'id': str(uuid.uuid4()),
        'ip': ip,
        'user': user or DEFAULT_USERNAME,
        'password': password or DEFAULT_PASSWORD,
        'selected': False,
        'status': 'idle',
        'cpu': 0,
        'mem': 0
    }

# ---------- SSH 长连接 ----------
class ConnectionManager:
    def __init__(self, host):
        self.host = host
        self._stop_event = threading.Event()
        self._thread = None
        self._client = None
        self._chan = None
        self._lock = threading.Lock()
        self._reader_thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._maintain_connection_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        try:
            if self._chan: self._chan.close()
        except: pass
        try:
            if self._client: self._client.close()
        except: pass

    def _connect(self):
        ip = self.host['ip']
        user = self.host.get('user', DEFAULT_USERNAME)
        password = self.host.get('password', DEFAULT_PASSWORD)
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=user, password=password, timeout=10, look_for_keys=False, allow_agent=False)
            return client, None
        except Exception as e:
            return None, str(e)

    def _maintain_connection_loop(self):
        ip = self.host['ip']
        while not self._stop_event.is_set():
            client, err = self._connect()
            if client:
                with self._lock:
                    self._client = client
                emit_log(f"[{ip}] SSH 已连接")
                with hosts_lock:
                    self.host['status'] = 'connected'
                try:
                    chan = client.invoke_shell()
                    with self._lock:
                        self._chan = chan
                    time.sleep(0.2)
                    chan.send(f"vmstat {VMSTAT_INTERVAL}\n")
                    self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
                    self._reader_thread.start()
                    while not self._stop_event.is_set() and self._reader_thread.is_alive():
                        time.sleep(0.5)
                except Exception as e:
                    emit_log(f"[{ip}] 启动 vmstat/reader 失败: {e}")
                finally:
                    try: 
                        with self._lock:
                            if self._chan: self._chan.close(); self._chan=None
                    except: pass
                    try: 
                        with self._lock:
                            if self._client: self._client.close(); self._client=None
                    except: pass
                    with hosts_lock:
                        self.host['status']='idle'
            else:
                emit_log(f"[{ip}] SSH 连接失败: {err}")
                with hosts_lock:
                    self.host['status']='error'
                for _ in range(RECONNECT_DELAY):
                    if self._stop_event.is_set(): break
                    time.sleep(1)

    def _reader_loop(self):
        ip=self.host['ip']
        chan=None
        with self._lock: chan=self._chan
        if not chan: return
        buf=""
        while not self._stop_event.is_set():
            try:
                if chan.recv_ready():
                    data=chan.recv(4096).decode(errors='ignore')
                    if not data: time.sleep(0.2); continue
                    buf+=data
                    lines=buf.splitlines()
                    if not buf.endswith("\n"):
                        buf=lines[-1]
                        lines=lines[:-1]
                    else:
                        buf=""
                    for ln in lines:
                        ln=ln.strip()
                        if not ln: continue
                        parts=ln.split()
                        if len(parts)<5 or not parts[0].isdigit(): continue
                        try: idle=float(parts[-3]) if len(parts)>=6 else float(parts[-1])
                        except: 
                            try: idle=float(parts[-1])
                            except: continue
                        cpu_percent=int(max(0,min(100,round(100.0-idle))))
                        with hosts_lock:
                            self.host['cpu']=cpu_percent
                        socketio.emit('host_metrics',{'id':self.host['id'],'cpu':cpu_percent,'mem':self.host.get('mem',0)})
                else: time.sleep(0.2)
            except Exception as e:
                emit_log(f"[{ip}] reader 异常: {e}")
                break
        emit_log(f"[{ip}] 实时监控线程退出")

    def exec_command(self, command):
        ip=self.host['ip']
        user=self.host.get('user', DEFAULT_USERNAME)
        password=self.host.get('password', DEFAULT_PASSWORD)
        emit_log(f"[{ip}] 准备执行命令: {command}")
        with self._lock: client=self._client
        created_temp=False
        if not client:
            client, err=self._connect()
            if not client:
                emit_log(f"[{ip}] 临时连接失败: {err}")
                return False
            created_temp=True
        try:
            chan=client.get_transport().open_session()
            chan.get_pty()
            chan.exec_command(command)
            while True:
                if chan.recv_ready():
                    out=chan.recv(4096).decode(errors='ignore')
                    for line in out.splitlines(): emit_log(f"[{ip}] {line}")
                if chan.recv_stderr_ready():
                    serr=chan.recv_stderr(4096).decode(errors='ignore')
                    for line in serr.splitlines(): emit_log(f"[{ip}][ERR] {line}")
                if chan.exit_status_ready(): break
                time.sleep(0.1)
            status=chan.recv_exit_status()
            emit_log(f"[{ip}] 命令完成，退出状态 {status}")
            return status==0
        finally:
            if created_temp:
                try: client.close()
                except: pass

# ---------- 命令队列 ----------
def command_consumer():
    while True:
        task=command_queue.get()
        if task is None: break
        ids=task.get('hosts',[])
        cmd=task.get('command','')
        if not ids or not cmd: command_queue.task_done(); continue
        for hid in ids:
            with hosts_lock:
                h=next((x for x in hosts if x['id']==hid),None)
                if not h: emit_log(f"[{hid}] 未找到主机"); continue
                h['status']='running'
            mgr=connection_managers.get(hid)
            if not mgr:
                mgr=ConnectionManager(h)
                connection_managers[hid]=mgr
                mgr.start()
                time.sleep(1)
            success=mgr.exec_command(cmd)
            with hosts_lock:
                h['status']='idle' if success else 'error'
        emit_log("批量命令执行队列任务完成")
        command_queue.task_done()

threading.Thread(target=command_consumer,daemon=True).start()

# ---------- Flask API ----------
@app.route('/')
def index():
    if os.path.exists('./frontend.html'):
        return send_from_directory('.', 'frontend.html')
    return "Not Found",404

@app.route('/hosts',methods=['GET'])
def api_get_hosts():
    with hosts_lock: return jsonify(hosts)

@app.route('/add_host',methods=['POST'])
def api_add_host():
    data=request.json or {}
    ip=data.get('ip')
    user=data.get('user',DEFAULT_USERNAME)
    password=data.get('password',DEFAULT_PASSWORD)
    if not ip: return jsonify({'ok':False,'error':'missing ip'}),400
    h=make_host(ip,user,password)
    with hosts_lock:
        hosts.append(h)
        save_hosts()
    mgr=ConnectionManager(h)
    connection_managers[h['id']]=mgr
    mgr.start()
    emit_log(f"已添加主机 {ip}")
    return jsonify({'ok':True,'host':h})

@app.route('/import_aws',methods=['POST'])
def api_import_aws():
    data=request.json or {}
    access=data.get('access_key')
    secret=data.get('secret_key')
    region=data.get('region','us-east-1')
    if not access or not secret: return jsonify({'ok':False,'error':'missing aws keys'}),400
    try:
        ec2=boto3.client('ec2',aws_access_key_id=access,aws_secret_access_key=secret,region_name=region)
        resp=ec2.describe_instances()
        added=0
        details=[]
        for r in resp.get('Reservations',[]):
            for inst in r.get('Instances',[]):
                ip=inst.get('PublicIpAddress') or inst.get('PrivateIpAddress')
                if ip:
                    h=make_host(ip)
                    h['aws_key']={'access_key':access,'secret_key':secret,'region':region}
                    with hosts_lock:
                        hosts.append(h)
                        save_hosts()
                    mgr=ConnectionManager(h)
                    connection_managers[h['id']]=mgr
                    mgr.start()
                    added+=1
                    details.append(ip)
        emit_log(f"AWS 导入完成：新增 {added} 台")
        return jsonify({'ok':True,'added':added,'details':details})
    except (BotoCoreError,ClientError) as e:
        return jsonify({'ok':False,'error':str(e)}),500

@app.route('/run_command',methods=['POST'])
def api_run_command():
    data=request.json or {}
    ids=data.get('hosts') or []
    cmd=data.get('command','')
    if not ids or not cmd: return jsonify({'ok':False,'error':'missing hosts or command'}),400
    command_queue.put({'hosts':ids,'command':cmd})
    emit_log(f"接收到运行命令请求，队列长度 {command_queue.qsize()}")
    return jsonify({'ok':True})

@app.route('/frontend.html')
def serve_frontend():
    return send_from_directory('.', 'frontend.html')

# ---------- SocketIO ----------
@socketio.on('connect')
def on_connect(): emit_log("前端已连接 Socket.IO")

# ---------- 启动 ----------
if __name__=='__main__':
    load_hosts()
    with hosts_lock:
        for h in hosts:
            mgr=ConnectionManager(h)
            connection_managers[h['id']]=mgr
            mgr.start()
    emit_log(f"后端启动，监听端口 {WEB_PORT}")
    socketio.run(app, host='0.0.0.0', port=WEB_PORT)
