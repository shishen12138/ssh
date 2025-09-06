from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import json, threading, time, paramiko, os, subprocess, boto3
from botocore.exceptions import ClientError
import concurrent.futures

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

HOST_FILE = "hosts.json"
LOG_FILE = "logs.txt"
monitor_info = {}       # IP -> 监控数据
fail_counter = {}       # IP -> 连续失败次数

# -------------------- 工具函数 --------------------
def load_hosts():
    if not os.path.exists(HOST_FILE):
        return []
    with open(HOST_FILE,"r") as f:
        return json.load(f)

def save_hosts(hosts):
    with open(HOST_FILE,"w") as f:
        json.dump(hosts,f,indent=2)

def append_log(text):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}"
    print(line)
    with open(LOG_FILE,"a") as f:
        f.write(line + "\n")

def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE,"r") as f:
        return f.readlines()

# -------------------- 首页 --------------------
@app.route("/")
def index():
    hosts = load_hosts()
    append_log(f"[DEBUG] 访问首页，共有 {len(hosts)} 台主机")
    return render_template("index.html", hosts=hosts)

# -------------------- 手动添加主机 --------------------
@app.route("/add_manual_host", methods=["POST"])
def add_manual_host():
    data = request.json
    append_log(f"[DEBUG] /add_manual_host 收到: {data}")
    hosts = load_hosts()
    hosts.append({
        "ip": data["ip"],
        "name": data.get("name",""),
        "username": data.get("username","root"),
        "password": data.get("password","Qcy1994@06"),
        "source":"manual"
    })
    save_hosts(hosts)
    append_log(f"[手动添加] {data['ip']}")
    return jsonify({"ip": data["ip"], "username": data.get("username","root")})

# -------------------- AWS 批量导入 --------------------
@app.route("/import_aws_hosts", methods=["POST"])
def import_aws_hosts():
    data = request.json
    append_log(f"[DEBUG] /import_aws_hosts 收到: {data}")
    accounts = data["accounts"]
    hosts = load_hosts()
    count = 0

    for acc in accounts:
        try:
            append_log(f"[DEBUG] 尝试连接 AWS: {acc['label']}")
            session = boto3.Session(
                aws_access_key_id=acc["access_key"],
                aws_secret_access_key=acc["secret_key"],
                region_name="us-east-1"
            )
            ec2 = session.resource("ec2")
            instances = ec2.instances.filter(Filters=[{'Name':'instance-state-name','Values':['running']}])
            for inst in instances:
                ip = inst.public_ip_address or inst.private_ip_address
                if not ip or any(h['ip']==ip for h in hosts):
                    continue
                hosts.append({
                    "ip": ip,
                    "name": inst.tags[0]['Value'] if inst.tags else f"{acc['label']}-{inst.id}",
                    "username": acc.get("username","root"),
                    "password": acc.get("password","Qcy1994@06"),
                    "access_key": acc["access_key"],
                    "secret_key": acc["secret_key"],
                    "source": "aws"
                })
                append_log(f"[AWS导入] {ip} ({acc['label']})")
                count += 1
        except ClientError as e:
            append_log(f"[AWS错误] {acc['label']}: {e}")
            continue

    save_hosts(hosts)
    return jsonify({"count":count})

# -------------------- 恢复主机 --------------------
@app.route("/recover_host", methods=["POST"])
def recover_host():
    ip = request.json.get("ip")
    if not ip:
        return jsonify({"error":"缺少 IP"}), 400
    append_log(f"[DEBUG] /recover_host 收到 IP={ip}")
    hosts = load_hosts()
    target_host = next((h for h in hosts if h["ip"]==ip and h.get("source")=="aws"), None)
    if not target_host:
        append_log(f"[ERROR] 未找到目标主机 {ip}")
        return jsonify({"error":"未找到该主机或非 AWS 来源"}), 400

    access_key = target_host["access_key"]
    hosts = [h for h in hosts if h.get("access_key") != access_key]
    append_log(f"[恢复] 删除旧主机 (Access Key: {access_key})")

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=target_host["secret_key"],
            region_name="us-east-1"
        )
        ec2 = session.resource("ec2")
        instances = ec2.instances.filter(Filters=[{'Name':'instance-state-name','Values':['running']}])
        imported_count = 0
        for inst in instances:
            inst_ip = inst.public_ip_address or inst.private_ip_address
            if not inst_ip or any(h['ip']==inst_ip for h in hosts):
                continue
            hosts.append({
                "ip": inst_ip,
                "name": inst.tags[0]['Value'] if inst.tags else f"{access_key}-{inst.id}",
                "username": "root",
                "password": "Qcy1994@06",
                "access_key": access_key,
                "secret_key": target_host["secret_key"],
                "source": "aws"
            })
            append_log(f"[恢复导入] {inst_ip} ({access_key})")
            imported_count += 1
        save_hosts(hosts)
        return jsonify({"imported_count": imported_count})
    except ClientError as e:
        append_log(f"[恢复 AWS错误] {access_key}: {e}")
        return jsonify({"error": str(e)}), 500

# -------------------- SSH 执行命令 --------------------
@app.route("/exec_command", methods=["POST"])
def exec_command():
    try:
        data = request.json
        append_log(f"[DEBUG] /exec_command 收到: {data}")
        ips = data.get("ips", [])
        command = data.get("command", "")
        hosts = load_hosts()
        for h in hosts:
            if h["ip"] in ips:
                threading.Thread(target=run_ssh, args=(h,command)).start()
        return jsonify({"status":"ok"})
    except Exception as e:
        append_log(f"[ERROR] /exec_command 异常: {e}")
        return jsonify({"error": str(e)}), 500

def run_ssh(host, command):
    ip = host["ip"]
    append_log(f"[DEBUG] run_ssh 被调用: {ip}, command={command}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=host.get("username","root"), password=host.get("password","Qcy1994@06"), timeout=5)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        err = stderr.read().decode()
        append_log(f"[SSH输出] {ip}:\n{output}\n{err}")
        ssh.close()
    except Exception as e:
        append_log(f"[SSH失败] {ip}: {e}")

# -------------------- 监控数据抓取 --------------------
def fetch_host_monitor(host):
    ip = host["ip"]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=host.get("username","root"), password=host.get("password","Qcy1994@06"), timeout=5)

        stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
        cpu = float(stdout.read().decode().strip() or 0)
        stdin, stdout, stderr = ssh.exec_command("free | grep Mem | awk '{print $3/$2 * 100.0}'")
        memory = float(stdout.read().decode().strip() or 0)
        stdin, stdout, stderr = ssh.exec_command("cat /proc/net/dev | awk 'NR>2{rx+=$2; tx+=$10} END{print rx/1024\"/\"tx/1024}'")
        network = stdout.read().decode().strip()
        stdin, stdout, stderr = ssh.exec_command("ps -eo pid,comm,%cpu --sort=-%cpu | head -n 6")
        top5 = stdout.read().decode().strip()
        try:
            ping_res = subprocess.check_output(["ping","-c","1","-W","1", ip], universal_newlines=True)
            ping_line = [line for line in ping_res.split("\n") if "time=" in line][0]
            ping = float(ping_line.split("time=")[1].split(" ")[0])
        except Exception:
            ping = -1

        ssh.close()
        fail_counter[ip] = 0  # 成功 → 重置失败计数
        return ip, {"cpu":round(cpu,2),"memory":round(memory,2),"network":network,"top5_processes":top5,"ping":ping,"online":True}

    except Exception as e:
        append_log(f"[监控失败] {ip}: {e}")
        fail_counter[ip] = fail_counter.get(ip,0)+1
        if fail_counter[ip] >= 10:
            append_log(f"[自动恢复触发] {ip} 连续10次监控失败")
            threading.Thread(target=recover_host_thread, args=(ip,)).start()
            fail_counter[ip] = 0
        return ip, {"cpu":0,"memory":0,"network":"-","top5_processes":"-","ping":-1,"online":False}

def recover_host_thread(ip):
    try:
        with app.test_request_context(json={"ip": ip}):
            recover_host()
    except Exception as e:
        append_log(f"[自动恢复失败] {ip}: {e}")

# -------------------- WebSocket 后台推送 --------------------
def update_monitor():
    while True:
        hosts = load_hosts()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(fetch_host_monitor,h): h for h in hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, data = future.result()
                monitor_info[ip] = data
        socketio.emit('message', {'type':'monitor_data','data':monitor_info})
        time.sleep(5)

def push_logs():
    last_pos = 0
    while True:
        logs = read_logs()
        new_logs = logs[last_pos:]
        last_pos = len(logs)
        if new_logs:
            socketio.emit('message', {'type':'logs','logs':new_logs})
        time.sleep(2)

# -------------------- 修改密码 --------------------
@app.route("/change_password", methods=["POST"])
def change_password():
    data = request.json
    ip = data["ip"]
    password = data["password"]
    hosts = load_hosts()
    for h in hosts:
        if h["ip"]==ip:
            h["password"]=password
            append_log(f"[修改密码] {ip}")
    save_hosts(hosts)
    return jsonify({"status":"ok"})

# -------------------- WebSocket 事件 --------------------
@socketio.on('connect')
def ws_connect():
    append_log("[WS] 前端连接建立")
    emit('message', {'type':'info','msg':'连接成功'})

# -------------------- 启动后台线程 --------------------
threading.Thread(target=update_monitor, daemon=True).start()
threading.Thread(target=push_logs, daemon=True).start()

# -------------------- 启动 Flask+SocketIO --------------------
if __name__=="__main__":
    append_log("[DEBUG] Flask+SocketIO 服务启动中...")
    socketio.run(app, host="0.0.0.0", port=12138)
