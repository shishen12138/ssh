from flask import Flask, render_template, request, jsonify
import json, threading, time, paramiko, os
import boto3
from botocore.exceptions import ClientError
import concurrent.futures
import subprocess

app = Flask(__name__)

HOST_FILE = "hosts.json"
LOG_FILE = "logs.txt"
monitor_info = {}  # IP -> 数据

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
    print(line)  # 同时输出到控制台
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
    return jsonify({"ip":data["ip"]})

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
                region_name="us-east-1"   # 默认区域
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
    ip = request.json["ip"]
    append_log(f"[DEBUG] /recover_host 收到 IP={ip}")
    hosts = load_hosts()

    target_host = next((h for h in hosts if h["ip"]==ip and h.get("source")=="aws"), None)
    if not target_host:
        append_log("[ERROR] 未找到目标主机")
        return jsonify({"error":"未找到该主机或非 AWS 来源"}), 400

    access_key = target_host["access_key"]
    secret_key = target_host["secret_key"]

    hosts = [h for h in hosts if h.get("access_key") != access_key]
    append_log(f"[恢复] 删除旧主机 (Access Key: {access_key})")

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
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
                "secret_key": secret_key,
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
        if not data:
            return jsonify({"error":"未收到数据"}), 400

        ips = data.get("ips", [])
        command = data.get("command", "")
        hosts = load_hosts()
        for h in hosts:
            if h["ip"] in ips:
                append_log(f"[DEBUG] 准备执行 {command} on {h['ip']}")
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
        append_log(f"[DEBUG] 已连接 {ip}")
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        err = stderr.read().decode()
        append_log(f"[SSH输出] {ip}:\n{output}\n{err}")
        ssh.close()
    except Exception as e:
        append_log(f"[SSH失败] {ip}: {e}")

# -------------------- 多线程实时监控 --------------------
def fetch_host_monitor(host):
    ip = host["ip"]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=host.get("username","root"), password=host.get("password","Qcy1994@06"), timeout=5)
        append_log(f"[DEBUG] 监控连接成功 {ip}")

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
        return ip, {
            "cpu": round(cpu,2),
            "memory": round(memory,2),
            "network": network,
            "top5_processes": top5,
            "ping": ping
        }
    except Exception as e:
        append_log(f"[监控失败] {ip}: {e}")
        return ip, {"cpu":0,"memory":0,"network":"-","top5_processes":"-","ping":-1}

def update_monitor():
    while True:
        hosts = load_hosts()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(fetch_host_monitor, h): h for h in hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, data = future.result()
                monitor_info[ip] = data
        time.sleep(5)

@app.route("/monitor_data")
def monitor_data():
    return jsonify(monitor_info)

# -------------------- 日志 --------------------
@app.route("/logs")
def logs():
    return jsonify({"logs": read_logs()})

# -------------------- 启动后台监控 --------------------
threading.Thread(target=update_monitor, daemon=True).start()

# -------------------- 启动 Flask --------------------
if __name__ == "__main__":
    append_log("[DEBUG] Flask 服务启动中...")
    app.run(host="0.0.0.0", port=12138, debug=True)
