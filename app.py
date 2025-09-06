from flask import Flask, request, jsonify, render_template
import json, os, threading, time, paramiko

app = Flask(__name__)

ROOT_DIR = "/root/aws_ssh_panel"
HOSTS_FILE = os.path.join(ROOT_DIR, "hosts.json")
LOG_FILE = os.path.join(ROOT_DIR, "logs.txt")

def load_hosts():
    if not os.path.exists(HOSTS_FILE):
        return []
    with open(HOSTS_FILE, "r") as f:
        return json.load(f)

def save_hosts(hosts):
    with open(HOSTS_FILE, "w") as f:
        json.dump(hosts, f, indent=2, ensure_ascii=False)

def append_log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/hosts")
def get_hosts():
    return jsonify(load_hosts())

@app.route("/logs")
def get_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify([])
    with open(LOG_FILE, "r") as f:
        return jsonify(f.read().splitlines()[-200:])

@app.route("/add_manual_host", methods=["POST"])
def add_manual_host():
    data = request.json
    hosts = load_hosts()
    hosts.append({
        "ip": data["ip"],
        "name": data["name"],
        "username": data.get("username", "root"),
        "password": data.get("password", "Qcy1994@06"),
        "status": "未连接"
    })
    save_hosts(hosts)
    append_log(f"[手动添加] {data['ip']} 已添加")
    return jsonify({"status": "ok"})

@app.route("/import_aws_hosts", methods=["POST"])
def import_aws_hosts():
    accounts = request.json.get("accounts", [])
    hosts = load_hosts()
    for acc in accounts:
        # 这里模拟导入，真实环境应使用 boto3 获取实例列表
        hosts.append({
            "ip": f"192.168.1.{len(hosts)+1}",
            "name": acc["label"],
            "username": "root",
            "password": "Qcy1994@06",
            "status": "未连接"
        })
        append_log(f"[AWS导入] {acc['label']} -> 192.168.1.{len(hosts)}")
    save_hosts(hosts)
    return jsonify({"status": "ok"})

@app.route("/exec", methods=["POST"])
def exec_command():
    data = request.json
    ips = data.get("ips", [])
    command = data.get("command", "")
    hosts = load_hosts()
    for h in hosts:
        if h["ip"] in ips:
            threading.Thread(target=ssh_exec, args=(h, command)).start()
    return jsonify({"status": "ok"})

def ssh_exec(host, command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host["ip"], username=host["username"], password=host["password"], timeout=10)
        stdin, stdout, stderr = ssh.exec_command(command)
        out = stdout.read().decode()
        err = stderr.read().decode()
        append_log(f"[执行命令] {host['ip']} -> {command}\n输出: {out}\n错误: {err}")
        ssh.close()
    except Exception as e:
        append_log(f"[执行命令错误] {host['ip']} -> {e}")

@app.route("/recover_host", methods=["POST"])
def recover_host():
    ip = request.json.get("ip")
    hosts = load_hosts()
    target = None
    for h in hosts:
        if h["ip"] == ip:
            target = h
            break
    if not target:
        return jsonify({"error": "未找到主机"}), 404
    key = target.get("access_key")
    hosts = [h for h in hosts if h.get("access_key") != key]
    save_hosts(hosts)
    append_log(f"[恢复] 删除 AccessKey={key} 的所有主机，重新拉取")
    return jsonify({"status": "ok"})

@app.route("/update_host", methods=["POST"])
def update_host():
    data = request.json
    ip = data["ip"]
    username = data.get("username")
    password = data.get("password")
    hosts = load_hosts()
    updated = False
    for h in hosts:
        if h["ip"] == ip:
            h["username"] = username
            h["password"] = password
            updated = True
            append_log(f"[修改凭证] {ip} -> 用户名={username}, 密码已更新")
    if updated:
        save_hosts(hosts)
        return jsonify({"status": "ok"})
    else:
        return jsonify({"error": "未找到主机"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=12138, debug=False)
