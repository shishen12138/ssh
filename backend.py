from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import asyncio, json, paramiko, datetime, boto3

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

HOSTS_FILE = "hosts.json"
LOGS = []

# ----------------- 数据操作 -----------------
def load_hosts():
    try:
        with open(HOSTS_FILE, "r") as f:
            return json.load(f)
    except:
        return []

def save_hosts(hosts):
    with open(HOSTS_FILE, "w") as f:
        json.dump(hosts, indent=2, fp=f)

def update_host(host_ip, cpu=None, memory=None, status=None, runtime_days=None, password=None):
    hosts = load_hosts()
    for host in hosts:
        if host["ip"] == host_ip:
            if cpu is not None: host["cpu"] = cpu
            if memory is not None: host["memory"] = memory
            if status is not None: host["status"] = status
            if runtime_days is not None: host["runtime_days"] = runtime_days
            if password is not None: host["password"] = password
    save_hosts(hosts)

# ----------------- AWS Key 解析 -----------------
def parse_aws_key(key_str):
    """
    支持格式：
    1. AccessKey----SecretKey
    2. 任意前缀----AccessKey----SecretKey
    """
    parts = key_str.strip().split("----")
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    elif len(parts) >= 3:
        return parts[-2].strip(), parts[-1].strip()
    else:
        raise ValueError("AWS Key 格式错误")

# ----------------- AWS 实例导入 -----------------
def import_aws_instances(access_key, secret_key, default_user="root", default_pwd="Qcy1994@06"):
    ec2_client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name='us-east-1')
    regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
    hosts = []
    for region in regions:
        ec2 = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        reservations = ec2.describe_instances()['Reservations']
        for res in reservations:
            for inst in res['Instances']:
                if inst['State']['Name'] != 'running':
                    continue
                ip = inst.get('PublicIpAddress')
                if not ip:
                    continue
                launch_time = inst['LaunchTime']
                runtime_days = (datetime.datetime.utcnow() - launch_time.replace(tzinfo=None)).days
                hosts.append({
                    "ip": ip,
                    "username": default_user,
                    "password": default_pwd,
                    "aws_key": f"{access_key}----{secret_key}",
                    "cpu": 0,
                    "memory": 0,
                    "runtime_days": runtime_days,
                    "status": "green"
                })
    save_hosts(hosts)
    return hosts

# ----------------- SSH 执行 -----------------
async def ssh_execute(host, command, websocket):
    ip = host["ip"]
    LOGS.append(f"{datetime.datetime.now()} - 开始执行 {ip}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=host["username"], password=host["password"])
        stdin, stdout, stderr = ssh.exec_command(command)
        for line in stdout:
            await websocket.send_json({"ip": ip, "log": line.strip()})
        ssh.close()
        LOGS.append(f"{datetime.datetime.now()} - 完成 {ip}")
    except Exception as e:
        LOGS.append(f"{datetime.datetime.now()} - 错误 {ip}: {e}")
        await websocket.send_json({"ip": ip, "log": f"错误: {e}"})
    finally:
        await websocket.send_json({"ip": ip, "status": "done"})

# ----------------- 实时 CPU/内存监控 -----------------
async def monitor_host(host, websocket):
    ip = host["ip"]
    while True:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=host["username"], password=host["password"], timeout=5)
            stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep Cpu; free -m | grep Mem")
            cpu_line = stdout.readline()
            mem_line = stdout.readline()
            cpu_usage = float(cpu_line.split()[1]) if cpu_line else 0
            mem_usage = float(mem_line.split()[2])/float(mem_line.split()[1])*100 if mem_line else 0
            status = "green"
            if cpu_usage>80 or mem_usage>80: status="red"
            elif cpu_usage>50 or mem_usage>50: status="yellow"
            runtime_days = host["runtime_days"]
            update_host(ip, cpu=int(cpu_usage), memory=int(mem_usage), status=status, runtime_days=runtime_days)
            await websocket.send_json({"action":"update_host","host":load_hosts()[[h['ip'] for h in load_hosts()].index(ip)]})
            ssh.close()
            await asyncio.sleep(5)
        except:
            await asyncio.sleep(5)
            continue

# ----------------- WebSocket -----------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    hosts = load_hosts()
    tasks = [asyncio.create_task(monitor_host(host, ws)) for host in hosts]

    while True:
        try:
            data = await ws.receive_json()
        except:
            break
        action = data.get("action")

        if action == "exec":
            command = data.get("command")
            selected_ips = data.get("ips", [])
            for host in hosts:
                if host["ip"] in selected_ips:
                    await ssh_execute(host, command, ws)

        elif action == "get_hosts":
            for host in hosts:
                await ws.send_json({"action": "update_host", "host": host})

        elif action == "get_logs":
            for log in LOGS:
                await ws.send_json({"log": log})

        elif action == "update_password":
            ip = data["ip"]
            pwd = data["password"]
            update_host(ip, password=pwd)

        elif action == "import_aws":
            raw_key = data.get("aws_key_id")
            try:
                access_key, secret_key = parse_aws_key(raw_key)
                hosts = import_aws_instances(access_key, secret_key)
                for host in hosts:
                    await ws.send_json({"action":"update_host","host":host})
                await ws.send_json({"log":f"AWS 实例导入完成，共 {len(hosts)} 台"})
            except Exception as e:
                await ws.send_json({"log":f"AWS Key 解析错误: {e}"})

# ----------------- 前端 -----------------
@app.get("/")
def index():
    return FileResponse("static/index.html")
