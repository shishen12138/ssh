from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import asyncio, json, paramiko, datetime, boto3

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

HOSTS_FILE = "hosts.json"
LOGS = []
file_lock = asyncio.Lock()  # 🔒 文件写锁


# ----------------- 数据操作 -----------------
def load_hosts():
    try:
        with open(HOSTS_FILE, "r") as f:
            return json.load(f)
    except:
        return []


async def save_hosts(hosts):
    """带锁的保存，避免并发写入冲突"""
    async with file_lock:
        with open(HOSTS_FILE, "w") as f:
            json.dump(hosts, f, indent=2)


def update_host_sync(host_ip, cpu=None, memory=None, status=None, runtime_days=None, password=None):
    hosts = load_hosts()
    for host in hosts:
        if host["ip"] == host_ip:
            if cpu is not None: host["cpu"] = cpu
            if memory is not None: host["memory"] = memory
            if status is not None: host["status"] = status
            if runtime_days is not None: host["runtime_days"] = runtime_days
            if password is not None: host["password"] = password
    # 因为 update_host 可能在同步函数里调用，这里用 run_until_complete 包装
    asyncio.get_event_loop().run_until_complete(save_hosts(hosts))


# ----------------- AWS Key 解析 -----------------
def parse_aws_key(key_str):
    parts = key_str.strip().split("----")
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    elif len(parts) >= 3:
        return parts[-2].strip(), parts[-1].strip()
    else:
        raise ValueError("AWS Key 格式错误")


# ----------------- 异步 AWS 实例导入 -----------------
async def import_aws_instances_async(raw_key, websocket, default_user="root", default_pwd="Qcy1994@06"):
    try:
        access_key, secret_key = parse_aws_key(raw_key)
    except Exception as e:
        await websocket.send_json({"log": f"AWS Key 格式错误: {e}"})
        return []

    await websocket.send_json({"log": "开始导入 AWS 实例..."})
    hosts = []

    try:
        ec2_client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name='us-east-1')
        regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        await websocket.send_json({"log": f"共找到 {len(regions)} 个区域，开始遍历..."})

        for region in regions:
            await websocket.send_json({"log": f"正在连接区域: {region}"})
            try:
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
                        host_info = {
                            "ip": ip,
                            "username": default_user,
                            "password": default_pwd,
                            "aws_key": f"{access_key}----{secret_key}",
                            "cpu": 0,
                            "memory": 0,
                            "runtime_days": runtime_days,
                            "status": "green"
                        }
                        hosts.append(host_info)
                        await websocket.send_json({"action": "update_host", "host": host_info})
            except Exception as e:
                await websocket.send_json({"log": f"区域 {region} 访问失败: {e}"})

        # ✅ 追加保存，而不是覆盖
        all_hosts = load_hosts()
        all_hosts.extend(hosts)
        await save_hosts(all_hosts)

        await websocket.send_json({"log": f"AWS 实例导入完成，共 {len(hosts)} 台"})

    except Exception as e:
        await websocket.send_json({"log": f"AWS 导入异常: {e}"})

    return hosts


# ----------------- SSH 执行 -----------------
async def ssh_execute(host, command, websocket):
    ip = host["ip"]
    LOGS.append(f"{datetime.datetime.now()} - 开始执行 {ip}")
    await websocket.send_json({"ip": ip, "status": "running"})
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


# ----------------- 远程实例监控 -----------------
async def monitor_host(host, websocket):
    ip = host["ip"]
    while True:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=host["username"], password=host["password"], timeout=5)

            # CPU
            stdin, stdout, stderr = ssh.exec_command("which mpstat")
            mpstat_path = stdout.readline().strip()
            if mpstat_path:
                stdin, stdout, stderr = ssh.exec_command("mpstat 1 1 | awk '/Average/ {print 100-$12}'")
                cpu_line = stdout.readline()
                cpu_usage = float(cpu_line.strip()) if cpu_line else 0
            else:
                stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep Cpu")
                cpu_line = stdout.readline()
                cpu_usage = 0
                if cpu_line:
                    parts = cpu_line.replace(",", ".").split()
                    for p in parts:
                        if "%us" in p or "%sy" in p:
                            try:
                                cpu_usage += float(p.replace("%us", "").replace("%sy", ""))
                            except:
                                continue

            # 内存
            stdin, stdout, stderr = ssh.exec_command("free | awk '/Mem:/ {printf \"%.2f\", $3/$2*100}'")
            mem_line = stdout.readline()
            mem_usage = float(mem_line.strip()) if mem_line else 0

            status = "green"
            if cpu_usage > 80 or mem_usage > 80:
                status = "red"
            elif cpu_usage > 50 or mem_usage > 50:
                status = "yellow"

            runtime_days = host["runtime_days"]
            update_host_sync(ip, cpu=int(cpu_usage), memory=int(mem_usage), status=status, runtime_days=runtime_days)

            await websocket.send_json({
                "action": "update_host",
                "host": load_hosts()[[h['ip'] for h in load_hosts()].index(ip)]
            })

            ssh.close()
            await asyncio.sleep(5)

        except Exception as e:
            # ✅ 打印异常日志
            await websocket.send_json({"ip": ip, "log": f"监控异常: {e}"})
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
            tasks = [ssh_execute(host, command, ws) for host in hosts if host["ip"] in selected_ips]
            await asyncio.gather(*tasks)

        elif action == "get_hosts":
            for host in hosts:
                await ws.send_json({"action": "update_host", "host": host})

        elif action == "get_logs":
            for log in LOGS:
                await ws.send_json({"log": log})

        elif action == "update_password":
            ip = data["ip"]
            pwd = data["password"]
            update_host_sync(ip, password=pwd)

        elif action == "import_aws":
            raw_key = data.get("aws_key_id")
            if raw_key:
                asyncio.create_task(import_aws_instances_async(raw_key, ws))


# ----------------- 前端 -----------------
@app.get("/")
def index():
    return FileResponse("static/index.html")
