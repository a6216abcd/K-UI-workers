#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, urllib.parse, json, ipaddress, hashlib, hmac, sys, re
from collections import deque
from pathlib import Path
import proxy_server
try:
    from realtime_client import RealtimeChannel
except ImportError:
    class RealtimeChannel:
        def __init__(self, *args, **kwargs): self.connected = False; self.enabled = False; self.ever_connected = False; self.last_disconnected = 0; self.started_at = 0
        def start(self): pass
        def stop(self): pass
        def send(self, data, message_type="status"): return False

API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = os.environ.get("C2_URL", "https://YOUR_CONTROLLER_DOMAIN")
UPDATE_ORIGIN = os.environ.get("UPDATE_ORIGIN", "")
# 控制器 API 前缀：本地 (CF Pages) 控制器为 /api/proxy；独立部署的原版控制器为 /api
C2_API_PREFIX = os.environ.get("C2_API_PREFIX", "/api/proxy")
if urllib.parse.urlsplit(C2_URL).scheme != "https":
    raise RuntimeError("C2_URL must use HTTPS")
if UPDATE_ORIGIN and urllib.parse.urlsplit(UPDATE_ORIGIN).scheme != "https":
    raise RuntimeError("UPDATE_ORIGIN must use HTTPS")
if C2_API_PREFIX not in {"/api", "/api/proxy"}:
    raise RuntimeError("invalid C2_API_PREFIX")

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"

def env_secret(name, default=""):
    encoded = os.environ.get(name + "_B64")
    if encoded:
        try: return base64.b64decode(encoded).decode("utf-8")
        except Exception: return default
    return os.environ.get(name, default)

WEB_USER = env_secret("WEB_USER", "admin")
WEB_PASS = env_secret("WEB_PASS")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
if not AGENT_TOKEN:
    try: AGENT_TOKEN = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "kui", "config.json"))).get("token", "")
    except Exception: pass
VPS_IP = os.environ.get("VPS_IP", "")

PROXY_PORT = 7920
target_country = "JP"
last_switch_trigger = 0
config_generation = 0
last_config_sync = 0
last_config_log = ""
last_update_check = 0
REALTIME_URL = os.environ.get("REALTIME_URL", "")
realtime_channel = None
config_wakeup = threading.Event()
heartbeat_wakeup = threading.Event()
last_http_report = 0
REALTIME_HTTP_INTERVAL = 900
REALTIME_STATUS_ACTIVE_INTERVAL = 5
REALTIME_STATUS_IDLE_INTERVAL = 30
realtime_status_interval = REALTIME_STATUS_ACTIVE_INTERVAL

state_lock = threading.Lock()
dead_ips = set()
last_blacklist_clear = time.time()
public_ip = ""

global_node_reservoir = {} 
reservoir_lock = threading.Lock()

class Tunnel:
    def __init__(self, name: str, table_id: int):
        self.name = name
        self.table_id = table_id
        self.process = None
        self.node = None
        self.entry_ip = ""
        self.egress_ip = ""
        self.country = ""
        self.ready = False
        self.connected_at = 0
        self.is_connecting = False

tun_main = Tunnel("tun_main", 101)
tun_backup = Tunnel("tun_backup", 102)

def penalize_node(ip: str, penalty: int):
    """
    节点信誉动态降级机制：
    给不可用或低质的节点加上高额的虚拟 ping 值惩罚，
    确保下一次调度排序时，该节点被永久压入蓄水池底部，从而避免"死循环假性枯竭"。
    """
    with reservoir_lock:
        if ip in global_node_reservoir:
            global_node_reservoir[ip]["ping"] += penalty

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
        if public_ip and ':' in public_ip:
            raise ValueError("Got IPv6")
    except:
        try:
            req = urllib.request.Request("https://api.ipify.org?format=text",
                                          headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=5) as res:
                public_ip = res.read().decode("utf-8").strip()
        except:
            public_ip = "Unknown_IP"

def get_c2_headers():
    if AGENT_TOKEN:
        return {"User-Agent": "KUI-Residential-Agent/2.0", "Authorization": AGENT_TOKEN}
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Authorization": f"Basic {auth_ptr}"
    }

def check_for_updates():
    global last_update_check
    now = time.time()
    if not AGENT_TOKEN or now - last_update_check < 3600:
        return
    last_update_check = now
    components = (("realtime-client", (Path(__file__).parent / "realtime_client.py").resolve()), ("proxy-manager", Path(__file__).resolve()), ("proxy-server", (Path(__file__).parent / "proxy_server.py").resolve()))
    staged = []
    temporary_files = []
    try:
        for component, target in components:
            if not UPDATE_ORIGIN: raise ValueError("UPDATE_OR is required for updates")
            url = f"{UPDATE_ORIGIN.rstrip('/')}/api/agent_update?ip={urllib.parse.quote(VPS_IP, safe='')}&component={component}"
            request = urllib.request.Request(url, headers=get_c2_headers())
            with urllib.request.urlopen(request, timeout=20) as response:
                source = response.read(2 * 1024 * 1024 + 1)
                expected = response.headers.get("X-Agent-SHA256", "").lower()
                version = response.headers.get("X-Agent-Manifest-Version", "")
                length = response.headers.get("X-Agent-Length", "")
                supplied_mac = response.headers.get("X-Agent-MAC", "").lower()
            manifest = f"v1\n{component}\n{expected}\n{len(source)}\n".encode()
            expected_mac = hmac.new(AGENT_TOKEN.encode(), manifest, hashlib.sha256).hexdigest()
            if len(source) > 2 * 1024 * 1024 or version != "1" or length != str(len(source)) or not re.fullmatch(r"[0-9a-f]{64}", expected) or not hmac.compare_digest(supplied_mac, expected_mac) or hashlib.sha256(source).hexdigest() != expected:
                raise ValueError(f"{component} checksum mismatch")
            if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
                continue
            temporary = target.with_name(target.name + ".update.py")
            temporary_files.append(temporary)
            temporary.write_bytes(source)
            temporary.chmod(0o700)
            checked = subprocess.run([sys.executable, "-m", "py_compile", str(temporary)], capture_output=True, text=True)
            if checked.returncode != 0:
                raise ValueError(f"{component} compile failed: {checked.stderr.strip()}")
            staged.append((temporary, target))
        if not staged:
            return
        replaced = []
        try:
            for temporary, target in staged:
                backup = target.with_name(target.name + ".last-good")
                if target.exists(): backup.write_bytes(target.read_bytes()); backup.chmod(0o700)
                os.replace(temporary, target); replaced.append((target, backup))
        except Exception:
            for target, backup in reversed(replaced):
                if backup.exists(): target.write_bytes(backup.read_bytes()); target.chmod(0o700)
            raise
        marker = WORKSPACE / ".update-pending"
        marker.write_text(json.dumps({"updated_at": int(time.time()), "deadline_at": int(time.time()) + 120})); marker.chmod(0o600)
        print("[update] residential proxy components updated; restarting", flush=True)
        subprocess.run(["pkill", "-f", "openvpn.*tun_main"], capture_output=True)
        subprocess.run(["pkill", "-f", "openvpn.*tun_backup"], capture_output=True)
        os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve())])
    except Exception as error:
        print(f"[update] update check failed: {error}", flush=True)
        for temporary in temporary_files:
            try: temporary.unlink(missing_ok=True)
            except Exception: pass

def get_recent_logs():
    try:
        alpine_log = Path("/var/log/proxy-lite.log")
        if alpine_log.exists():
            with alpine_log.open("r", encoding="utf-8", errors="replace") as log_file:
                return "".join(deque(log_file, maxlen=30))
        res = subprocess.run(["journalctl", "-u", "proxy-lite.service", "-n", "30", "--no-pager", "--output=cat"], capture_output=True, text=True, errors="replace", timeout=10)
        return res.stdout or "Waiting for logs..."
    except: return "Waiting for logs..."

def fetch_controller_config():
    """拉取控制器下发的配置，仅使用代理控制器专用端点。
    注意：/api/config 和 /config 返回的是节点配置而非代理配置，
    缺少 "0"/"country" 字段，使用后会迫使 desired_country 回退为 "JP"，
    导致 VPS 永远无法感知地区变更。
    """
    base = C2_URL.rstrip('/')
    url = f"{base}{C2_API_PREFIX}/config?ip={VPS_IP}"
    try:
        req = urllib.request.Request(url, headers=get_c2_headers())
        with urllib.request.urlopen(req, timeout=10) as res:
            raw = res.read().decode("utf-8")
            data = json.loads(raw)
            if isinstance(data, dict) and (data.get("0") or data.get("country")):
                return data
            else:
                print(f"[cfg] 端点返回数据缺少地区字段(0/country)，跳过: {raw}", flush=True)
    except Exception as e:
        print(f"[cfg] 拉取配置失败({url}): {e}", flush=True)
    return None

def update_config_loop():
    global target_country, last_switch_trigger, PROXY_PORT, tun_main, tun_backup, last_config_log, REALTIME_URL, realtime_channel, config_generation
    while True:
        config_wakeup.clear()
        while realtime_channel and realtime_channel.enabled and not realtime_channel.connected:
            grace_remaining = 30 - (time.time() - (realtime_channel.last_disconnected or realtime_channel.started_at))
            if grace_remaining <= 0:
                break
            config_wakeup.wait(timeout=grace_remaining)
            config_wakeup.clear()
        try:
            check_for_updates()
            data = fetch_controller_config()
            if not data:
                config_wakeup.wait(timeout=300)
                continue
            desired_country = str(data.get("0") or data.get("country") or "JP").upper()
            if not re.fullmatch(r"[A-Z]{2}|ANY", desired_country): raise ValueError("invalid country")
            new_realtime_url = data.get("realtime_url") or ""
            if new_realtime_url and new_realtime_url != REALTIME_URL:
                REALTIME_URL = new_realtime_url
                if realtime_channel: realtime_channel.stop()
                realtime_channel = create_realtime_channel()
                realtime_channel.start()
            switch_trigger = int(data.get("switch_trigger", 0))
            new_port = int(data.get("port", 7920))
            if not 1 <= new_port <= 65535: raise ValueError("invalid proxy port")
            config_log = f"country={desired_country}, port={new_port}, trigger={switch_trigger}"
            if config_log != last_config_log:
                print(f"[cfg] 配置同步: {config_log}", flush=True)
                last_config_log = config_log
            # 同步代理凭证到 proxy_server 模块（让其实时生效，无需重启进程）
            try:
                pc = data.get("proxy") or {}
                if isinstance(pc, dict):
                    enabled = pc.get("enabled") is not False
                    pu = str(pc.get("user", "")) or env_secret("PROXY_USER")
                    pp = str(pc.get("pass", "")) or env_secret("PROXY_PASS")
                    os.environ["PROXY_USER"] = pu
                    os.environ["PROXY_PASS"] = pp
                    if hasattr(proxy_server, "set_credentials"):
                        proxy_server.set_credentials(pu if enabled else "", pp if enabled else "")
                    else:
                        proxy_server.PROXY_USER = pu.encode()
                        proxy_server.PROXY_PASS = pp.encode()
                    if not pu or not pp:
                        print("[cfg] 代理凭证未配置，监听器保持拒绝连接状态", flush=True)
            except Exception as e:
                print(f"[cfg] 凭证同步失败: {e}", flush=True)
            if new_port != PROXY_PORT:
                print(f"[*] 收到端口变更指令 ({PROXY_PORT} -> {new_port})，重启守护进程...", flush=True)
                os._exit(0)
            
            with state_lock:
                force_switch = (switch_trigger > last_switch_trigger)
                if target_country != desired_country or force_switch:
                    config_generation += 1
                    target_country = desired_country
                    if force_switch: print(f"[*] 收到强制更换指令，正在清退通道并拉黑当前 IP...", flush=True)
                    else: print(f"[*] 策略热切换: 目标重定向到 {desired_country}...", flush=True)
                    
                    if tun_main.entry_ip: dead_ips.add(tun_main.entry_ip)
                    if tun_main.process:
                        try: tun_main.process.terminate(); tun_main.process.wait(2)
                        except: tun_main.process.kill()
                    tun_main.ready = False; tun_main.process = None; tun_main.entry_ip = ""; tun_main.egress_ip = ""
                    
                    if tun_backup.process:
                        try: tun_backup.process.terminate(); tun_backup.process.wait(2)
                        except: tun_backup.process.kill()
                    tun_backup.ready = False; tun_backup.process = None; tun_backup.entry_ip = ""; tun_backup.egress_ip = ""
                    
                    last_switch_trigger = switch_trigger
            if realtime_channel and realtime_channel.connected:
                realtime_channel.send({"success": True, "country": desired_country, "switch_trigger": switch_trigger, "applied_at": int(time.time() * 1000)}, "config.result")
        except Exception as e:
            print(f"[cfg] 拉取配置失败: {e}", flush=True)
            if realtime_channel and realtime_channel.connected:
                realtime_channel.send({"success": False, "error": str(e)[:500], "applied_at": int(time.time() * 1000)}, "config.result")
        config_wakeup.wait(timeout=REALTIME_HTTP_INTERVAL if realtime_channel and realtime_channel.connected else 300)

def c2_heartbeat_loop():
    global public_ip, PROXY_PORT, tun_main, tun_backup, last_http_report
    while True:
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with state_lock:
            for tun in [tun_main, tun_backup]:
                if tun.ready and tun.process and tun.process.poll() is None:
                    uptime = time.time() - tun.connected_at
                    details.append({
                        "tunnel": tun.name,
                        "active": proxy_server.ACTIVE_BIND == tun.name,
                        "country": tun.country, 
                        "port": PROXY_PORT, 
                        "connected_time": int(uptime), 
                        "node_ip": tun.egress_ip if tun.egress_ip else tun.entry_ip
                    })
        
        status = {"ip": VPS_IP, "socks_ip": public_ip, "details": details, "logs": get_recent_logs()}
        websocket_sent = realtime_channel.send(status) if realtime_channel and realtime_channel.connected else False
        try:
            fallback_ready = not realtime_channel or not realtime_channel.enabled or time.time() - (realtime_channel.last_disconnected or realtime_channel.started_at) >= 30
            if realtime_channel and realtime_channel.enabled and not websocket_sent and time.time() - realtime_channel.last_disconnected < 30:
                fallback_ready = False
            if (websocket_sent and time.time() - last_http_report >= REALTIME_HTTP_INTERVAL) or (not websocket_sent and fallback_ready):
                req = urllib.request.Request(f"{C2_URL}{C2_API_PREFIX}/report", data=json.dumps(status).encode('utf-8'), headers=get_c2_headers(), method='POST')
                with urllib.request.urlopen(req, timeout=10) as response: response.read(1)
                last_http_report = time.time()
        except Exception as error:
            print(f"[c2] 状态上报失败: {error}", flush=True)
        if realtime_channel and realtime_channel.connected:
            interval = realtime_status_interval
        elif realtime_channel and realtime_channel.enabled and not realtime_channel.ever_connected and time.time() - realtime_channel.started_at < 30:
            interval = max(1, 30 - (time.time() - realtime_channel.started_at))
        elif realtime_channel and realtime_channel.ever_connected and time.time() - realtime_channel.last_disconnected < 30:
            interval = max(1, 30 - (time.time() - realtime_channel.last_disconnected))
        else:
            interval = 90
        heartbeat_wakeup.wait(timeout=interval)
        heartbeat_wakeup.clear()

def on_realtime_message(message):
    global realtime_status_interval
    if message.get("type") == "status.interval":
        requested_interval = int(message.get("seconds", REALTIME_STATUS_IDLE_INTERVAL))
        realtime_status_interval = max(REALTIME_STATUS_ACTIVE_INTERVAL, min(REALTIME_STATUS_IDLE_INTERVAL, requested_interval))
        heartbeat_wakeup.set()
    if message.get("type") in {"config.refresh", "transport.connected", "transport.disconnected"}: config_wakeup.set()
    if message.get("type") in {"transport.connected", "transport.disconnected"}: heartbeat_wakeup.set()

def create_realtime_channel():
    return RealtimeChannel(REALTIME_URL, VPS_IP, AGENT_TOKEN, "proxy", on_realtime_message)

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\nvpn\n", encoding="utf-8")
        AUTH_FILE.chmod(0o600)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], capture_output=True)

def harvest_snapshot_nodes() -> list:
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            try:
                ip = row.get("IP")
                if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
                raw_ping = row.get("Ping", "")
                nodes.append({
                    "ip": ip,
                    "ping": int(raw_ping) if raw_ping.isdigit() else 9999,
                    "country": row.get("CountryShort", "").upper(),
                    "config": sanitize_openvpn_config(base64.b64decode(row["OpenVPN_ConfigData_Base64"], validate=True).decode("utf-8", errors="replace"), ip),
                    "harvested_at": time.time()
                })
            except Exception:
                continue
        return nodes
    except Exception as e: return []

def vpngate_fetch_loop():
    global global_node_reservoir, dead_ips
    while True:
        snapshot = harvest_snapshot_nodes()
        if snapshot:
            with reservoir_lock:
                for n in snapshot:
                    # 保留原有的惩罚性 ping 值，防止坏节点被新抓取的快照刷新后又跑到前列去
                    if n["ip"] in global_node_reservoir:
                        n["ping"] = max(n["ping"], global_node_reservoir[n["ip"]]["ping"])
                    global_node_reservoir[n["ip"]] = n
            print(f"[*] ⚡ 节点库更新，当前囤积有效节点 -> {len(global_node_reservoir)} 个", flush=True)
        else:
            # FIX 3: 如果 VPNGate 接口被限流或不通，延长现有节点的生命周期，防止库干涸
            with reservoir_lock:
                now = time.time()
                for n in global_node_reservoir.values():
                    n["harvested_at"] = now
        time.sleep(300)

def setup_routing(tun_name: str, table_id: int):
    subprocess.run(["ip", "rule", "del", "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id + 1000)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", tun_name, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", tun_name, "lookup", str(table_id), "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "iif", tun_name, "lookup", str(table_id), "pref", str(table_id + 1000)], capture_output=True)

def connect_node(tun: Tunnel, node: dict, generation: int):
    global dead_ips
    try:
        print(f"[*] {tun.name} 开始拨号: {node['country']} {node['ip']} (ping={node['ping']})", flush=True)
        cfg_path = CONFIG_DIR / f"{tun.name}.ovpn"
        log_file = WORKSPACE / f"{tun.name}_err.log"
        cfg_path.write_text(node["config"], encoding="utf-8")
        
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        
        # 强制添加 --nobind 解除端口冲突，--route-nopull 剥夺路由修改权
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", tun.name, "--dev-type", "tun", 
               "--nobind", "--route-nopull",
               "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", 
               "--auth-user-pass", str(AUTH_FILE),
               "--connect-timeout", "5", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
               
        with open(log_file, "w") as f: process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        with state_lock:
            if generation != config_generation:
                process.terminate(); return
            tun.process = process
        
        success = False
        for _ in range(15):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass
                
        if success and process.poll() is None:
            with state_lock:
                if generation != config_generation or (target_country != "ANY" and node.get("country") != target_country):
                    process.terminate(); return
            setup_routing(tun.name, tun.table_id)
            time.sleep(1) 
            
            # --- 穿透获取通道真实出口 IP（纯IPv6+WARP兼容） ---
            true_ip = ""
            try:
                true_ip_res = subprocess.run(["curl", "-s", "-m", "10", "--interface", tun.name, "-4", "https://api.ipify.org"], capture_output=True, text=True)
                candidate_ip = true_ip_res.stdout.strip()
                try:
                    ipaddress.IPv4Address(candidate_ip)
                    true_ip = candidate_ip
                except (ipaddress.AddressValueError, ValueError):
                    pass
            except: pass

            if not true_ip:
                try:
                    true_ip_res = subprocess.run(["curl", "-s", "-m", "10", "--interface", tun.name, "-6", "https://api6.ipify.org"], capture_output=True, text=True)
                    candidate_ip = true_ip_res.stdout.strip()
                    try:
                        ipaddress.IPv6Address(candidate_ip)
                        true_ip = candidate_ip
                    except (ipaddress.AddressValueError, ValueError):
                        pass
                except: pass

            egress_ip = true_ip if true_ip else node['ip']

            if true_ip and true_ip != node['ip']:
                print(f"[*] {tun.name} 探测到真实出口 IP 与入口不一致: 入口 {node['ip']} -> 出口 {true_ip}", flush=True)

            is_residential = True
            try:
                req_url = f"https://testisp.info/api/check?ip={egress_ip}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, method="GET")
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    data = json.loads(check_res.read().decode("utf-8"))
                    print(f"[*] {tun.name} testisp.info 报告 {egress_ip}: {data.get('isp',{})} / native={data.get('geo',{}).get('is_native','?')}", flush=True)
                    isp = data.get("isp", {})
                    geo = data.get("geo", {})
                    isp_flag = str(isp.get("flag", "")).lower()
                    isp_type = str(isp.get("type", "")).lower()
                    isp_warn = str(isp.get("warning", "")).lower()
                    is_native = geo.get("is_native", False)
                    
                    # 综合判断：仅凭 isp.flag == "hosting" 不够可靠
                    # 真机房判定：flag=hosting 且 type 不含 isp/broadband/dsl/cable 且 is_native=False
                    if isp_flag == "hosting":
                        residential_indicators = [
                            "isp" in isp_type,
                            "broadband" in isp_type,
                            "dsl" in isp_type,
                            "cable" in isp_type,
                            is_native is True,
                            "hosting" not in isp_warn and "datacenter" not in isp_warn
                        ]
                        if not any(residential_indicators):
                            is_residential = False
            except Exception as e:
                print(f"[*] {tun.name} testisp.info 查询失败: {e}", flush=True)
            
            if not is_residential:
                print(f"[-] {tun.name} 节点出口 ({egress_ip}) 检测为机房 IP，残忍抛弃！", flush=True)
                penalize_node(node["ip"], 50000)  # 机房 IP 极重惩罚，几乎不再启用
                dead_ips.add(node["ip"])
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            print(f"[*] {tun.name} 流媒体连通性检测 (多端点)...", flush=True)
            stream_ok = False
            for stream_url in [
                "https://www.youtube.com",
                "https://www.gstatic.com/generate_204",
                "https://cp.cloudflare.com/generate_204",
                "https://www.google.com/robots.txt",
            ]:
                r = subprocess.run(["curl", "-o", "/dev/null", "-s", "-w", "%{http_code}", "-A", "Mozilla/5.0", "-m", "10", "--interface", tun.name, stream_url], capture_output=True, text=True)
                code = r.stdout.strip()
                if code and code != "000" and r.returncode == 0:
                    print(f"[+] {tun.name} 端点可达 {stream_url} HTTP {code}", flush=True)
                    stream_ok = True
                    break
                print(f"[*] {tun.name} 端点不可达 {stream_url} (code={code})", flush=True)
            if not stream_ok:
                print(f"[-] {tun.name} 所有流媒体端点均不可达，轻惩罚保留备用: {node['ip']}", flush=True)
                penalize_node(node["ip"], 3000)
                try: process.terminate(); process.wait(2)
                except: process.kill()
                return

            with state_lock:
                if generation != config_generation or (target_country != "ANY" and node.get("country") != target_country):
                    process.terminate(); return
                tun.process = process
                tun.node = node
                # 此时不再需要赋 entry_ip，因为在 maintain_pool 里已提前锁住坑位
                tun.egress_ip = egress_ip
                tun.country = node["country"]
                tun.connected_at = time.time()
                tun.ready = True
            role = "主网卡" if proxy_server.ACTIVE_BIND == tun.name else "备用网卡"
            print(f"[+] {tun.name} ({role}) 完全就绪: 入口 {node['ip']} -> 出口 {egress_ip}", flush=True)
        else:
            try:
                error_tail = "\n".join(log_file.read_text(errors="replace").splitlines()[-12:])
            except Exception:
                error_tail = "无法读取 OpenVPN 日志"
            print(f"[-] {tun.name} 建连失败: {node['ip']}\n{error_tail}", flush=True)
            penalize_node(node["ip"], 5000)  # 建连超时中度惩罚
            try: process.terminate(); process.wait(2)
            except: process.kill()
            dead_ips.add(node["ip"])
    finally:
        with state_lock:
            tun.is_connecting = False
            # 连接未成功时，释放在 maintain_pool 中预占的坑位（entry_ip），
            # 否则该 IP 会被 get_best_candidate 的 active_ips 永久剔除，
            # 在可用节点稀少时会导致备用通道永远填不上（负载率长期卡在 1/2）。
            if not tun.ready:
                tun.entry_ip = ""

def health_check_loop():
    global tun_main, tun_backup, dead_ips
    fail_counts = {}
    while True:
        time.sleep(15 if not any(fail_counts.values()) else 5)
        targets = []
        with state_lock:
            for tunnel in (tun_main, tun_backup):
                if tunnel.ready and tunnel.process and tunnel.process.poll() is None and time.time() - tunnel.connected_at > 20:
                    targets.append((tunnel, tunnel.name, tunnel.entry_ip, tunnel.process))

        for tunnel, target_tun, target_entry_ip, proc_ref in targets:
            is_alive = False
            for endpoint in ["http://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204", "http://1.1.1.1", "http://8.8.8.8"]:
                result = subprocess.run(["curl", "-I", "-s", "-m", "5", "--interface", target_tun, endpoint], capture_output=True)
                if result.returncode == 0:
                    is_alive = True
                    break
            if not is_alive:
                is_alive = subprocess.run(["ping", "-c", "2", "-W", "3", "-I", target_tun, "8.8.8.8"], capture_output=True).returncode == 0

            process_key = id(proc_ref)
            if is_alive:
                fail_counts[process_key] = 0
                continue
            fail_counts[process_key] = fail_counts.get(process_key, 0) + 1
            if fail_counts[process_key] >= 3:
                print(f"[!] {target_tun} 连续探针无响应，执行踢线: {target_entry_ip}", flush=True)
                penalize_node(target_entry_ip, 3000)
                dead_ips.add(target_entry_ip)
                try: proc_ref.terminate(); proc_ref.wait(timeout=2)
                except: proc_ref.kill()
                with state_lock:
                    if tunnel.process == proc_ref:
                        tunnel.ready = False
                fail_counts.pop(process_key, None)
            else:
                print(f"[*] {target_tun} 探针无响应，快速复核 ({fail_counts[process_key]}/3)...", flush=True)

def get_best_candidate():
    global global_node_reservoir, dead_ips, target_country, tun_main, tun_backup
    with reservoir_lock:
        all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x["ping"])
        candidates = [n for n in all_pool_nodes if (target_country == "ANY" or n["country"] == target_country) and n["ip"] not in dead_ips]
        
        with state_lock:
            active_ips = [ip for ip in (tun_main.entry_ip, tun_backup.entry_ip) if ip]
        candidates = [n for n in candidates if n["ip"] not in active_ips]

        if not candidates:
            has_blacklisted = any(target_country == "ANY" or n["country"] == target_country for n in all_pool_nodes)
            if has_blacklisted:
                dead_ips.clear()
                print(f"[!] ⚡ 紧急熔断：[{target_country}] 节点黑名单释放救场（由于动态信誉系统存在，历史坏节点将被沉底）", flush=True)
                candidates = [n for n in all_pool_nodes if (target_country == "ANY" or n["country"] == target_country) and n["ip"] not in active_ips]

        if candidates: return candidates.pop(0)
        country_counts = {}
        for node in all_pool_nodes:
            country_counts[node["country"]] = country_counts.get(node["country"], 0) + 1
        print(f"[!] 无可用 {target_country} 候选；节点分布={country_counts}，黑名单={len(dead_ips)}", flush=True)
    return None

def sanitize_openvpn_config(raw: str, expected_ip: str) -> str:
    allowed = {"proto", "port", "cipher", "auth", "auth-nocache", "remote-cert-tls", "verify-x509-name", "tls-version-min", "tls-cipher", "compress", "comp-lzo", "key-direction", "reneg-sec"}
    blocked = {"script-security", "up", "down", "route-up", "route-pre-down", "plugin", "management", "config", "cd", "chroot", "daemon", "log", "log-append", "writepid", "client-connect", "client-disconnect", "learn-address"}
    blocks = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}
    output = ["client", "dev tun", "nobind", "persist-key", "persist-tun", "remote-random"]
    in_block = None
    for original in raw.splitlines():
        line = original.strip()
        if not line or line.startswith(('#', ';')): continue
        if in_block:
            output.append(line)
            if line.lower() == f"</{in_block}>": in_block = None
            continue
        if line.startswith('<') and line.endswith('>') and not line.startswith('</'):
            name = line[1:-1].strip().lower()
            if name not in blocks: raise ValueError(f"unsafe OpenVPN inline block: {name}")
            in_block = name; output.append(f"<{name}>"); continue
        parts = line.split()
        directive = parts[0].lower()
        if directive in blocked: raise ValueError(f"unsafe OpenVPN directive: {directive}")
        if directive == "remote":
            port = int(parts[2]) if len(parts) > 2 else 1194
            if not 1 <= port <= 65535: raise ValueError("invalid OpenVPN remote port")
            output.append(f"remote {expected_ip} {port}")
        elif directive in allowed:
            output.append(line)
    if in_block: raise ValueError(f"unterminated OpenVPN block: {in_block}")
    if not any(line.startswith("remote ") for line in output): raise ValueError("OpenVPN profile has no remote")
    return "\n".join(output) + "\n"

def maintain_pool():
    global dead_ips, last_blacklist_clear, tun_main, tun_backup
    while True:
        if time.time() - last_blacklist_clear > 600:
            dead_ips.clear()
            last_blacklist_clear = time.time()

        with reservoir_lock:
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips: global_node_reservoir.pop(ip, None)

        with state_lock:
            # FIX 2: 严格检测通道是否正在连接，防止由于尚未就绪导致的错误判死和秒切混乱
            main_dead = False
            if not tun_main.is_connecting:
                if tun_main.process is None or tun_main.process.poll() is not None or not tun_main.ready:
                    main_dead = True

            if main_dead:
                if tun_backup.ready and tun_backup.process and tun_backup.process.poll() is None and not tun_backup.is_connecting:
                    print(f"[*] ⚡ 主通道暴毙，软开关秒切！无缝接管业务至备用通道: 出口 {tun_backup.egress_ip or tun_backup.entry_ip}", flush=True)
                    # 状态互换 (身份对调)
                    tun_main, tun_backup = tun_backup, tun_main
                    proxy_server.ACTIVE_BIND = tun_main.name
                    
                    # 异步清理死掉的旧主卡 (现在的 tun_backup)
                    if tun_backup.process:
                        try: tun_backup.process.terminate(); tun_backup.process.wait(2)
                        except: tun_backup.process.kill()
                    tun_backup.process = None; tun_backup.node = None; tun_backup.entry_ip = ""; tun_backup.egress_ip = ""
                    tun_backup.ready = False; tun_backup.is_connecting = False
                else:
                    if tun_main.process:
                        try: tun_main.process.terminate(); tun_main.process.wait(2)
                        except: tun_main.process.kill()
                    tun_main.process = None; tun_main.ready = False; tun_main.is_connecting = False
                    tun_main.entry_ip = ""; tun_main.egress_ip = ""

        with state_lock:
            needs_main = not tun_main.ready and not tun_main.is_connecting
            needs_backup = not tun_backup.ready and not tun_backup.is_connecting

        if needs_main:
            node = get_best_candidate()
            if node:
                with state_lock: 
                    tun_main.is_connecting = True
                    tun_main.entry_ip = node["ip"] # FIX 1: 提前占住坑位，防止备用通道刚好获取到同样的 IP 导致死锁冲突
                threading.Thread(target=connect_node, args=(tun_main, node, config_generation), daemon=True).start()
                time.sleep(1)
        elif needs_backup:
            node = get_best_candidate()
            if node:
                with state_lock: 
                    tun_backup.is_connecting = True
                    tun_backup.entry_ip = node["ip"] # FIX 1: 提前占住坑位
                threading.Thread(target=connect_node, args=(tun_backup, node, config_generation), daemon=True).start()

        time.sleep(2)

def main():
    global PROXY_PORT, tun_main, target_country, last_switch_trigger, REALTIME_URL, realtime_channel
    if os.geteuid() != 0: return
    check_for_updates()
    get_public_ip()
    setup_env()
    try:
        initial = fetch_controller_config()
        if initial:
            candidate_port = int(initial.get("port", 7920))
            PROXY_PORT = candidate_port if 1 <= candidate_port <= 65535 else 7920
            target_country = str(initial.get("0") or initial.get("country") or "JP").upper()
            last_switch_trigger = int(initial.get("switch_trigger", 0))
            pc = initial.get("proxy") or {}
            if pc:
                enabled = pc.get("enabled") is not False
                proxy_server.set_credentials((str(pc.get("user", "")) or env_secret("PROXY_USER")) if enabled else "", (str(pc.get("pass", "")) or env_secret("PROXY_PASS")) if enabled else "")
    except Exception as error:
        print(f"[cfg] initial controller sync failed, using fallback values: {error}", flush=True)
    subprocess.run(["pkill", "-f", "openvpn.*tun_main"], capture_output=True)
    subprocess.run(["pkill", "-f", "openvpn.*tun_backup"], capture_output=True)
    
    proxy_server.ACTIVE_BIND = tun_main.name
    
    print("========================================", flush=True)

    realtime_channel = create_realtime_channel()
    realtime_channel.start()
    print(f"  Proxy Controller (主备双活引擎) 启动！端口: {PROXY_PORT}", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=vpngate_fetch_loop, daemon=True).start()
    threading.Thread(target=update_config_loop, daemon=True).start()
    # 启用全局 IPv6 ANY 监听
    def run_proxy_server():
        try:
            proxy_server.start_proxy_server("::", PROXY_PORT)
        except Exception as error:
            print(f"[proxy] listener stopped: {error}; tunnel manager remains online", flush=True)
    threading.Thread(target=run_proxy_server, daemon=True).start()
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    marker = WORKSPACE / ".update-pending"
    if marker.exists():
        if not initial or not proxy_server.listener_ready.wait(30):
            print("[proxy] updated version failed controller readiness", flush=True)
            raise SystemExit(1)
        try: marker.unlink()
        except FileNotFoundError: pass
    maintain_pool()

if __name__ == "__main__":
    main()
