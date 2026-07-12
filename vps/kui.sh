#!/bin/sh

set -eu

# ==========================================
# KUI Serverless 集群节点 - 智能跨系统安装脚本 (工业级加固版)
# 支持: Ubuntu 18-24 / Debian 10-13 / Alpine Linux
# ==========================================

API_URL=""; VPS_IP=""; TOKEN=""; PROXY_API_URL=""

while [ "$#" -gt 0 ]; do
    case $1 in
        --api) [ "$#" -ge 2 ] || { echo "--api 缺少参数"; exit 1; }; API_URL="$2"; shift ;;
        --ip) [ "$#" -ge 2 ] || { echo "--ip 缺少参数"; exit 1; }; VPS_IP="$2"; shift ;;
        --token) [ "$#" -ge 2 ] || { echo "--token 缺少参数"; exit 1; }; TOKEN="$2"; shift ;;
        --proxy-api) [ "$#" -ge 2 ] || { echo "--proxy-api 缺少参数"; exit 1; }; PROXY_API_URL="$2"; shift ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$API_URL" ] || [ -z "$VPS_IP" ] || [ -z "$TOKEN" ]; then
    echo "❌ 错误: 缺少必要参数！"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS="${ID:-}"
else
    echo "❌ 无法识别操作系统，脚本退出。"
    exit 1
fi

case "$OS" in
    alpine|debian|ubuntu) ;;
    *) echo "不支持的发行版: $OS"; exit 1 ;;
esac

echo "=========================================="
echo " 🚀 KUI Agent 智能安装启动中..."
echo " 💻 目标系统: ${OS}"
echo "=========================================="

export CURL_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

echo "[1/6] 🧹 正在清理历史残留..."
if [ "$OS" = "alpine" ]; then
    rc-service kui-agent stop >/dev/null 2>&1 || true
    rc-service sing-box stop >/dev/null 2>&1 || true
    rc-update del kui-agent default >/dev/null 2>&1 || true
    rc-update del sing-box default >/dev/null 2>&1 || true
    rm -f /etc/init.d/kui-agent /etc/init.d/sing-box
else
    systemctl stop kui-agent >/dev/null 2>&1 || true
    systemctl stop sing-box >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kui-agent.service
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -rf /opt/kui /etc/sing-box/config.json

echo "[2/6] ⚡ 保留系统现有软件源..."
if [ "$OS" = "alpine" ]; then
    :
else
    :
fi

echo "[3/6] 📦 正在安装底层网络依赖..."
ALIYUN_OK=0
if [ "$OS" = "alpine" ]; then
    apk update || echo "⚠️ apk update 失败，尝试使用现有缓存安装。"
    apk add python3 curl openssl iptables ip6tables coreutils bash tar libc6-compat gcompat iproute2
else
    if apt-get update -y >/tmp/kui_apt_update.log 2>&1; then
        cat /tmp/kui_apt_update.log
        ALIYUN_OK=1
    else
        cat /tmp/kui_apt_update.log
        echo "⚠️  aliyun 源 apt-get update 失败，回滚到原 sources.list..."
        if [ -f /etc/apt/sources.list.bak ]; then
            mv /etc/apt/sources.list.bak /etc/apt/sources.list
            apt-get update -y || echo "❌ 原 sources.list 也无法更新，请手动检查网络/源配置。"
        else
            echo "❌ 无备份可回滚，请手动修复 /etc/apt/sources.list 或更换镜像源后重试。"
        fi
        exit 1
    fi
    apt-get install -y python3 curl openssl iptables coreutils bash tar iproute2 iputils-ping
fi

echo "[4/6] ⚙️ 部署 Sing-box 代理核心..."
rm -f /usr/bin/sing-box
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) SB_ARCH="amd64" ;;
    aarch64) SB_ARCH="arm64" ;;
    *) echo "不支持的 CPU 架构: $ARCH"; exit 1 ;;
esac
SB_VER="1.13.14"
SB_SUFFIX="linux-${SB_ARCH}-glibc"
[ "$OS" = "alpine" ] && SB_SUFFIX="linux-${SB_ARCH}-musl"
curl -fL --retry 3 -o sing-box.tar.gz -A "$CURL_USER_AGENT" "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-${SB_SUFFIX}.tar.gz"
case "$SB_SUFFIX" in
    linux-amd64-glibc) EXPECTED_SHA="aae9172317c61760aae3dafcde889b2e51b7ea590c40d2b3c7ccdeae14b361b6" ;;
    linux-amd64-musl) EXPECTED_SHA="d5b46de6498427bccfeb87dbafcde4dbefdfe35680020d07d286ad915f0bfb34" ;;
    linux-arm64-glibc) EXPECTED_SHA="08d37b2bf12145ec44307333490cecca4c917df054cd8e27a210f8d9cdbe0fd9" ;;
    linux-arm64-musl) EXPECTED_SHA="edec18488af35a93cf8b362063146fdd7b557ef9862710ee77a1f4adb5c70118" ;;
    *) echo "❌ 不支持的 sing-box 构建: $SB_SUFFIX"; exit 1 ;;
esac
ACTUAL_SHA=$(sha256sum sing-box.tar.gz | awk '{print $1}')
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || { echo "❌ sing-box SHA256 校验失败"; exit 1; }
tar -xzf sing-box.tar.gz
test -x "sing-box-${SB_VER}-${SB_SUFFIX}/sing-box"
mv "sing-box-${SB_VER}-${SB_SUFFIX}/sing-box" /usr/bin/
chmod +x /usr/bin/sing-box
rm -rf sing-box.tar.gz "sing-box-${SB_VER}-${SB_SUFFIX}"

echo "[4.5/6] ⚙️ 正在应用网络内核调优（BBR / QUIC / conntrack）..."
if [ "$OS" = "alpine" ]; then
    modprobe -q xt_conntrack 2>/dev/null || true
    sysctl -w net.netfilter.nf_conntrack_max=1048576 >/dev/null 2>&1 || true
else
    cat > /etc/sysctl.d/99-kui-optimize.conf <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 5000
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
SYSCTL
    sysctl --system >/dev/null 2>&1 || echo "⚠️ 部分内核参数无法应用，继续安装。"
fi

echo "[5/6] 📂 初始化 KUI 工作目录与环境..."
mkdir -p /opt/kui /etc/sing-box

API_URL="$API_URL" VPS_IP="$VPS_IP" TOKEN="$TOKEN" PROXY_API_URL="${PROXY_API_URL:-}" python3 -c 'import json, os; json.dump({"api_url": os.environ["API_URL"] + "/api/config", "report_url": os.environ["API_URL"] + "/api/report", "ip": os.environ["VPS_IP"], "token": os.environ["TOKEN"], "proxy_api": os.environ["PROXY_API_URL"]}, open("/opt/kui/config.json", "w"))'
chmod 600 /opt/kui/config.json

echo "正在拉取最新版 Agent 执行器..."
AGENT_URL="${API_URL}/api/agent_update?ip=${VPS_IP}&component=agent"
AGENT_TEMP="/opt/kui/agent.py.download"; AGENT_HEADERS="/opt/kui/agent.py.headers"
curl -fsSL --retry 3 --retry-delay 2 -A "$CURL_USER_AGENT" -D "$AGENT_HEADERS" -H "Authorization: ${TOKEN}" "$AGENT_URL" -o "$AGENT_TEMP"
EXPECTED_AGENT_SHA=$(tr -d '\r' < "$AGENT_HEADERS" | awk '/^[Xx]-[Aa]gent-[Ss][Hh][Aa]256:/ {print tolower($2)}' | tail -n 1)
ACTUAL_AGENT_SHA=$(sha256sum "$AGENT_TEMP" | awk '{print $1}')
[ -n "$EXPECTED_AGENT_SHA" ] && [ "$EXPECTED_AGENT_SHA" = "$ACTUAL_AGENT_SHA" ] || { echo "❌ agent.py SHA256 校验失败"; exit 1; }
python3 -m py_compile "$AGENT_TEMP"
mv "$AGENT_TEMP" /opt/kui/agent.py
rm -f "$AGENT_HEADERS"
chmod 700 /opt/kui/agent.py

echo "[6/6] 🛡️ 智能注册底层守护进程并启动..."
if [ "$OS" = "alpine" ]; then
    cat > /etc/init.d/kui-agent <<EOF
#!/sbin/openrc-run
description="KUI Serverless Agent"
command="/usr/bin/python3"
command_args="/opt/kui/agent.py"
command_background="yes"
pidfile="/run/kui-agent.pid"
EOF
    cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
description="Sing-box Proxy Service"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
EOF
    chmod +x /etc/init.d/kui-agent /etc/init.d/sing-box
    rc-update add kui-agent default
    rc-update add sing-box default
    rc-service kui-agent start
else
    cat > /etc/systemd/system/kui-agent.service <<EOF
[Unit]
Description=KUI Serverless Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/kui/agent.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable kui-agent
    if command -v sing-box >/dev/null 2>&1; then
        if [ ! -f /etc/systemd/system/sing-box.service ]; then
            cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
        fi
        systemctl enable sing-box
    fi
    systemctl start kui-agent
fi

echo "=========================================="
echo " 🎉 KUI Agent 跨平台部署成功！"
echo " 节点 IP: ${VPS_IP}"
echo " 系统架构: ${OS}"
echo "=========================================="
