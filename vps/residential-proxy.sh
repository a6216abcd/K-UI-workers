#!/usr/bin/env bash
# ==========================================================
# KUI 住宅IP代理 Agent 安装脚本 (Residential Proxy Agent)
# 用法:
#   bash <(curl -sL https://<KUI_PAGES>/vps/residential-proxy.sh) \
#        --domain https://<KUI_PAGES> --controller https://<RESIDENTIAL_CTRL>
#   --domain      : 本仓库 (KUI Pages) 域名，用于下载 /vps/ 下的 agent 脚本
#   --controller  : 住宅IP代理控制器域名 (Free-Residential-IP-Proxy-Controller 部署地址)
#                   即 agent 心跳上报 (C2) 地址，对应面板 PROXY_CTRL_URL
# ==========================================================
set -e

DOMAIN=""
CONTROLLER=""

while [ "$#" -gt 0 ]; do
    case $1 in
        --domain) DOMAIN="$2"; shift 2 ;;
        --controller) CONTROLLER="$2"; shift 2 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    echo "❌ 错误: 缺少 --domain (本仓库域名，用于拉取 /vps/ 下的 agent 脚本)"
    exit 1
fi
if [ -z "$CONTROLLER" ]; then
    CONTROLLER="$DOMAIN"
fi

export C2_URL="$CONTROLLER"
export WEB_USER="${WEB_USER:-admin}"
export WEB_PASS="${WEB_PASS:-admin888}"

echo "=========================================================="
echo "     Proxy Controller (Active-Standby Multi-Tunnel)    "
echo "=========================================================="

# 彻底修复内核反向路径过滤导致备用通道回包被丢弃的问题
echo "net.ipv4.conf.all.rp_filter=2" > /etc/sysctl.d/99-proxy-lite.conf
echo "net.ipv4.conf.default.rp_filter=2" >> /etc/sysctl.d/99-proxy-lite.conf
sysctl --system >/dev/null 2>&1

apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron psmisc

mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

echo "[1/3] 从安全中心拉取双活极速引擎..."
curl -sLo lite_manager.py ${DOMAIN}/vps/lite_manager.py
curl -sLo proxy_server.py ${DOMAIN}/vps/proxy_server.py

echo "[2/3] 配置系统守护服务..."
cat > /lib/systemd/system/proxy-lite.service << EOF
[Unit]
Description=Proxy Core Engine (Active-Standby)
After=network.target

[Service]
Type=simple
Environment="C2_URL=${CONTROLLER}"
Environment="WEB_USER=${WEB_USER:-admin}"
Environment="WEB_PASS=${WEB_PASS:-admin888}"
Environment="PROXY_USER=${PROXY_USER:-proxy}"
Environment="PROXY_PASS=${PROXY_PASS:-888888}"
Environment="PYTHONIOENCODING=utf-8"
Environment="LANG=C.UTF-8"
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
systemctl restart proxy-lite.service

echo "[+] 引擎更新成功！主备双活通道、异步刷IP逻辑已全量加载。"
