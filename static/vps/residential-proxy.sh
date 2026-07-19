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
set -euo pipefail

DOMAIN=""
CONTROLLER=""
AGENT_TOKEN=""
VPS_IP=""

while [ "$#" -gt 0 ]; do
    case $1 in
        --domain) [ "$#" -ge 2 ] || { echo "❌ --domain 缺少参数"; exit 1; }; DOMAIN="$2"; shift 2 ;;
        --controller) [ "$#" -ge 2 ] || { echo "❌ --controller 缺少参数"; exit 1; }; CONTROLLER="$2"; shift 2 ;;
        --token) [ "$#" -ge 2 ] || { echo "❌ --token 缺少参数"; exit 1; }; AGENT_TOKEN="$2"; shift 2 ;;
        --ip) [ "$#" -ge 2 ] || { echo "❌ --ip 缺少参数"; exit 1; }; VPS_IP="$2"; shift 2 ;;
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
if [ -z "$AGENT_TOKEN" ]; then
    echo "❌ 错误: 缺少 --token (服务器专属 Agent Token)"
    exit 1
fi
if [ -z "$VPS_IP" ]; then
    echo "❌ 错误: 缺少 --ip (面板登记的服务器 IP)"
    exit 1
fi
if ! printf '%s' "$AGENT_TOKEN" | grep -Eq '^[A-Za-z0-9._:-]+$'; then echo "❌ Agent Token 包含非法字符"; exit 1; fi
if ! printf '%s\n%s\n' "$DOMAIN" "$CONTROLLER" | grep -Eq '^https://[A-Za-z0-9._:/-]+$'; then echo "❌ 域名参数必须使用 HTTPS"; exit 1; fi
if ! printf '%s' "$VPS_IP" | grep -Eq '^[0-9A-Fa-f:.]+$'; then echo "❌ VPS IP 格式无效"; exit 1; fi

export C2_URL="$CONTROLLER"
export WEB_USER="${WEB_USER:-admin}"
export WEB_PASS="${WEB_PASS:-}"
export AGENT_TOKEN
export VPS_IP

echo "=========================================================="
echo "     Proxy Controller (Active-Standby Multi-Tunnel)    "
echo "=========================================================="
echo "[*] 操作系统: $(uname -srm)"
echo "[*] 包管理器检测中..."

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    else
        echo ""
    fi
}

detect_init_system() {
    if [ -d /run/systemd/system ] && [ "$(cat /proc/1/comm 2>/dev/null || true)" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
        echo "systemd"
    elif [ -x /sbin/openrc-run ] && command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    else
        echo ""
    fi
}

PKG_MGR=$(detect_pkg_manager)
INIT_SYS=$(detect_init_system)

echo "[*] 包管理器: ${PKG_MGR:-未识别}"
echo "[*] 初始化系统: ${INIT_SYS:-未识别}"

if [ -z "$PKG_MGR" ]; then
    echo "❌ 错误: 未识别包管理器，请手动安装 openvpn python3 curl iproute2 iptables"
    exit 1
fi

if [ -z "$INIT_SYS" ]; then echo "❌ 需要正在运行的 systemd 或 OpenRC"; exit 1; fi

install_dependencies() {
    echo "[0/4] 安装系统依赖..."
    case "$PKG_MGR" in
        apt)
            apt-get update -q || { echo "❌ apt-get update 失败"; exit 1; }
            apt-get install -y --no-install-recommends \
                openvpn python3 python3-websocket curl openssl iproute2 iptables cron psmisc \
                || { echo "❌ 依赖安装失败"; exit 1; }
            ;;
        apk)
            apk update || true
            apk add --no-cache \
                openvpn python3 py3-websocket-client curl openssl iproute2 iptables dcron psmisc \
                || { echo "❌ apk 依赖安装失败"; exit 1; }
            ;;
        yum|dnf)
            $PKG_MGR install -y \
                openvpn python3 curl openssl iproute2 iptables cron psmisc \
                || { echo "❌ $PKG_MGR 依赖安装失败"; exit 1; }
            $PKG_MGR install -y python3-websocket-client >/dev/null 2>&1 || echo "⚠️ 未找到 python3-websocket-client，将使用 HTTP 备份模式。"
            ;;
    esac
    echo "[+] 依赖安装完成"
}

setup_sysctl() {
    echo "[1/4] 配置内核网络参数..."
    cat > /etc/sysctl.d/99-proxy-lite.conf << 'SYSCTL'
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
SYSCTL
    if command -v sysctl >/dev/null 2>&1; then
        sysctl --system >/dev/null 2>&1 || {
            echo "⚠️  sysctl --system 部分失败，尝试单独应用..."
            sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1 || true
            sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1 || true
            sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
            sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
        }
    fi
    echo "[+] 内核参数配置完成"
}

setup_tun() {
    echo "[1.5/4] 检查 TUN/TAP 设备..."
    if [ -e /dev/net/tun ]; then
        echo "[+] /dev/net/tun 已存在"
        return
    fi
    echo "[*] /dev/net/tun 不存在，尝试创建..."
    mkdir -p /dev/net
    modprobe tun 2>/dev/null || true
    if grep -Eq '(^|[[:space:]])tun$' /proc/misc 2>/dev/null; then
        [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200
        chmod 600 /dev/net/tun
        if [ -f /etc/alpine-release ]; then
            grep -qxF tun /etc/modules 2>/dev/null || echo tun >> /etc/modules
        fi
    fi
    if [ ! -e /dev/net/tun ]; then
        echo "❌ 错误: /dev/net/tun 不存在，无法创建 TUN 设备。"
        echo "    可能原因："
        echo "    1. 内核未编译 tun 模块"
        echo "    2. 容器/虚拟化环境未开放 /dev/net/tun"
        echo "    3. 需要宿主机开启 TUN 设备"
        echo "    请先在宿主机或控制台开启 TUN/TAP 支持后重试。"
        exit 1
    fi
    echo "[+] TUN/TAP 设备已就绪"
}

download_agents() {
    echo "[2/4] 从安全中心拉取双活极速引擎..."
    mkdir -p /opt/proxy_lite/configs
    cd /opt/proxy_lite

    verify_agent_manifest() {
        COMPONENT="$1"; FILE="$2"; HEADERS="$3"
        EXPECTED_SHA=$(tr -d '\r' < "$HEADERS" | awk '/^[Xx]-[Aa]gent-[Ss][Hh][Aa]256:/ {print tolower($2)}' | tail -n 1)
        VERSION=$(tr -d '\r' < "$HEADERS" | awk '/^[Xx]-[Aa]gent-[Mm]anifest-[Vv]ersion:/ {print $2}' | tail -n 1)
        EXPECTED_LENGTH=$(tr -d '\r' < "$HEADERS" | awk '/^[Xx]-[Aa]gent-[Ll]ength:/ {print $2}' | tail -n 1)
        SUPPLIED_MAC=$(tr -d '\r' < "$HEADERS" | awk '/^[Xx]-[Aa]gent-[Mm][Aa][Cc]:/ {print tolower($2)}' | tail -n 1)
        ACTUAL_SHA=$(sha256sum "$FILE" | awk '{print $1}')
        ACTUAL_LENGTH=$(wc -c < "$FILE" | tr -d ' ')
        EXPECTED_MAC=$(printf 'v1\n%s\n%s\n%s\n' "$COMPONENT" "$EXPECTED_SHA" "$ACTUAL_LENGTH" | openssl dgst -sha256 -mac HMAC -macopt "key:${AGENT_TOKEN}" | awk '{print tolower($NF)}')
        [ "$VERSION" = "1" ] && [ "$EXPECTED_LENGTH" = "$ACTUAL_LENGTH" ] && [ "$EXPECTED_SHA" = "$ACTUAL_SHA" ] && [ -n "$SUPPLIED_MAC" ] && [ "$SUPPLIED_MAC" = "$EXPECTED_MAC" ]
    }

    download_component() {
        COMPONENT="$1"; TARGET="$2"; TEMP_FILE="${TARGET}.download"; HEADER_FILE="${TARGET}.headers"
        curl -fSL --retry 3 --retry-delay 2 -D "$HEADER_FILE" -H "Authorization: ${AGENT_TOKEN}" -o "$TEMP_FILE" "${DOMAIN}/api/agent_update?ip=${VPS_IP}&component=${COMPONENT}" || return 1
        verify_agent_manifest "$COMPONENT" "$TEMP_FILE" "$HEADER_FILE" || { echo "❌ ${COMPONENT} 更新清单校验失败"; return 1; }
        mv "$TEMP_FILE" "$TARGET"
        rm -f "$HEADER_FILE"
    }
    download_component proxy-manager lite_manager.py || { echo "❌ 下载 lite_manager.py 失败"; exit 1; }
    download_component proxy-server proxy_server.py || { echo "❌ 下载 proxy_server.py 失败"; exit 1; }
    download_component realtime-client realtime_client.py || { echo "❌ 下载 realtime_client.py 失败"; exit 1; }
    python3 -m py_compile lite_manager.py proxy_server.py realtime_client.py || {
        echo "❌ 下载的代理引擎不是有效 Python 文件"
        exit 1
    }
    chmod 700 /opt/proxy_lite/lite_manager.py /opt/proxy_lite/proxy_server.py /opt/proxy_lite/realtime_client.py
    echo "[+] 引擎文件下载完成"
}

install_service() {
    echo "[3/4] 配置系统守护服务..."
    install -d -m 700 /etc/proxy-lite
    umask 077
    WEB_USER_B64=$(printf '%s' "${WEB_USER:-admin}" | base64 | tr -d '\n')
    WEB_PASS_B64=$(printf '%s' "${WEB_PASS:-}" | base64 | tr -d '\n')
    PROXY_USER_B64=$(printf '%s' "${PROXY_USER:-}" | base64 | tr -d '\n')
    PROXY_PASS_B64=$(printf '%s' "${PROXY_PASS:-}" | base64 | tr -d '\n')
    if [ "$CONTROLLER" = "$DOMAIN" ]; then C2_API_PREFIX="/api/proxy"; else C2_API_PREFIX="/api"; fi
    cat > /etc/proxy-lite/env << EOF
C2_URL="${CONTROLLER}"
UPDATE_ORIGIN="${DOMAIN}"
C2_API_PREFIX="${C2_API_PREFIX}"
WEB_USER_B64="${WEB_USER_B64}"
WEB_PASS_B64="${WEB_PASS_B64}"
PROXY_USER_B64="${PROXY_USER_B64}"
PROXY_PASS_B64="${PROXY_PASS_B64}"
AGENT_TOKEN="${AGENT_TOKEN}"
VPS_IP="${VPS_IP}"
REALTIME_URL="${REALTIME_URL:-}"
PYTHONIOENCODING="utf-8"
LANG="C.UTF-8"
EOF
    chmod 600 /etc/proxy-lite/env
    umask 022
    cat > /opt/proxy_lite/run-proxy.sh <<'EOF'
#!/bin/sh
set -u
while true; do
    /usr/bin/python3 -u /opt/proxy_lite/lite_manager.py
    status=$?
    if [ -f /opt/proxy_lite/.update-pending ]; then
        echo "[launcher] residential update failed; restoring last-good" >&2
        for file in lite_manager.py proxy_server.py realtime_client.py; do [ ! -f "/opt/proxy_lite/$file.last-good" ] || cp -f "/opt/proxy_lite/$file.last-good" "/opt/proxy_lite/$file"; done
        rm -f /opt/proxy_lite/.update-pending
        continue
    fi
    exit "$status"
done
EOF
    chmod 700 /opt/proxy_lite/run-proxy.sh

    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop proxy-lite 2>/dev/null || true
        systemctl disable proxy-lite 2>/dev/null || true
        rm -f /lib/systemd/system/proxy-lite.service /etc/systemd/system/proxy-lite.service

        SERVICE_FILE="/etc/systemd/system/proxy-lite.service"
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Proxy Core Engine (Active-Standby)
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/proxy-lite/env
WorkingDirectory=/opt/proxy_lite
ExecStart=/opt/proxy_lite/run-proxy.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable proxy-lite.service
        systemctl restart proxy-lite.service
        echo "[+] 引擎更新成功！主备双活通道、异步刷IP逻辑已全量加载。"
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service proxy-lite stop 2>/dev/null || true
        rc-update del proxy-lite default >/dev/null 2>&1 || true
        rm -f /etc/init.d/proxy-lite /etc/conf.d/proxy-lite

        cp /etc/proxy-lite/env /etc/conf.d/proxy-lite
        chmod 600 /etc/conf.d/proxy-lite
        : > /var/log/proxy-lite.log
        chmod 600 /var/log/proxy-lite.log
        cat > /etc/init.d/proxy-lite << 'EOF'
#!/sbin/openrc-run
name="proxy-lite"
description="Proxy Core Engine (Active-Standby)"
supervisor="supervise-daemon"
        command="/opt/proxy_lite/run-proxy.sh"
        command_args=""
respawn_delay=3
respawn_max=0
output_log="/var/log/proxy-lite.log"
error_log="/var/log/proxy-lite.log"
directory="/opt/proxy_lite"
start_pre() {
    set -a
    . /etc/proxy-lite/env
    set +a
}
depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/proxy-lite
        rc-update add proxy-lite default >/dev/null 2>&1 || true
        rc-service proxy-lite restart 2>/dev/null || true
        echo "[+] OpenRC 服务安装完成。"
        echo "    手动管理: rc-service proxy-lite start|stop|restart"
        echo "    查看日志: tail -f /var/log/proxy-lite.log"
    else
        cat > /opt/proxy_lite/run.sh << 'EOF'
#!/bin/sh
set -a
. /etc/proxy-lite/env
set +a
cd /opt/proxy_lite
exec python3 -u lite_manager.py
EOF
        chmod 700 /opt/proxy_lite/run.sh
        echo "[+] 未检测到标准初始化系统，启动脚本已创建: /opt/proxy_lite/run.sh"
        echo "    请运行: /opt/proxy_lite/run.sh"
    fi
}

main() {
    INSTALL_SUCCESS=0
    BACKUP_DIR=$(mktemp -d /tmp/kui-proxy-backup.XXXXXX)
    chmod 700 "$BACKUP_DIR"
    BACKUP_ITEMS=""
    for item in opt/proxy_lite etc/proxy-lite etc/systemd/system/proxy-lite.service etc/init.d/proxy-lite etc/conf.d/proxy-lite; do
        [ ! -e "/$item" ] || BACKUP_ITEMS="$BACKUP_ITEMS $item"
    done
    [ -z "$BACKUP_ITEMS" ] || tar -C / -czf "$BACKUP_DIR/proxy.tgz" $BACKUP_ITEMS
    restore_core_services() {
        if [ "$INIT_SYS" = "systemd" ]; then
            systemctl start sing-box 2>/dev/null || true
        elif [ "$INIT_SYS" = "openrc" ]; then
            rc-service sing-box start 2>/dev/null || true
        fi
    }
    rollback_proxy_install() {
        status=$?
        restore_core_services
        if [ "$INSTALL_SUCCESS" -ne 1 ]; then
            echo "❌ 住宅组件安装失败，正在恢复上一个可用版本..."
            if [ "$INIT_SYS" = "systemd" ]; then systemctl stop proxy-lite >/dev/null 2>&1 || true
            elif [ "$INIT_SYS" = "openrc" ]; then rc-service proxy-lite stop >/dev/null 2>&1 || true; fi
            rm -rf /opt/proxy_lite /etc/proxy-lite
            rm -f /etc/systemd/system/proxy-lite.service /etc/init.d/proxy-lite /etc/conf.d/proxy-lite
            [ ! -f "$BACKUP_DIR/proxy.tgz" ] || tar -C / -xzf "$BACKUP_DIR/proxy.tgz"
            if [ "$INIT_SYS" = "systemd" ]; then systemctl daemon-reload >/dev/null 2>&1 || true; systemctl start proxy-lite >/dev/null 2>&1 || true
            elif [ "$INIT_SYS" = "openrc" ]; then rc-service proxy-lite start >/dev/null 2>&1 || true; fi
        fi
        rm -rf "$BACKUP_DIR"
        exit "$status"
    }
    trap rollback_proxy_install EXIT INT TERM
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop proxy-lite 2>/dev/null || true
        systemctl disable proxy-lite 2>/dev/null || true
        systemctl stop sing-box 2>/dev/null || true
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service proxy-lite stop 2>/dev/null || true
        rc-update del proxy-lite default >/dev/null 2>&1 || true
        rc-service sing-box stop 2>/dev/null || true
    fi
    pkill -f "python3 -u lite_manager.py" >/dev/null 2>&1 || true
    pkill -f "openvpn.*tun_main" >/dev/null 2>&1 || true
    pkill -f "openvpn.*tun_backup" >/dev/null 2>&1 || true
    rm -f /opt/proxy_lite/lite_manager.py /opt/proxy_lite/proxy_server.py /opt/proxy_lite/run.sh

    install_dependencies
    setup_sysctl
    setup_tun
    download_agents
    install_service
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart kui-agent 2>/dev/null || true
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service kui-agent restart 2>/dev/null || true
    fi
    for _ in $(seq 1 30); do
        if [ "$INIT_SYS" = "systemd" ] && systemctl is-active --quiet sing-box; then break; fi
        if [ "$INIT_SYS" = "openrc" ] && rc-service sing-box --quiet status; then break; fi
        sleep 1
    done
    restore_core_services
    INSTALL_SUCCESS=1
    rm -rf "$BACKUP_DIR"
    trap - EXIT INT TERM

    echo ""
    echo "=========================================================="
    echo "[+] 住宅IP代理引擎部署完成！"
    echo "=========================================================="
    if [ "$INIT_SYS" = "systemd" ]; then
        echo "    检查状态: systemctl status proxy-lite"
        echo "    查看日志: journalctl -u proxy-lite -f"
    elif [ "$INIT_SYS" = "openrc" ]; then
        echo "    检查状态: rc-service proxy-lite status"
        echo "    查看日志: tail -f /var/log/proxy-lite.log"
    else
        echo "    检查进程: ps | grep lite_manager.py"
        echo "    启动脚本: /opt/proxy_lite/run.sh"
    fi
    echo "=========================================================="
}

main "$@"
