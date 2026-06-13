#!/bin/bash

# ==========================================
# trojan-rs (trojan+wss / vless+wss) 一键安装管理脚本
# ==========================================

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

INSTALL_DIR="/usr/local/trojan-rs"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/trojan-rs.service"
CERT_DIR="${INSTALL_DIR}/cert"
BIN_FILE="${INSTALL_DIR}/trojan-rs"

# 请根据您的实际 GitHub 仓库修改此处，以获取最新的 Release 产物
# 例如: GITHUB_REPO="p4gefau1t/trojan-rs"
GITHUB_REPO="your_username/trojan-rs"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：本脚本必须以 root 身份运行！${PLAIN}"
        exit 1
    fi
}

install_deps() {
    echo -e "${GREEN}正在安装必要的依赖...${PLAIN}"
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update -y
        apt-get install -y curl wget tar jq openssl socat cron
    elif [ -x "$(command -v yum)" ]; then
        yum update -y
        yum install -y curl wget tar jq openssl socat cronie
    else
        echo -e "${RED}不支持的操作系统，请使用 Ubuntu/Debian 或 CentOS。${PLAIN}"
        exit 1
    fi
}

install_acme() {
    if [ ! -d "/root/.acme.sh" ]; then
        echo -e "${GREEN}正在安装 acme.sh...${PLAIN}"
        curl https://get.acme.sh | sh
    else
        echo -e "${GREEN}acme.sh 已安装。${PLAIN}"
    fi
}

issue_cert() {
    read -p "请输入您要配置的域名 (例如: example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}域名不能为空！${PLAIN}"
        exit 1
    fi

    echo -e "${YELLOW}请确保您的域名已解析到本服务器的 IP，并且本机的 80 端口未被占用。${PLAIN}"
    read -p "按回车键继续申请证书..."

    mkdir -p ${CERT_DIR}
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d ${DOMAIN} --standalone -k ec-256

    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查域名解析和 80 端口。${PLAIN}"
        exit 1
    fi

    /root/.acme.sh/acme.sh --installcert -d ${DOMAIN} --fullchainpath ${CERT_DIR}/fullchain.cer --keypath ${CERT_DIR}/private.key --ecc

    echo -e "${GREEN}证书申请成功！已保存至 ${CERT_DIR}${PLAIN}"
}

download_bin() {
    echo -e "${GREEN}正在获取最新的 trojan-rs 版本...${PLAIN}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ASSET_KEYWORD="linux-amd64" ;;
        aarch64) ASSET_KEYWORD="linux-arm64" ;; # 若您编译了 arm64
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac

    # 通过 GitHub API 获取最新 release 的下载链接
    API_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    DOWNLOAD_URL=$(curl -s "$API_URL" | jq -r ".assets[] | select(.name | contains(\"${ASSET_KEYWORD}\")) | .browser_download_url")

    if [ -z "$DOWNLOAD_URL" ] || [ "$DOWNLOAD_URL" == "null" ]; then
        echo -e "${RED}无法找到适用于 ${ARCH} 架构的预编译文件，请检查您的 GitHub Release！${PLAIN}"
        echo -e "尝试让您手动输入下载地址："
        read -p "二进制压缩包直链: " DOWNLOAD_URL
    fi

    echo -e "${GREEN}正在下载二进制包...${PLAIN}"
    mkdir -p ${INSTALL_DIR}
    wget -O trojan-rs.tar.gz "${DOWNLOAD_URL}"
    tar -xzf trojan-rs.tar.gz -C ${INSTALL_DIR}
    rm -f trojan-rs.tar.gz

    # 由于打包出来的二进制可能叫 trojan-rs 或 trojan-r，统一重命名为 trojan-rs
    if [ -f "${INSTALL_DIR}/trojan-r" ]; then
        mv ${INSTALL_DIR}/trojan-r ${BIN_FILE}
    fi
    chmod +x ${BIN_FILE}
}

generate_config() {
    echo -e "请选择您要部署的协议："
    echo "1. trojan + wss"
    echo "2. vless + wss"
    read -p "请输入 [1/2]: " PROTO_CHOICE

    read -p "请输入服务监听端口 (默认: 443): " PORT
    PORT=${PORT:-443}

    read -p "请输入 WebSocket 路径 (默认: /ws): " WSPATH
    WSPATH=${WSPATH:-/ws}

    if [ "$PROTO_CHOICE" == "2" ]; then
        # vless
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${GREEN}已为您自动生成 VLESS UUID: ${UUID}${PLAIN}"
        cat > ${CONFIG_FILE} <<EOF
mode = "server"
log_level = "info"

[tls]
addr = "0.0.0.0:${PORT}"
cert = "${CERT_DIR}/fullchain.cer"
key = "${CERT_DIR}/private.key"

[vless]
users = ["${UUID}"]

[websocket]
path = "${WSPATH}"
EOF

    else
        # trojan
        read -p "请输入 Trojan 密码 (默认: 自动生成): " PASSWORD
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
            echo -e "${GREEN}已为您自动生成随机密码: ${PASSWORD}${PLAIN}"
        fi
        
        read -p "请输入回落地址(Fallback) (默认: 127.0.0.1:80): " FALLBACK
        FALLBACK=${FALLBACK:-127.0.0.1:80}

        cat > ${CONFIG_FILE} <<EOF
mode = "server"
log_level = "info"

[tls]
addr = "0.0.0.0:${PORT}"
cert = "${CERT_DIR}/fullchain.cer"
key = "${CERT_DIR}/private.key"

[trojan]
password = "${PASSWORD}"
fallback_addr = "${FALLBACK}"

[websocket]
path = "${WSPATH}"
EOF
    fi

    echo -e "${GREEN}配置文件生成完毕: ${CONFIG_FILE}${PLAIN}"
}

setup_systemd() {
    echo -e "${GREEN}配置 systemd 守护进程...${PLAIN}"
    cat > ${SERVICE_FILE} <<EOF
[Unit]
Description=trojan-rs service
After=network.target network-online.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_FILE} -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trojan-rs
    systemctl restart trojan-rs
    echo -e "${GREEN}服务已启动并设置为开机自启。${PLAIN}"
}

install() {
    check_root
    install_deps
    install_acme
    issue_cert
    download_bin
    generate_config
    setup_systemd
    echo -e "${GREEN}安装与部署已全部完成！${PLAIN}"
    echo -e "${YELLOW}请使用菜单栏的日志查看功能确认服务是否正常运行。${PLAIN}"
}

manage_service() {
    echo "1. 启动服务 (Start)"
    echo "2. 停止服务 (Stop)"
    echo "3. 重启服务 (Restart)"
    echo "4. 查看状态 (Status)"
    read -p "请输入 [1-4]: " ACTION
    case "${ACTION}" in
        1) systemctl start trojan-rs; echo -e "${GREEN}已发送启动指令。${PLAIN}" ;;
        2) systemctl stop trojan-rs; echo -e "${GREEN}已发送停止指令。${PLAIN}" ;;
        3) systemctl restart trojan-rs; echo -e "${GREEN}已发送重启指令。${PLAIN}" ;;
        4) systemctl status trojan-rs ;;
        *) echo -e "${RED}无效选项。${PLAIN}" ;;
    esac
}

view_logs() {
    echo -e "${GREEN}正在打开日志流，按 Ctrl+C 退出...${PLAIN}"
    journalctl -u trojan-rs -f
}

change_config() {
    if [ ! -f "${CONFIG_FILE}" ]; then
        echo -e "${RED}未找到配置文件 ${CONFIG_FILE}${PLAIN}"
        return
    fi
    echo -e "${YELLOW}当前配置如下：${PLAIN}"
    cat ${CONFIG_FILE}
    echo -e "\n${GREEN}请选择修改方式：${PLAIN}"
    echo "1. 使用 vim 手动编辑"
    echo "2. 使用 nano 手动编辑"
    echo "3. 重新运行自动配置向导 (将覆盖当前配置)"
    read -p "请输入 [1-3]: " C_CHOICE
    case "${C_CHOICE}" in
        1) vim ${CONFIG_FILE} ;;
        2) nano ${CONFIG_FILE} ;;
        3) generate_config ;;
        *) echo -e "${RED}取消。${PLAIN}"; return ;;
    esac
    
    read -p "修改完毕，是否立即重启服务生效？[y/N]: " RESTART_CONFIRM
    if [[ "$RESTART_CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl restart trojan-rs
        echo -e "${GREEN}服务已重启。${PLAIN}"
    fi
}

uninstall() {
    read -p "警告：您确定要完全卸载 trojan-rs 吗？[y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl stop trojan-rs
        systemctl disable trojan-rs
        rm -f ${SERVICE_FILE}
        systemctl daemon-reload
        rm -rf ${INSTALL_DIR}
        echo -e "${GREEN}trojan-rs 已被彻底卸载！${PLAIN}"
    fi
}

menu() {
    clear
    echo -e "=================================="
    echo -e " ${GREEN}trojan-rs 一键部署与管理脚本${PLAIN}"
    echo -e "=================================="
    echo "1. 全自动全新安装"
    echo "2. 修改/查看配置文件"
    echo "3. 服务管理 (启动/停止/重启)"
    echo "4. 查看实时运行日志"
    echo "5. 彻底卸载"
    echo "0. 退出脚本"
    echo -e "=================================="
    read -p "请输入选择 [0-5]: " CHOICE
    case "${CHOICE}" in
        1) install ;;
        2) change_config ;;
        3) manage_service ;;
        4) view_logs ;;
        5) uninstall ;;
        0) exit 0 ;;
        *) echo -e "${RED}输入无效，请重新输入。${PLAIN}"; sleep 2; menu ;;
    esac
}

menu
