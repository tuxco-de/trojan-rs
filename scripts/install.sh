#!/bin/bash

# ==========================================
# trojan-rs (trojan+wss / vless+wss) 一键安装管理脚本
# ==========================================

set -euo pipefail

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
GITHUB_REPO="tuxco-de/trojan-rs"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：本脚本必须以 root 身份运行！${PLAIN}"
        exit 1
    fi
}

install_deps() {
    read -rp "是否需要更新并安装系统依赖 (curl, wget, tar, jq, openssl, socat, cron)？[Y/n]: " INSTALL_DEPS_CONFIRM
    if [[ "$INSTALL_DEPS_CONFIRM" =~ ^[Nn]$ ]]; then
        echo -e "${GREEN}跳过依赖安装。${PLAIN}"
        return
    fi

    echo -e "${GREEN}正在安装必要的依赖...${PLAIN}"
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update -y || true
        apt-get install -y curl wget tar jq openssl socat cron
    elif [ -x "$(command -v yum)" ]; then
        yum update -y || true
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
    read -rp "请输入您要配置的域名 (例如: example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}域名不能为空！${PLAIN}"
        exit 1
    fi

    if [ -f "/root/.acme.sh/${DOMAIN}_ecc/fullchain.cer" ] || [ -f "/root/.acme.sh/${DOMAIN}/fullchain.cer" ] || [ -f "${CERT_DIR}/fullchain.cer" ]; then
        echo -e "${GREEN}检测到本机或 acme.sh 中已存在域名 ${DOMAIN} 的证书。${PLAIN}"
        read -rp "是否需要强制重新申请证书？[y/N]: " RENEW_CONFIRM
        if [[ ! "$RENEW_CONFIRM" =~ ^[Yy]$ ]]; then
            echo -e "${GREEN}跳过证书申请，尝试直接安装现有证书...${PLAIN}"
            mkdir -p "${CERT_DIR}"
            if /root/.acme.sh/acme.sh --installcert -d "${DOMAIN}" --fullchainpath "${CERT_DIR}/fullchain.cer" --keypath "${CERT_DIR}/private.key" --ecc 2>/dev/null || \
               /root/.acme.sh/acme.sh --installcert -d "${DOMAIN}" --fullchainpath "${CERT_DIR}/fullchain.cer" --keypath "${CERT_DIR}/private.key" 2>/dev/null; then
                if [ -f "${CERT_DIR}/fullchain.cer" ] && [ -f "${CERT_DIR}/private.key" ]; then
                    echo -e "${GREEN}已成功安装现有证书至 ${CERT_DIR}${PLAIN}"
                    return
                fi
            fi
            echo -e "${RED}无法安装现有证书，将继续申请新证书...${PLAIN}"
        fi
    fi

    echo -e "${YELLOW}请确保您的域名已解析到本服务器的 IP，并且本机的 80 端口未被占用。${PLAIN}"
    read -rp "按回车键继续申请证书..."

    mkdir -p "${CERT_DIR}"
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    if ! /root/.acme.sh/acme.sh --issue -d "${DOMAIN}" --standalone -k ec-256; then
        echo -e "${RED}证书申请失败！请检查域名解析和 80 端口。${PLAIN}"
        exit 1
    fi

    /root/.acme.sh/acme.sh --installcert -d "${DOMAIN}" --fullchainpath "${CERT_DIR}/fullchain.cer" --keypath "${CERT_DIR}/private.key" --ecc

    if [ ! -f "${CERT_DIR}/fullchain.cer" ] || [ ! -f "${CERT_DIR}/private.key" ]; then
        echo -e "${RED}证书安装失败！证书文件不存在。${PLAIN}"
        exit 1
    fi

    echo -e "${GREEN}证书申请成功！已保存至 ${CERT_DIR}${PLAIN}"
}

download_bin() {
    echo -e "${GREEN}正在获取最新的 trojan-rs 版本...${PLAIN}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ASSET_KEYWORD="server-linux-amd64" ;;
        aarch64) ASSET_KEYWORD="server-linux-arm64" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac

    # 通过 GitHub API 获取最新 release 的下载链接
    API_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    DOWNLOAD_URL=$(curl -s "$API_URL" | jq -r ".assets[] | select(.name | contains(\"${ASSET_KEYWORD}\")) | .browser_download_url")

    if [ -z "$DOWNLOAD_URL" ] || [ "$DOWNLOAD_URL" == "null" ]; then
        echo -e "${RED}无法找到适用于 ${ARCH} 架构的预编译文件，请检查您的 GitHub Release！${PLAIN}"
        echo -e "尝试让您手动输入下载地址："
        read -rp "二进制压缩包直链: " DOWNLOAD_URL
    fi

    echo -e "${GREEN}正在下载二进制包...${PLAIN}"
    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    if ! wget -O "${TMP_DIR}/trojan-rs.tar.gz" "${DOWNLOAD_URL}"; then
        echo -e "${RED}下载失败！请检查网络连接或下载链接。${PLAIN}"
        rm -rf "${TMP_DIR}"
        exit 1
    fi

    if ! tar -xzf "${TMP_DIR}/trojan-rs.tar.gz" -C "${TMP_DIR}"; then
        echo -e "${RED}解压失败！下载的文件可能已损坏。${PLAIN}"
        rm -rf "${TMP_DIR}"
        exit 1
    fi

    mkdir -p "${INSTALL_DIR}"

    # 查找解压出的二进制文件并安装到目标位置
    if [ -f "${TMP_DIR}/trojan-rs-server" ]; then
        mv "${TMP_DIR}/trojan-rs-server" "${BIN_FILE}"
    elif [ -f "${TMP_DIR}/trojan-rs" ]; then
        mv "${TMP_DIR}/trojan-rs" "${BIN_FILE}"
    elif [ -f "${TMP_DIR}/trojan-r" ]; then
        mv "${TMP_DIR}/trojan-r" "${BIN_FILE}"
    else
        echo -e "${RED}解压后未找到可执行文件！${PLAIN}"
        rm -rf "${TMP_DIR}"
        exit 1
    fi

    chmod +x "${BIN_FILE}"
    rm -rf "${TMP_DIR}"
    echo -e "${GREEN}二进制文件已安装至 ${BIN_FILE}${PLAIN}"
}

generate_config() {
    echo -e "请选择您要部署的协议："
    echo "1. trojan + wss"
    echo "2. vless + wss"
    read -rp "请输入 [1/2]: " PROTO_CHOICE

    read -rp "请输入服务监听端口 (默认: 443): " PORT
    PORT=${PORT:-443}

    read -rp "请输入 WebSocket 路径 (默认: /ws): " WSPATH
    WSPATH=${WSPATH:-/ws}

    if [ "$PROTO_CHOICE" == "2" ]; then
        # vless
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${GREEN}已为您自动生成 VLESS UUID: ${UUID}${PLAIN}"
        cat > "${CONFIG_FILE}" <<EOF
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
        read -rp "请输入 Trojan 密码 (默认: 自动生成): " PASSWORD
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
            echo -e "${GREEN}已为您自动生成随机密码: ${PASSWORD}${PLAIN}"
        fi

        read -rp "请输入回落地址(Fallback) (默认: 127.0.0.1:80): " FALLBACK
        FALLBACK=${FALLBACK:-127.0.0.1:80}

        cat > "${CONFIG_FILE}" <<EOF
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
    cat > "${SERVICE_FILE}" <<EOF
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

    # --- 证书检测 ---
    issue_cert

    # --- 二进制检测 ---
    if [ -x "${BIN_FILE}" ]; then
        echo -e "${GREEN}检测到已安装的 trojan-rs 二进制文件 (${BIN_FILE})。${PLAIN}"
        CURRENT_VER=$("${BIN_FILE}" --version 2>/dev/null || echo "未知版本")
        echo -e "${YELLOW}当前版本: ${CURRENT_VER}${PLAIN}"
        read -rp "是否重新下载最新版本？[y/N]: " REDOWNLOAD
        if [[ "$REDOWNLOAD" =~ ^[Yy]$ ]]; then
            download_bin
        else
            echo -e "${GREEN}跳过下载，继续使用现有二进制文件。${PLAIN}"
        fi
    else
        download_bin
    fi

    # --- 配置检测 ---
    if [ -f "${CONFIG_FILE}" ]; then
        echo -e "${GREEN}检测到已有配置文件：${PLAIN}"
        echo -e "${YELLOW}────────────────────────────────${PLAIN}"
        cat "${CONFIG_FILE}"
        echo -e "${YELLOW}────────────────────────────────${PLAIN}"
        read -rp "是否复用当前配置？[Y/n]: " REUSE_CONFIG
        if [[ "$REUSE_CONFIG" =~ ^[Nn]$ ]]; then
            generate_config
        else
            echo -e "${GREEN}复用现有配置文件。${PLAIN}"
        fi
    else
        generate_config
    fi

    setup_systemd
    echo -e "${GREEN}安装与部署已全部完成！${PLAIN}"
    echo -e "${YELLOW}请使用菜单栏的日志查看功能确认服务是否正常运行。${PLAIN}"
}

manage_service() {
    echo "1. 启动服务 (Start)"
    echo "2. 停止服务 (Stop)"
    echo "3. 重启服务 (Restart)"
    echo "4. 查看状态 (Status)"
    read -rp "请输入 [1-4]: " ACTION
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
    cat "${CONFIG_FILE}"
    echo -e "\n${GREEN}请选择修改方式：${PLAIN}"
    echo "1. 使用 vim 手动编辑"
    echo "2. 使用 nano 手动编辑"
    echo "3. 重新运行自动配置向导 (将覆盖当前配置)"
    read -rp "请输入 [1-3]: " C_CHOICE
    case "${C_CHOICE}" in
        1) vim "${CONFIG_FILE}" ;;
        2) nano "${CONFIG_FILE}" ;;
        3) generate_config ;;
        *) echo -e "${RED}取消。${PLAIN}"; return ;;
    esac
    
    read -rp "修改完毕，是否立即重启服务生效？[y/N]: " RESTART_CONFIRM
    if [[ "$RESTART_CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl restart trojan-rs
        echo -e "${GREEN}服务已重启。${PLAIN}"
    fi
}

uninstall() {
    read -rp "警告：您确定要完全卸载 trojan-rs 吗？[y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl stop trojan-rs 2>/dev/null || true
        systemctl disable trojan-rs 2>/dev/null || true
        rm -f "${SERVICE_FILE}"
        systemctl daemon-reload

        # 提示用户清理 acme.sh 证书数据
        read -rp "是否同时清理 acme.sh 中该域名的证书和定时续期任务？[y/N]: " CLEAN_ACME
        if [[ "$CLEAN_ACME" =~ ^[Yy]$ ]]; then
            if [ -f "${CONFIG_FILE}" ]; then
                # 尝试从配置文件中提取证书路径推断域名
                ACME_CERT_PATH=$(grep 'cert' "${CONFIG_FILE}" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/' || true)
            fi
            read -rp "请输入要清理的域名 (直接回车跳过): " CLEAN_DOMAIN
            if [ -n "$CLEAN_DOMAIN" ]; then
                /root/.acme.sh/acme.sh --remove -d "${CLEAN_DOMAIN}" --ecc 2>/dev/null || true
                /root/.acme.sh/acme.sh --remove -d "${CLEAN_DOMAIN}" 2>/dev/null || true
                echo -e "${GREEN}已清理 acme.sh 中 ${CLEAN_DOMAIN} 的证书数据。${PLAIN}"
            fi
        fi

        rm -rf "${INSTALL_DIR}"
        echo -e "${GREEN}trojan-rs 已被彻底卸载！${PLAIN}"
    fi
}

menu() {
    while true; do
        echo ""
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
        read -rp "请输入选择 [0-5]: " CHOICE
        case "${CHOICE}" in
            1) install ;;
            2) change_config ;;
            3) manage_service ;;
            4) view_logs ;;
            5) uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入无效，请重新输入。${PLAIN}" ;;
        esac
    done
}

menu
