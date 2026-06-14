#!/bin/bash

# ========================================================================
# trojan-rs (trojan+wss / vless+wss) 一键安装管理脚本
# ========================================================================

set -euo pipefail

# ---- 字体颜色定义 ----
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
MAGENTA="\033[1;35m"
CYAN="\033[1;36m"
PLAIN="\033[0m"

# ---- 信息日志前缀 ----
INFO="[${CYAN}*${PLAIN}]"
SUCCESS="[${GREEN}+${PLAIN}]"
WARN="[${YELLOW}!${PLAIN}]"
ERROR="[${RED}-${PLAIN}]"

INSTALL_DIR="/usr/local/trojan-rs"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/trojan-rs.service"
CERT_DIR="${INSTALL_DIR}/cert"
BIN_FILE="${INSTALL_DIR}/trojan-rs"

# 请根据您的实际 GitHub 仓库修改此处，以获取最新的 Release 产物
GITHUB_REPO="tuxco-de/trojan-rs"

# ---- 辅助函数 ----
print_banner() {
    clear
    echo -e "${BLUE}========================================================================${PLAIN}"
    echo -e "${CYAN}    ████████╗██████╗  ██████╗      ██████╗  █████╗ ███╗   ██╗      ██████╗  ██████╗"
    echo -e "    ╚══██╔══╝██╔══██╗██╔═══██╗     ██╔══██╗██╔══██╗████╗  ██║      ██╔══██╗██╔════╝"
    echo -e "       ██║   ██████╔╝██║   ██║█████╗██████╔╝███████║██╔██╗ ██║█████╗██████╔╝╚█████╗"
    echo -e "       ██║   ██╔══██╗██║   ██║╚════╝██╔══██╗██╔══██║██║╚██╗██║╚════╝██╔══██╗ ╚═══██╗"
    echo -e "       ██║   ██║  ██║╚██████╔╝     ██║  ██║██║  ██║██║ ╚████║      ██║  ██║██████╔╝"
    echo -e "       ╚═╝   ╚═╝  ╚═╝ ╚═════╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚═════╝${PLAIN}"
    echo -e "${BLUE}========================================================================${PLAIN}"
    echo -e "                 ${MAGENTA}trojan-rs 一键部署与管理脚本 (v1.1.3)${PLAIN}"
    echo -e "${BLUE}========================================================================${PLAIN}"
}

press_any_key() {
    echo -e "\n${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
    echo -ne "${CYAN}按回车键返回主菜单...${PLAIN}"
    read -r
}

check_update() {
    print_banner
    echo -ne "${WARN} 是否检查并更新一键管理脚本本身？[y/N]: "
    read -r UPDATE_CONFIRM
    if [[ "$UPDATE_CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${INFO} 正在拉取最新脚本...${PLAIN}"
        local TMP_SCRIPT
        TMP_SCRIPT=$(mktemp)
        if curl -sL "https://raw.githubusercontent.com/${GITHUB_REPO}/main/scripts/install.sh" -o "${TMP_SCRIPT}"; then
            if grep -q "trojan-rs" "${TMP_SCRIPT}"; then
                cp -f "${TMP_SCRIPT}" "$0"
                chmod +x "$0"
                rm -f "${TMP_SCRIPT}"
                echo -e "${SUCCESS} 脚本更新成功！重新启动脚本...${PLAIN}"
                sleep 1
                exec "$0" "$@"
            else
                echo -e "${ERROR} 下载的内容似乎不合法，更新失败。${PLAIN}"
                rm -f "${TMP_SCRIPT}"
                press_any_key
            fi
        else
            echo -e "${ERROR} 网络原因拉取最新脚本失败！${PLAIN}"
            rm -f "${TMP_SCRIPT}"
            press_any_key
        fi
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${ERROR} 错误：本脚本必须以 root 身份运行！${PLAIN}"
        exit 1
    fi
}

install_deps() {
    echo -ne "${WARN} 是否需要更新并安装系统依赖 (curl, wget, tar, jq, openssl, socat, cron)？[Y/n]: "
    read -r INSTALL_DEPS_CONFIRM
    INSTALL_DEPS_CONFIRM=${INSTALL_DEPS_CONFIRM:-Y}
    if [[ "$INSTALL_DEPS_CONFIRM" =~ ^[Nn]$ ]]; then
        echo -e "${INFO} 跳过依赖安装。${PLAIN}"
        return
    fi

    echo -e "${INFO} 正在安装必要的依赖...${PLAIN}"
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update -y || true
        apt-get install -y curl wget tar jq openssl socat cron
    elif [ -x "$(command -v yum)" ]; then
        yum update -y || true
        yum install -y curl wget tar jq openssl socat cronie
    else
        echo -e "${ERROR} 不支持的操作系统，请使用 Ubuntu/Debian 或 CentOS。${PLAIN}"
        exit 1
    fi
}

install_acme() {
    if [ ! -d "/root/.acme.sh" ]; then
        echo -e "${INFO} 正在安装 acme.sh...${PLAIN}"
        curl https://get.acme.sh | sh
    else
        echo -e "${INFO} acme.sh 已安装。${PLAIN}"
    fi
}

issue_cert() {
    echo -ne "${INFO} 请输入您要配置的域名 (例如: example.com): "
    read -r DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${ERROR} 域名不能为空！${PLAIN}"
        exit 1
    fi

    if [ -f "/root/.acme.sh/${DOMAIN}_ecc/fullchain.cer" ] || [ -f "/root/.acme.sh/${DOMAIN}/fullchain.cer" ] || [ -f "${CERT_DIR}/fullchain.cer" ]; then
        echo -e "${INFO} 检测到本机或 acme.sh 中已存在域名 ${DOMAIN} 的证书。${PLAIN}"
        echo -ne "${WARN} 是否需要强制重新申请证书？[y/N]: "
        read -r RENEW_CONFIRM
        if [[ ! "$RENEW_CONFIRM" =~ ^[Yy]$ ]]; then
            echo -e "${INFO} 跳过证书申请，尝试直接安装现有证书...${PLAIN}"
            mkdir -p "${CERT_DIR}"
            if /root/.acme.sh/acme.sh --installcert -d "${DOMAIN}" --fullchainpath "${CERT_DIR}/fullchain.cer" --keypath "${CERT_DIR}/private.key" --ecc 2>/dev/null || \
               /root/.acme.sh/acme.sh --installcert -d "${DOMAIN}" --fullchainpath "${CERT_DIR}/fullchain.cer" --keypath "${CERT_DIR}/private.key" 2>/dev/null; then
                if [ -f "${CERT_DIR}/fullchain.cer" ] && [ -f "${CERT_DIR}/private.key" ]; then
                    echo -e "${SUCCESS} 已成功安装现有证书至 ${CERT_DIR}${PLAIN}"
                    return
                fi
            fi
            echo -e "${WARN} 无法安装现有证书，将继续申请新证书...${PLAIN}"
        fi
    fi

    echo -e "${WARN} 请确保您的域名已解析到本服务器的 IP，并且本机的 80 端口未被占用。${PLAIN}"
    echo -ne "${CYAN}按回车键继续申请证书...${PLAIN}"
    read -r

    mkdir -p "${CERT_DIR}"
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    if ! /root/.acme.sh/acme.sh --issue -d "${DOMAIN}" --standalone -k ec-256; then
        echo -e "${ERROR} 证书申请失败！请检查域名解析和 80 端口。${PLAIN}"
        exit 1
    fi

    /root/.acme.sh/acme.sh --installcert -d "${DOMAIN}" --fullchainpath "${CERT_DIR}/fullchain.cer" --keypath "${CERT_DIR}/private.key" --ecc

    if [ ! -f "${CERT_DIR}/fullchain.cer" ] || [ ! -f "${CERT_DIR}/private.key" ]; then
        echo -e "${ERROR} 证书安装失败！证书文件不存在。${PLAIN}"
        exit 1
    fi

    echo -e "${SUCCESS} 证书申请成功！已保存至 ${CERT_DIR}${PLAIN}"
}

download_bin() {
    echo -e "${INFO} 正在获取最新的 trojan-rs 版本...${PLAIN}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ASSET_KEYWORD="server-linux-amd64" ;;
        aarch64) ASSET_KEYWORD="server-linux-arm64" ;;
        *) echo -e "${ERROR} 不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac

    # 通过 GitHub API 获取最新 release 的下载链接
    API_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    DOWNLOAD_URL=$(curl -s "$API_URL" | jq -r ".assets[] | select(.name | contains(\"${ASSET_KEYWORD}\")) | .browser_download_url" || echo "")

    if [ -z "$DOWNLOAD_URL" ] || [ "$DOWNLOAD_URL" == "null" ]; then
        echo -e "${WARN} 无法自动找到适用于 ${ARCH} 架构的预编译文件，请检查您的 GitHub Release！${PLAIN}"
        echo -ne "${INFO} 尝试让您手动输入下载地址 (二进制压缩包直链): "
        read -r DOWNLOAD_URL
    fi

    if [ -z "$DOWNLOAD_URL" ]; then
        echo -e "${ERROR} 下载地址不能为空！${PLAIN}"
        exit 1
    fi

    echo -e "${INFO} 正在下载二进制包...${PLAIN}"
    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    if ! wget -O "${TMP_DIR}/trojan-rs.tar.gz" "${DOWNLOAD_URL}"; then
        echo -e "${ERROR} 下载失败！请检查网络连接或下载链接。${PLAIN}"
        rm -rf "${TMP_DIR}"
        exit 1
    fi

    if ! tar -xzf "${TMP_DIR}/trojan-rs.tar.gz" -C "${TMP_DIR}"; then
        echo -e "${ERROR} 解压失败！下载的文件可能已损坏。${PLAIN}"
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
        echo -e "${ERROR} 解压后未找到可执行文件！${PLAIN}"
        rm -rf "${TMP_DIR}"
        exit 1
    fi

    chmod +x "${BIN_FILE}"
    rm -rf "${TMP_DIR}"
    echo -e "${SUCCESS} 二进制文件已安装至 ${BIN_FILE}${PLAIN}"
}

generate_config() {
    echo -e "\n${INFO} 请选择您要部署的协议："
    echo -e " ${CYAN}1.${PLAIN} trojan + wss"
    echo -e " ${CYAN}2.${PLAIN} vless + wss"
    echo -ne "${CYAN}请输入选择 [1/2]: ${PLAIN}"
    read -r PROTO_CHOICE

    echo -ne "${INFO} 请输入服务监听端口 [默认: 443]: "
    read -r PORT
    PORT=${PORT:-443}

    echo -ne "${INFO} 请输入 WebSocket 路径 [默认: /ws]: "
    read -r WSPATH
    WSPATH=${WSPATH:-/ws}

    if [ "$PROTO_CHOICE" == "2" ]; then
        # vless
        UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "12345678-1234-1234-1234-1234567890ab")
        echo -e "${SUCCESS} 已为您自动生成 VLESS UUID: ${MAGENTA}${UUID}${PLAIN}"
        cat > "${CONFIG_FILE}" <<EOF
mode = "server"
log_level = "info"

[tls]
addr = "[::]:${PORT}"
cert = "${CERT_DIR}/fullchain.cer"
key = "${CERT_DIR}/private.key"

[vless]
users = ["${UUID}"]

[websocket]
path = "${WSPATH}"

[fallback]
page = "${INSTALL_DIR}/camouflage.html"
EOF

    else
        # trojan
        echo -ne "${INFO} 请输入 Trojan 密码 [默认: 自动生成]: "
        read -r PASSWORD
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
            echo -e "${SUCCESS} 已为您自动生成随机密码: ${MAGENTA}${PASSWORD}${PLAIN}"
        fi

        cat > "${CONFIG_FILE}" <<EOF
mode = "server"
log_level = "info"

[tls]
addr = "[::]:${PORT}"
cert = "${CERT_DIR}/fullchain.cer"
key = "${CERT_DIR}/private.key"

[trojan]
password = "${PASSWORD}"

[websocket]
path = "${WSPATH}"

[fallback]
page = "${INSTALL_DIR}/camouflage.html"
EOF
    fi

    echo -e "${SUCCESS} 配置文件生成完毕: ${CONFIG_FILE}${PLAIN}"
}

setup_systemd() {
    echo -e "${INFO} 配置 systemd 守护进程...${PLAIN}"
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
    echo -e "${SUCCESS} 服务已启动并设置为开机自启。${PLAIN}"
}

install() {
    check_root
    
    clear
    print_banner
    echo -e " ${CYAN}=== 全自动全新安装 ===${PLAIN}\n"

    install_deps
    install_acme

    # --- 证书检测 ---
    issue_cert

    # --- 二进制检测 ---
    if [ -x "${BIN_FILE}" ]; then
        echo -e "${SUCCESS} 检测到已安装的 trojan-rs 二进制文件 (${BIN_FILE})。${PLAIN}"
        CURRENT_VER=$("${BIN_FILE}" --version 2>/dev/null || echo "未知版本")
        echo -e "${INFO} 当前版本: ${MAGENTA}${CURRENT_VER}${PLAIN}"
        echo -ne "${WARN} 是否重新下载最新版本？[y/N]: "
        read -r REDOWNLOAD
        if [[ "$REDOWNLOAD" =~ ^[Yy]$ ]]; then
            download_bin
        else
            echo -e "${INFO} 跳过下载，继续使用现有二进制文件。${PLAIN}"
        fi
    else
        download_bin
    fi

    # --- 配置检测 ---
    if [ -f "${CONFIG_FILE}" ]; then
        echo -e "${SUCCESS} 检测到已有配置文件：${PLAIN}"
        echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
        cat "${CONFIG_FILE}"
        echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
        echo -ne "${WARN} 是否复用当前配置？[Y/n]: "
        read -r REUSE_CONFIG
        REUSE_CONFIG=${REUSE_CONFIG:-Y}
        if [[ "$REUSE_CONFIG" =~ ^[Nn]$ ]]; then
            generate_config
        else
            echo -e "${INFO} 复用现有配置文件。${PLAIN}"
        fi
    else
        generate_config
    fi

    # 自动拷贝伪装页面
    if [ -f "config/camouflage.html" ]; then
        cp -f "config/camouflage.html" "${INSTALL_DIR}/camouflage.html"
        echo -e "${SUCCESS} 伪装页面已成功部署至 ${INSTALL_DIR}/camouflage.html${PLAIN}"
    elif [ -f "../config/camouflage.html" ]; then
        cp -f "../config/camouflage.html" "${INSTALL_DIR}/camouflage.html"
        echo -e "${SUCCESS} 伪装页面已成功部署至 ${INSTALL_DIR}/camouflage.html${PLAIN}"
    fi

    setup_systemd
    echo -e "${SUCCESS} 安装与部署已全部完成！${PLAIN}"
    echo -e "${WARN} 请使用菜单栏的日志查看功能确认服务是否正常运行。${PLAIN}"
}

manage_service() {
    while true; do
        clear
        print_banner
        echo -e " ${CYAN}=== 服务管理 (Systemd) ===${PLAIN}\n"
        
        # 实时显示当前服务运行状态
        if systemctl is-active --quiet trojan-rs 2>/dev/null; then
            echo -e "${INFO} 当前服务状态: ${GREEN}运行中 (Running)${PLAIN}"
        else
            echo -e "${INFO} 当前服务状态: ${RED}已停止 (Stopped/Inactive)${PLAIN}"
        fi
        echo ""
        
        echo -e " ${CYAN}1.${PLAIN} 启动服务 (Start)"
        echo -e " ${CYAN}2.${PLAIN} 停止服务 (Stop)"
        echo -e " ${CYAN}3.${PLAIN} 重启服务 (Restart)"
        echo -e " ${CYAN}4.${PLAIN} 查看状态 (Status)"
        echo -e " ${CYAN}0.${PLAIN} 返回主菜单"
        echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
        echo -ne "${CYAN}请输入选择 [0-4]: ${PLAIN}"
        read -r ACTION
        case "${ACTION}" in
            1)
                echo -e "${INFO} 正在启动服务...${PLAIN}"
                systemctl start trojan-rs 2>/dev/null || true
                echo -e "${SUCCESS} 已发送启动指令。${PLAIN}"
                sleep 1
                ;;
            2)
                echo -e "${INFO} 正在停止服务...${PLAIN}"
                systemctl stop trojan-rs 2>/dev/null || true
                echo -e "${SUCCESS} 已发送停止指令。${PLAIN}"
                sleep 1
                ;;
            3)
                echo -e "${INFO} 正在重启服务...${PLAIN}"
                systemctl restart trojan-rs 2>/dev/null || true
                echo -e "${SUCCESS} 已发送重启指令。${PLAIN}"
                sleep 1
                ;;
            4)
                echo -e "\n${INFO} 服务详细状态："
                echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
                systemctl status trojan-rs || true
                echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
                echo -ne "${CYAN}按回车键继续...${PLAIN}"
                read -r
                ;;
            0)
                return
                ;;
            *)
                echo -e "${ERROR} 无效选项，请重新选择。${PLAIN}"
                sleep 1
                ;;
        esac
    done
}

view_logs() {
    clear
    print_banner
    echo -e " ${CYAN}=== 查看实时运行日志 ===${PLAIN}\n"
    echo -e "${INFO} 正在打开日志流，按 Ctrl+C 退出...${PLAIN}"
    journalctl -u trojan-rs -f
}

change_config() {
    clear
    print_banner
    echo -e " ${CYAN}=== 修改/查看配置文件 ===${PLAIN}\n"
    if [ ! -f "${CONFIG_FILE}" ]; then
        echo -e "${ERROR} 未找到配置文件 ${CONFIG_FILE}${PLAIN}"
        press_any_key
        return
    fi
    echo -e "${INFO} 当前配置如下：${PLAIN}"
    echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
    cat "${CONFIG_FILE}"
    echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
    echo -e "\n${INFO} 请选择修改方式："
    echo -e " ${CYAN}1.${PLAIN} 使用 vim 手动编辑"
    echo -e " ${CYAN}2.${PLAIN} 使用 nano 手动编辑"
    echo -e " ${CYAN}3.${PLAIN} 重新运行自动配置向导 (将覆盖当前配置)"
    echo -e " ${CYAN}0.${PLAIN} 返回主菜单"
    echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
    echo -ne "${CYAN}请输入选择 [0-3]: ${PLAIN}"
    read -r C_CHOICE
    case "${C_CHOICE}" in
        1) vim "${CONFIG_FILE}" ;;
        2) nano "${CONFIG_FILE}" ;;
        3) generate_config ;;
        0) return ;;
        *) echo -e "${ERROR} 无效选项，取消操作。${PLAIN}"; press_any_key; return ;;
    esac
    
    echo -ne "\n${WARN} 修改完毕，是否立即重启服务生效？[y/N]: "
    read -r RESTART_CONFIRM
    if [[ "$RESTART_CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${INFO} 正在重启服务...${PLAIN}"
        systemctl restart trojan-rs 2>/dev/null || true
        echo -e "${SUCCESS} 服务已重启。${PLAIN}"
    fi
    press_any_key
}

uninstall() {
    clear
    print_banner
    echo -e " ${CYAN}=== 彻底卸载 trojan-rs ===${PLAIN}\n"
    echo -ne "${WARN} 警告：您确定要完全卸载 trojan-rs 吗？[y/N]: "
    read -r CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl stop trojan-rs 2>/dev/null || true
        systemctl disable trojan-rs 2>/dev/null || true
        rm -f "${SERVICE_FILE}"
        systemctl daemon-reload

        # 提示用户清理 acme.sh 证书数据
        echo -ne "${WARN} 是否同时清理 acme.sh 中该域名的证书和定时续期任务？[y/N]: "
        read -r CLEAN_ACME
        if [[ "$CLEAN_ACME" =~ ^[Yy]$ ]]; then
            echo -ne "${INFO} 请输入要清理的域名 (直接回车跳过): "
            read -r CLEAN_DOMAIN
            if [ -n "$CLEAN_DOMAIN" ]; then
                /root/.acme.sh/acme.sh --remove -d "${CLEAN_DOMAIN}" --ecc 2>/dev/null || true
                /root/.acme.sh/acme.sh --remove -d "${CLEAN_DOMAIN}" 2>/dev/null || true
                echo -e "${SUCCESS} 已清理 acme.sh 中 ${CLEAN_DOMAIN} 的证书数据。${PLAIN}"
            fi
        fi

        rm -rf "${INSTALL_DIR}"
        echo -e "${SUCCESS} trojan-rs 已被彻底卸载！${PLAIN}"
    else
        echo -e "${INFO} 已取消卸载操作。${PLAIN}"
    fi
}

update_bin_only() {
    check_root
    clear
    print_banner
    echo -e " ${CYAN}=== 仅更新核心二进制文件 ===${PLAIN}\n"
    if [ ! -f "${BIN_FILE}" ]; then
        echo -e "${ERROR} 未检测到已安装的 trojan-rs，请先执行全新安装。${PLAIN}"
        return
    fi
    echo -e "${INFO} 准备更新二进制文件...${PLAIN}"
    CURRENT_VER=$("${BIN_FILE}" --version 2>/dev/null || echo "未知版本")
    echo -e "${INFO} 当前版本: ${MAGENTA}${CURRENT_VER}${PLAIN}"
    
    echo -e "${INFO} 正在停止服务...${PLAIN}"
    systemctl stop trojan-rs 2>/dev/null || true
    
    download_bin
    
    echo -e "${INFO} 正在重启服务...${PLAIN}"
    systemctl start trojan-rs 2>/dev/null || true
    echo -e "${SUCCESS} 二进制文件更新完毕！${PLAIN}"
}

share_node() {
    clear
    print_banner
    echo -e " ${CYAN}=== 生成 Clash 节点配置 (JSON) ===${PLAIN}\n"
    if [ ! -f "${CONFIG_FILE}" ]; then
        echo -e "${ERROR} 未找到配置文件 ${CONFIG_FILE}，请先执行安装。${PLAIN}"
        return
    fi

    local PORT
    PORT=$(grep -E '^\s*addr\s*=' "${CONFIG_FILE}" | awk -F':' '{print $NF}' | tr -d '", ')
    local WSPATH
    WSPATH=$(grep -E '^\s*path\s*=' "${CONFIG_FILE}" | awk -F'=' '{print $2}' | tr -d '", ')

    local TYPE
    local PASSWORD=""
    local UUID=""

    if grep -q '\[vless\]' "${CONFIG_FILE}"; then
        TYPE="vless"
        UUID=$(grep -E '^\s*users\s*=' "${CONFIG_FILE}" | grep -oE '[0-9a-fA-F-]{36}')
    elif grep -q '\[trojan\]' "${CONFIG_FILE}"; then
        TYPE="trojan"
        PASSWORD=$(grep -E '^\s*password\s*=' "${CONFIG_FILE}" | awk -F'=' '{print $2}' | tr -d '", ')
    else
        echo -e "${ERROR} 无法识别配置中的协议类型。${PLAIN}"
        return
    fi

    echo -ne "${INFO} 请输入该节点绑定的域名 (用于客户端连接，如 example.com): "
    read -r NODE_DOMAIN
    if [ -z "$NODE_DOMAIN" ]; then
        echo -e "${ERROR} 域名不能为空！${PLAIN}"
        return
    fi

    echo -e "\n${BLUE}========== Clash 节点配置 (JSON 格式) ==========${PLAIN}"
    if [ "$TYPE" == "vless" ]; then
        cat <<EOF
{
  "name": "trojan-rs-vless",
  "type": "vless",
  "server": "${NODE_DOMAIN}",
  "port": ${PORT},
  "uuid": "${UUID}",
  "network": "ws",
  "tls": true,
  "udp": true,
  "sni": "${NODE_DOMAIN}",
  "client-fingerprint": "chrome",
  "ws-opts": {
    "path": "${WSPATH}",
    "headers": {
      "Host": "${NODE_DOMAIN}"
    }
  }
}
EOF
    else
        cat <<EOF
{
  "name": "trojan-rs-trojan",
  "type": "trojan",
  "server": "${NODE_DOMAIN}",
  "port": ${PORT},
  "password": "${PASSWORD}",
  "network": "ws",
  "sni": "${NODE_DOMAIN}",
  "udp": true,
  "ws-opts": {
    "path": "${WSPATH}",
    "headers": {
      "Host": "${NODE_DOMAIN}"
    }
  }
}
EOF
    fi
    echo -e "${BLUE}================================================${PLAIN}\n"
}

menu() {
    while true; do
        print_banner
        echo -e " ${CYAN}1.${PLAIN} 全自动全新安装"
        echo -e " ${CYAN}2.${PLAIN} 修改/查看配置文件"
        echo -e " ${CYAN}3.${PLAIN} 服务管理 (启动/停止/重启/查看状态)"
        echo -e " ${CYAN}4.${PLAIN} 查看实时运行日志"
        echo -e " ${CYAN}5.${PLAIN} 彻底卸载"
        echo -e " ${CYAN}6.${PLAIN} 生成 Clash 节点配置 (JSON)"
        echo -e " ${CYAN}7.${PLAIN} 仅更新核心二进制文件"
        echo -e " ${CYAN}0.${PLAIN} 退出脚本"
        echo -e "${BLUE}========================================================================${PLAIN}"
        echo -ne "${CYAN}请输入选择 [0-7]: ${PLAIN}"
        read -r CHOICE
        case "${CHOICE}" in
            1) install; press_any_key ;;
            2) change_config ;;
            3) manage_service ;;
            4) view_logs; press_any_key ;;
            5) uninstall; press_any_key ;;
            6) share_node; press_any_key ;;
            7) update_bin_only; press_any_key ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入无效，请重新输入。${PLAIN}"; sleep 1 ;;
        esac
    done
}

check_update
menu
