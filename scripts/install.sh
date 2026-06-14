#!/bin/bash

# ========================================================================
# trojan-rs (trojan+wss / vless+wss) 一键安装管理脚本
# ========================================================================

set -euo pipefail

SCRIPT_VERSION="1.1.8"
TROJAN_RS_VERSION="latest"

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
if [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then
    SERVICE_FILE="/etc/systemd/system/trojan-rs.service"
else
    SERVICE_FILE="/etc/init.d/trojan-rs"
fi
CERT_DIR="${INSTALL_DIR}/cert"
BIN_FILE="${INSTALL_DIR}/trojan-rs"
DOMAIN_FILE="${INSTALL_DIR}/domain"
ACME_SH="/root/.acme.sh/acme.sh"
SCRIPT_PATH="${BASH_SOURCE[0]}"
if ! SCRIPT_DIR=$(cd -- "$(dirname -- "${SCRIPT_PATH}")" 2>/dev/null && pwd -P); then
    SCRIPT_DIR=$(pwd -P)
fi

# 请根据您的实际 GitHub 仓库修改此处，以获取最新的 Release 产物
GITHUB_REPO="tuxco-de/trojan-rs"

# ---- 辅助函数 ----
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

safe_clear() {
    if [ -t 1 ] && command_exists clear; then
        clear 2>/dev/null || true
    fi
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

is_valid_domain() {
    local domain=$1
    local label
    local -a labels

    [[ ${#domain} -le 253 && "$domain" == *.* && "$domain" != *..* ]] || return 1
    [[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    IFS='.' read -r -a labels <<<"$domain"
    for label in "${labels[@]}"; do
        [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

is_valid_ws_path() {
    [[ "$1" == /* && "$1" != *'?'* && "$1" != *'#'* && "$1" != *$'\n'* && "$1" != *$'\r'* ]]
}

toml_escape() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

json_escape() {
    toml_escape "$1"
}

has_systemd() {
    [ -d /run/systemd/system ] || command_exists systemctl
}

has_openrc() {
    command_exists rc-service && command_exists rc-update
}

svc_start() { has_systemd && svc_start || rc-service trojan-rs start; }
svc_stop() { has_systemd && svc_stop 2>/dev/null || rc-service trojan-rs stop 2>/dev/null; }
svc_restart() { has_systemd && svc_restart || rc-service trojan-rs restart; }
svc_try_restart() { has_systemd && systemctl try-restart trojan-rs.service 2>/dev/null || rc-service trojan-rs restart 2>/dev/null; }
svc_enable() { has_systemd && systemctl enable trojan-rs.service >/dev/null || rc-update add trojan-rs default >/dev/null; }
svc_disable() { has_systemd && systemctl disable trojan-rs.service 2>/dev/null || rc-update del trojan-rs default 2>/dev/null; }
svc_status() { has_systemd && svc_status || rc-service trojan-rs status; }
svc_is_active() { has_systemd && svc_is_active || rc-service trojan-rs status | grep -q "started"; }
svc_daemon_reload() { has_systemd && systemctl daemon-reload || true; }
svc_logs() {
    if has_systemd; then
        svc_logs
    else
        tail -n 30 /var/log/trojan-rs.log 2>/dev/null || true
    fi
}
svc_logs_f() {
    if has_systemd; then
        svc_logs_f
    else
        tail -f /var/log/trojan-rs.log || true
    fi
}


generate_uuid() {
    local hex
    if [ -r /proc/sys/kernel/random/uuid ]; then
        tr -d '\r\n' </proc/sys/kernel/random/uuid
    elif command_exists uuidgen; then
        uuidgen
    elif command_exists openssl; then
        hex=$(openssl rand -hex 16)
        printf '%s-%s-4%s-8%s-%s\n' \
            "${hex:0:8}" "${hex:8:4}" "${hex:13:3}" "${hex:17:3}" "${hex:20:12}"
    else
        echo -e "${ERROR} 无法生成 UUID：系统缺少可用的随机数工具。${PLAIN}" >&2
        return 1
    fi
}

generate_password() {
    openssl rand -hex 16
}

require_runtime() {
    local missing=()
    local command
    for command in curl tar openssl mktemp install; do
        if ! command_exists "$command"; then
            missing+=("$command")
        fi
    done
    if ((${#missing[@]} > 0)); then
        echo -e "${ERROR} 缺少必要命令: ${missing[*]}${PLAIN}"
        return 1
    fi
    if ! has_systemd && ! has_openrc; then
        echo -e "${ERROR} 当前系统未运行 systemd 或 OpenRC，无法安装服务。${PLAIN}"
        return 1
    fi
}

print_banner() {
    safe_clear
    echo -e "${BLUE}========================================================================${PLAIN}"
    echo -e "${CYAN}    ████████╗██████╗  ██████╗      ██████╗  █████╗ ███╗   ██╗      ██████╗  ██████╗"
    echo -e "    ╚══██╔══╝██╔══██╗██╔═══██╗     ██╔══██╗██╔══██╗████╗  ██║      ██╔══██╗██╔════╝"
    echo -e "       ██║   ██████╔╝██║   ██║█████╗██████╔╝███████║██╔██╗ ██║█████╗██████╔╝╚█████╗"
    echo -e "       ██║   ██╔══██╗██║   ██║╚════╝██╔══██╗██╔══██║██║╚██╗██║╚════╝██╔══██╗ ╚═══██╗"
    echo -e "       ██║   ██║  ██║╚██████╔╝     ██║  ██║██║  ██║██║ ╚████║      ██║  ██║██████╔╝"
    echo -e "       ╚═╝   ╚═╝  ╚═╝ ╚═════╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚═════╝${PLAIN}"
    echo -e "${BLUE}========================================================================${PLAIN}"
    echo -e "                 ${MAGENTA}trojan-rs 一键部署与管理脚本 (v${SCRIPT_VERSION})${PLAIN}"
    echo -e "${BLUE}========================================================================${PLAIN}"
}

press_any_key() {
    echo -e "\n${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
    echo -ne "${CYAN}按回车键返回主菜单...${PLAIN}"
    read -r
}

check_update() {
    print_banner
    if ! command_exists curl; then
        echo -e "${WARN} 未找到 curl，跳过脚本更新检查。${PLAIN}"
        return
    fi
    if [ ! -f "${SCRIPT_PATH}" ] || [ ! -w "${SCRIPT_PATH}" ]; then
        echo -e "${WARN} 当前脚本不是可写的普通文件，跳过自更新。${PLAIN}"
        return
    fi
    echo -ne "${WARN} 是否检查并更新一键管理脚本本身？[y/N]: "
    read -r UPDATE_CONFIRM
    if [[ "$UPDATE_CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${INFO} 正在拉取最新脚本...${PLAIN}"
        local TMP_SCRIPT
        TMP_SCRIPT=$(mktemp)
        if curl --fail --silent --show-error --location --retry 3 \
            "https://raw.githubusercontent.com/${GITHUB_REPO}/main/scripts/install.sh" \
            -o "${TMP_SCRIPT}"; then
            if grep -q '^#!/bin/bash' "${TMP_SCRIPT}" && bash -n "${TMP_SCRIPT}"; then
                local current_hash=""
                local tmp_hash=""
                if command_exists sha256sum; then
                    current_hash=$(sha256sum "${SCRIPT_PATH}" | awk '{print $1}')
                    tmp_hash=$(sha256sum "${TMP_SCRIPT}" | awk '{print $1}')
                elif command_exists md5sum; then
                    current_hash=$(md5sum "${SCRIPT_PATH}" | awk '{print $1}')
                    tmp_hash=$(md5sum "${TMP_SCRIPT}" | awk '{print $1}')
                fi

                local is_same=false
                if [ -n "${current_hash}" ] && [ "${current_hash}" == "${tmp_hash}" ]; then
                    is_same=true
                elif cmp -s "${TMP_SCRIPT}" "${SCRIPT_PATH}"; then
                    is_same=true
                fi

                if ${is_same}; then
                    rm -f "${TMP_SCRIPT}"
                    echo -e "${SUCCESS} 当前脚本已经是最新版本。${PLAIN}"
                    return
                fi
                install -m 0755 "${TMP_SCRIPT}" "${SCRIPT_PATH}"
                rm -f "${TMP_SCRIPT}"
                echo -e "${SUCCESS} 脚本更新成功！重新启动脚本...${PLAIN}"
                sleep 1
                exec "${SCRIPT_PATH}" "$@"
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
    echo -ne "${WARN} 是否需要更新并安装系统依赖 (curl, tar, openssl)？[Y/n]: "
    read -r INSTALL_DEPS_CONFIRM
    INSTALL_DEPS_CONFIRM=${INSTALL_DEPS_CONFIRM:-Y}
    if [[ "$INSTALL_DEPS_CONFIRM" =~ ^[Nn]$ ]]; then
        echo -e "${INFO} 跳过依赖安装。${PLAIN}"
        return
    fi

    echo -e "${INFO} 正在安装必要的依赖...${PLAIN}"
    if command_exists apt-get; then
        apt-get update -y || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar openssl
    elif command_exists dnf; then
        dnf install -y curl tar openssl
    elif command_exists yum; then
        yum install -y curl tar openssl
    elif command_exists apk; then
        apk update || true
        apk add curl tar openssl
    else
        echo -e "${ERROR} 不支持的包管理器，请使用 Debian/Ubuntu, RHEL/CentOS/Fedora 或 Alpine。${PLAIN}"
        exit 1
    fi
}

install_acme() {
    if [ ! -x "${ACME_SH}" ]; then
        echo -e "${INFO} 正在安装 acme.sh...${PLAIN}"
        curl --fail --silent --show-error --location https://get.acme.sh | sh -s -- --nocron
    else
        echo -e "${INFO} acme.sh 已安装。${PLAIN}"
    fi
    if [ ! -x "${ACME_SH}" ]; then
        echo -e "${ERROR} acme.sh 安装失败或文件不可执行。${PLAIN}"
        return 1
    fi
}

install_acme_certificate() {
    local domain=$1
    local reload_command='svc_try_restart'

    mkdir -p "${CERT_DIR}"
    if "${ACME_SH}" --install-cert -d "${domain}" \
        --fullchain-file "${CERT_DIR}/fullchain.cer" \
        --key-file "${CERT_DIR}/private.key" \
        --reloadcmd "${reload_command}" --ecc 2>/dev/null || \
       "${ACME_SH}" --install-cert -d "${domain}" \
        --fullchain-file "${CERT_DIR}/fullchain.cer" \
        --key-file "${CERT_DIR}/private.key" \
        --reloadcmd "${reload_command}" 2>/dev/null; then
        if [ ! -s "${CERT_DIR}/fullchain.cer" ] || [ ! -s "${CERT_DIR}/private.key" ]; then
            return 1
        fi
        chmod 600 "${CERT_DIR}/private.key"
        printf '%s\n' "${domain}" >"${DOMAIN_FILE}"
        return 0
    fi
    return 1
}

certificate_is_usable() {
    local domain=$1
    [ -s "${CERT_DIR}/fullchain.cer" ] && \
        [ -s "${CERT_DIR}/private.key" ] && \
        openssl x509 -in "${CERT_DIR}/fullchain.cer" -noout -checkhost "${domain}" >/dev/null 2>&1 && \
        openssl x509 -in "${CERT_DIR}/fullchain.cer" -noout -checkend 604800 >/dev/null 2>&1
}

issue_manual_dns_certificate() {
    local domain=$1
    local force_issue=${2:-false}
    local retry
    local -a issue_command=(
        "${ACME_SH}" --issue -d "${domain}" --dns
        --yes-I-know-dns-manual-mode-enough-go-ahead-please
        -k ec-256
    )

    if ${force_issue}; then
        issue_command+=(--force)
    fi

    echo -e "${INFO} 正在创建手动 DNS 验证请求。请记录下面输出的 TXT 域名和值。${PLAIN}"
    if "${issue_command[@]}"; then
        if install_acme_certificate "${domain}" && certificate_is_usable "${domain}"; then
            return 0
        fi
    else
        echo -e "${INFO} acme.sh 已生成 DNS 验证记录；此阶段返回非零状态通常表示正在等待手动配置 TXT。${PLAIN}"
    fi

    echo -e "${WARN} 请在 DNS 服务商处添加 acme.sh 输出的 _acme-challenge TXT 记录。${PLAIN}"
    echo -e "${WARN} 手动 DNS 模式无法自动续期；证书到期前必须重新运行本脚本并更新 TXT 记录。${PLAIN}"
    while true; do
        echo -ne "${CYAN}确认 TXT 记录已添加并生效后按回车继续，输入 q 取消: ${PLAIN}"
        read -r DNS_READY
        if [[ "${DNS_READY}" =~ ^[Qq]$ ]]; then
            echo -e "${WARN} 已取消证书验证。稍后可重新运行安装流程继续。${PLAIN}"
            return 1
        fi

        if "${ACME_SH}" --renew -d "${domain}" \
            --yes-I-know-dns-manual-mode-enough-go-ahead-please; then
            return 0
        fi

        echo -e "${WARN} DNS 验证尚未通过。请确认 TXT 值正确，并等待 DNS 传播。${PLAIN}"
        echo -ne "${CYAN}是否使用同一条 TXT 记录重试验证？[Y/n]: ${PLAIN}"
        read -r retry
        retry=${retry:-Y}
        if [[ "${retry}" =~ ^[Nn]$ ]]; then
            return 1
        fi
    done
}

issue_cert() {
    local domain_default=""
    local renew=false
    if [ -f "${DOMAIN_FILE}" ]; then
        domain_default=$(tr -d '\r\n' <"${DOMAIN_FILE}")
    fi
    while true; do
        if [ -n "${domain_default}" ]; then
            echo -ne "${INFO} 请输入要配置的域名 [默认: ${domain_default}]: "
        else
            echo -ne "${INFO} 请输入要配置的域名 (例如: example.com): "
        fi
        read -r DOMAIN
        DOMAIN=${DOMAIN:-${domain_default}}
        if is_valid_domain "${DOMAIN}"; then
            break
        fi
        echo -e "${ERROR} 域名格式无效，请输入完整域名。${PLAIN}"
    done

    local dots=${DOMAIN//[^.]/}
    if ((${#dots} >= 3)); then
        echo -e "${WARN} 当前为多级子域名；使用 CDN 时请确认边缘证书明确覆盖 ${DOMAIN}。${PLAIN}"
    fi

    if certificate_is_usable "${DOMAIN}"; then
        echo -e "${INFO} 检测到覆盖 ${DOMAIN} 的已安装证书。${PLAIN}"
        echo -ne "${WARN} 是否需要强制重新申请证书？[y/N]: "
        read -r RENEW_CONFIRM
        if [[ ! "$RENEW_CONFIRM" =~ ^[Yy]$ ]]; then
            printf '%s\n' "${DOMAIN}" >"${DOMAIN_FILE}"
            echo -e "${SUCCESS} 继续使用现有证书。${PLAIN}"
            return
        fi
        renew=true
    elif [ -d "/root/.acme.sh/${DOMAIN}_ecc" ] || [ -d "/root/.acme.sh/${DOMAIN}" ]; then
        echo -e "${INFO} 检测到 acme.sh 中已有 ${DOMAIN} 的证书，正在安装...${PLAIN}"
        if install_acme_certificate "${DOMAIN}" && certificate_is_usable "${DOMAIN}"; then
            echo -e "${SUCCESS} 已安装现有证书至 ${CERT_DIR}。${PLAIN}"
            return
        fi
        echo -e "${WARN} 现有证书无效或将在 7 天内过期，将重新申请。${PLAIN}"
        renew=true
    fi

    echo -e "${WARN} 证书将使用手动 DNS-01 验证，不要求域名指向本机，也不占用 80/443 端口。${PLAIN}"
    echo -ne "${CYAN}按回车键生成 DNS TXT 验证记录...${PLAIN}"
    read -r

    mkdir -p "${CERT_DIR}"
    "${ACME_SH}" --set-default-ca --server letsencrypt
    if ! issue_manual_dns_certificate "${DOMAIN}" "${renew}"; then
        echo -e "${ERROR} 手动 DNS 证书签发未完成。${PLAIN}"
        return 1
    fi

    if ! install_acme_certificate "${DOMAIN}" || ! certificate_is_usable "${DOMAIN}"; then
        echo -e "${ERROR} 证书安装或校验失败。${PLAIN}"
        return 1
    fi

    if ${renew}; then
        echo -e "${SUCCESS} 证书已重新申请并保存至 ${CERT_DIR}。${PLAIN}"
    else
        echo -e "${SUCCESS} 证书申请成功！已保存至 ${CERT_DIR}${PLAIN}"
    fi
}

deploy_camouflage() {
    local source_file=""
    local temp_file

    if [ -f "${SCRIPT_DIR}/../config/camouflage.html" ]; then
        source_file="${SCRIPT_DIR}/../config/camouflage.html"
    elif [ -f "${SCRIPT_DIR}/config/camouflage.html" ]; then
        source_file="${SCRIPT_DIR}/config/camouflage.html"
    fi

    mkdir -p "${INSTALL_DIR}"
    if [ -n "${source_file}" ]; then
        install -m 0644 "${source_file}" "${INSTALL_DIR}/camouflage.html"
    else
        temp_file=$(mktemp)
        if ! curl --fail --silent --show-error --location --retry 3 \
            "https://raw.githubusercontent.com/${GITHUB_REPO}/main/config/camouflage.html" \
            -o "${temp_file}"; then
            rm -f "${temp_file}"
            echo -e "${ERROR} 无法下载伪装页面。${PLAIN}"
            return 1
        fi
        if [ ! -s "${temp_file}" ] || ! grep -qi '<html' "${temp_file}"; then
            rm -f "${temp_file}"
            echo -e "${ERROR} 下载的伪装页面内容无效。${PLAIN}"
            return 1
        fi
        install -m 0644 "${temp_file}" "${INSTALL_DIR}/camouflage.html"
        rm -f "${temp_file}"
    fi
    echo -e "${SUCCESS} 伪装页面已部署至 ${INSTALL_DIR}/camouflage.html${PLAIN}"
}

download_bin() {
    echo -e "${INFO} 正在获取最新的 trojan-rs 版本...${PLAIN}"
    local arch
    local asset_name
    local download_url
    local temp_dir
    local archive
    local extracted_bin
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) asset_name="trojan-rs-server-linux-amd64.tar.gz" ;;
        aarch64|arm64) asset_name="trojan-rs-server-linux-arm64.tar.gz" ;;
        *) echo -e "${ERROR} 不支持的架构: $arch${PLAIN}"; return 1 ;;
    esac

    download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/${asset_name}"
    temp_dir=$(mktemp -d)
    archive="${temp_dir}/${asset_name}"
    echo -e "${INFO} 正在下载 ${asset_name}...${PLAIN}"
    if ! curl --fail --location --retry 3 --output "${archive}" "${download_url}"; then
        rm -f "${archive}"
        echo -e "${WARN} 自动下载失败，当前 Release 可能没有 ${arch} 架构产物。${PLAIN}"
        echo -ne "${INFO} 尝试让您手动输入下载地址 (二进制压缩包直链): "
        read -r download_url
        if [ -z "${download_url}" ] || \
           ! curl --fail --location --retry 3 --output "${archive}" "${download_url}"; then
            echo -e "${ERROR} 下载失败！请检查网络连接或下载链接。${PLAIN}"
            rm -rf -- "${temp_dir}"
            return 1
        fi
    fi

    if ! tar -xzf "${archive}" -C "${temp_dir}"; then
        echo -e "${ERROR} 解压失败！下载的文件可能已损坏。${PLAIN}"
        rm -rf -- "${temp_dir}"
        return 1
    fi

    mkdir -p "${INSTALL_DIR}"

    if [ -f "${temp_dir}/trojan-rs-server" ]; then
        extracted_bin="${temp_dir}/trojan-rs-server"
    elif [ -f "${temp_dir}/trojan-rs" ]; then
        extracted_bin="${temp_dir}/trojan-rs"
    elif [ -f "${temp_dir}/trojan-r" ]; then
        extracted_bin="${temp_dir}/trojan-r"
    else
        echo -e "${ERROR} 解压后未找到可执行文件！${PLAIN}"
        rm -rf -- "${temp_dir}"
        return 1
    fi

    install -m 0755 "${extracted_bin}" "${BIN_FILE}.new"
    if ! "${BIN_FILE}.new" --version >/dev/null 2>&1; then
        rm -f "${BIN_FILE}.new"
        rm -rf -- "${temp_dir}"
        echo -e "${ERROR} 下载的二进制文件无法运行，已拒绝安装。${PLAIN}"
        return 1
    fi
    mv -f "${BIN_FILE}.new" "${BIN_FILE}"
    rm -rf -- "${temp_dir}"
    echo -e "${SUCCESS} 二进制文件已安装至 ${BIN_FILE}${PLAIN}"
}

generate_config() {
    local config_temp
    local escaped_path
    local escaped_secret
    echo -e "\n${INFO} 请选择您要部署的协议："
    echo -e " ${CYAN}1.${PLAIN} trojan + wss"
    echo -e " ${CYAN}2.${PLAIN} vless + wss"
    while true; do
        echo -ne "${CYAN}请输入选择 [1/2]: ${PLAIN}"
        read -r PROTO_CHOICE
        [[ "${PROTO_CHOICE}" == "1" || "${PROTO_CHOICE}" == "2" ]] && break
        echo -e "${ERROR} 请选择 1 或 2。${PLAIN}"
    done

    while true; do
        echo -ne "${INFO} 请输入服务监听端口 [默认: 443]: "
        read -r PORT
        PORT=${PORT:-443}
        is_valid_port "${PORT}" && break
        echo -e "${ERROR} 端口必须是 1 到 65535 之间的整数。${PLAIN}"
    done

    while true; do
        echo -ne "${INFO} 请输入 WebSocket 路径 [默认: /ws]: "
        read -r WSPATH
        WSPATH=${WSPATH:-/ws}
        is_valid_ws_path "${WSPATH}" && break
        echo -e "${ERROR} WebSocket 路径必须以 / 开头，且不能包含查询参数或片段。${PLAIN}"
    done

    mkdir -p "${INSTALL_DIR}"
    config_temp=$(mktemp "${INSTALL_DIR}/config.toml.XXXXXX")
    escaped_path=$(toml_escape "${WSPATH}")

    local listen_addr="0.0.0.0"
    if [ -f /proc/net/if_inet6 ]; then
        listen_addr="[::]"
    fi

    if [ "$PROTO_CHOICE" == "2" ]; then
        # vless
        UUID=$(generate_uuid)
        echo -e "${SUCCESS} 已为您自动生成 VLESS UUID: ${MAGENTA}${UUID}${PLAIN}"
        cat > "${config_temp}" <<EOF
mode = "server"
log_level = "info"

[tls]
addr = "${listen_addr}:${PORT}"
cert = "${CERT_DIR}/fullchain.cer"
key = "${CERT_DIR}/private.key"

[vless]
users = ["${UUID}"]

[websocket]
path = "${escaped_path}"

[fallback]
page = "${INSTALL_DIR}/camouflage.html"
EOF

    else
        # trojan
        echo -ne "${INFO} 请输入 Trojan 密码 [默认: 自动生成]: "
        read -r PASSWORD
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(generate_password)
            echo -e "${SUCCESS} 已为您自动生成随机密码: ${MAGENTA}${PASSWORD}${PLAIN}"
        fi
        escaped_secret=$(toml_escape "${PASSWORD}")

        cat > "${config_temp}" <<EOF
mode = "server"
log_level = "info"

[tls]
addr = "${listen_addr}:${PORT}"
cert = "${CERT_DIR}/fullchain.cer"
key = "${CERT_DIR}/private.key"

[trojan]
password = "${escaped_secret}"

[websocket]
path = "${escaped_path}"

[fallback]
page = "${INSTALL_DIR}/camouflage.html"
EOF
    fi

    chmod 600 "${config_temp}"
    mv -f "${config_temp}" "${CONFIG_FILE}"
    echo -e "${SUCCESS} 配置文件生成完毕: ${CONFIG_FILE}${PLAIN}"
}

show_recent_logs() {
    svc_logs
}

check_service_health() {
    sleep 1
    if svc_is_active; then
        return 0
    fi
    echo -e "${ERROR} trojan-rs 服务启动失败，最近日志如下：${PLAIN}"
    show_recent_logs
    return 1
}

restart_service() {
    if ! svc_restart; then
        echo -e "${ERROR} systemd 无法重启 trojan-rs。${PLAIN}"
        show_recent_logs
        return 1
    fi
    check_service_health
}

setup_service() {
    echo -e "${INFO} 配置后台服务守护进程...${PLAIN}"
    if has_systemd; then
        cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=trojan-rs service
Wants=network-online.target
After=network.target network-online.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_FILE} -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    else
        cat > "${SERVICE_FILE}" <<EOF
#!/sbin/openrc-run

name="trojan-rs"
description="trojan-rs proxy service"
command="${BIN_FILE}"
command_args="-c ${CONFIG_FILE}"
command_background=true
pidfile="/run/\${name}.pid"
output_log="/var/log/trojan-rs.log"
error_log="/var/log/trojan-rs.log"

depend() {
    need net
    after firewall
}
EOF
        chmod +x "${SERVICE_FILE}"
    fi

    svc_daemon_reload
    svc_enable
    restart_service
    echo -e "${SUCCESS} 服务已启动并设置为开机自启。${PLAIN}"
}

install_trojan() {
    check_root
    
    safe_clear
    print_banner
    echo -e " ${CYAN}=== 交互式全新安装 (手动 DNS 证书) ===${PLAIN}\n"

    install_deps
    require_runtime
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

    deploy_camouflage

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

    setup_service
    echo -e "${SUCCESS} 安装与部署已全部完成！${PLAIN}"
    echo -e "${WARN} 请使用菜单栏的日志查看功能确认服务是否正常运行。${PLAIN}"
}

manage_service() {
    while true; do
        safe_clear
        print_banner
        echo -e " ${CYAN}=== 服务管理 (Systemd) ===${PLAIN}\n"
        
        # 实时显示当前服务运行状态
        if svc_is_active 2>/dev/null; then
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
                if svc_start && check_service_health; then
                    echo -e "${SUCCESS} 服务已启动。${PLAIN}"
                fi
                sleep 1
                ;;
            2)
                echo -e "${INFO} 正在停止服务...${PLAIN}"
                if svc_stop; then
                    echo -e "${SUCCESS} 服务已停止。${PLAIN}"
                else
                    echo -e "${ERROR} 服务停止失败。${PLAIN}"
                fi
                sleep 1
                ;;
            3)
                echo -e "${INFO} 正在重启服务...${PLAIN}"
                if restart_service; then
                    echo -e "${SUCCESS} 服务已重启。${PLAIN}"
                fi
                sleep 1
                ;;
            4)
                echo -e "\n${INFO} 服务详细状态："
                echo -e "${BLUE}────────────────────────────────────────────────────────────────────────${PLAIN}"
                svc_status || true
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
    safe_clear
    print_banner
    echo -e " ${CYAN}=== 查看实时运行日志 ===${PLAIN}\n"
    echo -e "${INFO} 正在打开日志流，按 Ctrl+C 退出...${PLAIN}"
    svc_logs_f
}

change_config() {
    local backup_file
    safe_clear
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
    backup_file=$(mktemp)
    cp -p "${CONFIG_FILE}" "${backup_file}"
    case "${C_CHOICE}" in
        1)
            if ! command_exists vim; then
                echo -e "${ERROR} 未安装 vim。${PLAIN}"
                rm -f "${backup_file}"
                press_any_key
                return
            fi
            vim "${CONFIG_FILE}"
            ;;
        2)
            if ! command_exists nano; then
                echo -e "${ERROR} 未安装 nano。${PLAIN}"
                rm -f "${backup_file}"
                press_any_key
                return
            fi
            nano "${CONFIG_FILE}"
            ;;
        3) generate_config ;;
        0) rm -f "${backup_file}"; return ;;
        *) echo -e "${ERROR} 无效选项，取消操作。${PLAIN}"; rm -f "${backup_file}"; press_any_key; return ;;
    esac
    
    echo -ne "\n${WARN} 修改完毕，是否立即重启服务生效？[y/N]: "
    read -r RESTART_CONFIRM
    if [[ "$RESTART_CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${INFO} 正在重启服务...${PLAIN}"
        if restart_service; then
            echo -e "${SUCCESS} 服务已重启。${PLAIN}"
        else
            echo -e "${WARN} 新配置启动失败，正在恢复原配置。${PLAIN}"
            install -m 0600 "${backup_file}" "${CONFIG_FILE}"
            restart_service || true
        fi
    fi
    rm -f "${backup_file}"
    press_any_key
}

uninstall() {
    safe_clear
    print_banner
    echo -e " ${CYAN}=== 彻底卸载 trojan-rs ===${PLAIN}\n"
    echo -ne "${WARN} 警告：您确定要完全卸载 trojan-rs 吗？[y/N]: "
    read -r CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        svc_stop
        svc_disable
        rm -f "${SERVICE_FILE}"
        svc_daemon_reload

        # 提示用户清理 acme.sh 证书数据
        echo -ne "${WARN} 是否同时清理 acme.sh 中该域名的证书记录？[y/N]: "
        read -r CLEAN_ACME
        if [[ "$CLEAN_ACME" =~ ^[Yy]$ ]]; then
            echo -ne "${INFO} 请输入要清理的域名 (直接回车跳过): "
            read -r CLEAN_DOMAIN
            if [ -n "$CLEAN_DOMAIN" ]; then
                if [ -x "${ACME_SH}" ]; then
                    "${ACME_SH}" --remove -d "${CLEAN_DOMAIN}" --ecc 2>/dev/null || true
                    "${ACME_SH}" --remove -d "${CLEAN_DOMAIN}" 2>/dev/null || true
                    echo -e "${SUCCESS} 已清理 acme.sh 中 ${CLEAN_DOMAIN} 的证书数据。${PLAIN}"
                else
                    echo -e "${WARN} 未找到 acme.sh，跳过证书记录清理。${PLAIN}"
                fi
            fi
        fi

        rm -rf "${INSTALL_DIR}"
        echo -e "${SUCCESS} trojan-rs 已被彻底卸载！${PLAIN}"
    else
        echo -e "${INFO} 已取消卸载操作。${PLAIN}"
    fi
}

update_bin_only() {
    local backup_file
    local was_active=false
    safe_clear
    print_banner
    echo -e " ${CYAN}=== 仅更新核心二进制文件 ===${PLAIN}\n"
    if [ ! -f "${BIN_FILE}" ]; then
        echo -e "${ERROR} 未检测到已安装的 trojan-rs，请先执行全新安装。${PLAIN}"
        return
    fi
    echo -e "${INFO} 准备更新二进制文件...${PLAIN}"
    CURRENT_VER=$("${BIN_FILE}" --version 2>/dev/null || echo "未知版本")
    echo -e "${INFO} 当前版本: ${MAGENTA}${CURRENT_VER}${PLAIN}"
    
    backup_file=$(mktemp)
    cp -p "${BIN_FILE}" "${backup_file}"
    if svc_is_active; then
        was_active=true
        echo -e "${INFO} 正在停止服务...${PLAIN}"
        if ! svc_stop; then
            rm -f "${backup_file}"
            echo -e "${ERROR} 服务停止失败，取消更新。${PLAIN}"
            return 1
        fi
    fi

    if ! download_bin; then
        install -m 0755 "${backup_file}" "${BIN_FILE}"
        rm -f "${backup_file}"
        ${was_active} && svc_start || true
        echo -e "${ERROR} 更新失败，已保留旧版本。${PLAIN}"
        return 1
    fi

    if ${was_active}; then
        echo -e "${INFO} 正在启动新版本...${PLAIN}"
        if ! restart_service; then
            echo -e "${WARN} 新版本启动失败，正在回滚。${PLAIN}"
            install -m 0755 "${backup_file}" "${BIN_FILE}"
            restart_service || true
            rm -f "${backup_file}"
            return 1
        fi
    fi
    rm -f "${backup_file}"
    echo -e "${SUCCESS} 二进制文件更新完毕！${PLAIN}"
}

share_node() {
    local TLS_ADDR
    local PORT
    local WSPATH
    local TYPE
    local PASSWORD=""
    local UUID=""
    local domain_default=""
    local escaped_domain
    local escaped_path
    local escaped_password
    safe_clear
    print_banner
    echo -e " ${CYAN}=== 生成 Clash 节点配置 (JSON) ===${PLAIN}\n"
    if [ ! -f "${CONFIG_FILE}" ]; then
        echo -e "${ERROR} 未找到配置文件 ${CONFIG_FILE}，请先执行安装。${PLAIN}"
        return
    fi

    TLS_ADDR=$(sed -nE 's/^[[:space:]]*addr[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${CONFIG_FILE}")
    PORT=${TLS_ADDR##*:}
    WSPATH=$(sed -nE 's/^[[:space:]]*path[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${CONFIG_FILE}")
    if ! is_valid_port "${PORT}" || [ -z "${WSPATH}" ]; then
        echo -e "${ERROR} 无法从配置中读取有效的 TLS 端口或 WebSocket 路径。${PLAIN}"
        return
    fi

    if grep -qE '^[[:space:]]*\[vless\][[:space:]]*$' "${CONFIG_FILE}"; then
        TYPE="vless"
        UUID=$(sed -nE 's/.*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}).*/\1/p' "${CONFIG_FILE}")
        if [ -z "${UUID}" ]; then
            echo -e "${ERROR} 无法从配置中读取 VLESS UUID。${PLAIN}"
            return
        fi
    elif grep -qE '^[[:space:]]*\[trojan\][[:space:]]*$' "${CONFIG_FILE}"; then
        TYPE="trojan"
        PASSWORD=$(sed -nE 's/^[[:space:]]*password[[:space:]]*=[[:space:]]*"(.*)"[[:space:]]*$/\1/p' "${CONFIG_FILE}")
        if [ -z "${PASSWORD}" ]; then
            echo -e "${ERROR} 无法从配置中读取 Trojan 密码。${PLAIN}"
            return
        fi
    else
        echo -e "${ERROR} 无法识别配置中的协议类型。${PLAIN}"
        return
    fi

    if [ -f "${DOMAIN_FILE}" ]; then
        domain_default=$(tr -d '\r\n' <"${DOMAIN_FILE}")
    fi
    if [ -n "${domain_default}" ]; then
        echo -ne "${INFO} 请输入节点域名 [默认: ${domain_default}]: "
    else
        echo -ne "${INFO} 请输入节点绑定的域名 (如 example.com): "
    fi
    read -r NODE_DOMAIN
    NODE_DOMAIN=${NODE_DOMAIN:-${domain_default}}
    if ! is_valid_domain "${NODE_DOMAIN}"; then
        echo -e "${ERROR} 域名格式无效！${PLAIN}"
        return
    fi
    escaped_domain=$(json_escape "${NODE_DOMAIN}")
    escaped_path=$(json_escape "${WSPATH}")
    escaped_password=$(json_escape "${PASSWORD}")

    echo -e "\n${BLUE}========== Clash 节点配置 (JSON 格式) ==========${PLAIN}"
    if [ "$TYPE" == "vless" ]; then
        cat <<EOF
{
  "name": "trojan-rs-vless",
  "type": "vless",
  "server": "${escaped_domain}",
  "port": ${PORT},
  "uuid": "${UUID}",
  "network": "ws",
  "tls": true,
  "udp": true,
  "sni": "${escaped_domain}",
  "client-fingerprint": "chrome",
  "ws-opts": {
    "path": "${escaped_path}",
    "headers": {
      "Host": "${escaped_domain}"
    }
  }
}
EOF
    else
        cat <<EOF
{
  "name": "trojan-rs-trojan",
  "type": "trojan",
  "server": "${escaped_domain}",
  "port": ${PORT},
  "password": "${escaped_password}",
  "network": "ws",
  "tls": true,
  "sni": "${escaped_domain}",
  "client-fingerprint": "chrome",
  "udp": true,
  "ws-opts": {
    "path": "${escaped_path}",
    "headers": {
      "Host": "${escaped_domain}"
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
        echo -e " ${CYAN}1.${PLAIN} 交互式全新安装 (手动 DNS 证书)"
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
            1) install_trojan; press_any_key ;;
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

main() {
    check_root
    check_update "$@"
    menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
