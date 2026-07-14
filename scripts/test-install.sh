#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=install.sh
source "${SCRIPT_DIR}/install.sh"

TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "${TEST_ROOT}"' EXIT

INSTALL_DIR="${TEST_ROOT}/install"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
export CERT_DIR="${INSTALL_DIR}/cert"
BIN_FILE="${INSTALL_DIR}/trojan-rs"
DOMAIN_FILE="${INSTALL_DIR}/domain"
mkdir -p "${INSTALL_DIR}"

assert_fails() {
    if "$@"; then
        echo "expected command to fail: $*" >&2
        return 1
    fi
}

is_valid_port 443
assert_fails is_valid_port 0
assert_fails is_valid_port 65536
assert_fails is_valid_port invalid
is_valid_domain example.com
is_valid_domain sg.example.com
assert_fails is_valid_domain invalid_domain
is_valid_ws_path /ws
assert_fails is_valid_ws_path 'ws'
assert_fails is_valid_ws_path '/ws?token=value'

ACME_LOG="${TEST_ROOT}/acme.log"
ACME_SH="${TEST_ROOT}/acme.sh"
cat >"${ACME_SH}" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${ACME_LOG}"
case "$1" in
    --issue) exit 1 ;;
    --renew) exit 0 ;;
    *) exit 1 ;;
esac
EOF
chmod +x "${ACME_SH}"
export ACME_LOG
issue_manual_dns_certificate example.com true >/dev/null <<'EOF'

EOF
grep -q -- '--issue -d example.com --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please -k ec-256 --force' "${ACME_LOG}"
grep -q -- '--renew -d example.com --yes-I-know-dns-manual-mode-enough-go-ahead-please' "${ACME_LOG}"
ACME_SH="/root/.acme.sh/acme.sh"

for _ in {1..20}; do
    password=$(generate_password)
    [[ "${password}" =~ ^[0-9a-f]{32}$ ]]
done

uuid=$(generate_uuid)
[[ "${uuid}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-8[0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]

if [ -z "${MSYSTEM:-}" ]; then
    mkdir -p "${CERT_DIR}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -subj '/CN=example.com' -addext 'subjectAltName=DNS:example.com' \
        -keyout "${CERT_DIR}/private.key" -out "${CERT_DIR}/fullchain.cer" >/dev/null 2>&1
    certificate_is_usable example.com
    assert_fails certificate_is_usable other.example.com
fi

printf '%s\n' 'example.com' >"${DOMAIN_FILE}"
generate_config >/dev/null <<'EOF'
1
443
/ws

EOF
grep -Eq 'addr = "(0\.0\.0\.0:443|\[::\]:443)"' "${CONFIG_FILE}"
grep -Eq 'password = "[0-9a-f]{32}"' "${CONFIG_FILE}"
grep -Eq 'dashboard_password = "[0-9a-f]{32}"' "${CONFIG_FILE}"
grep -q 'path = "/ws"' "${CONFIG_FILE}"

share_node >"${TEST_ROOT}/trojan-node.json" <<'EOF'

EOF
grep -q '"tls": true' "${TEST_ROOT}/trojan-node.json"
grep -q '"server": "example.com"' "${TEST_ROOT}/trojan-node.json"

generate_config >/dev/null <<'EOF'
2
8443
/vless
EOF
grep -Eq 'addr = "(0\.0\.0\.0:8443|\[::\]:8443)"' "${CONFIG_FILE}"
grep -Eq 'users = \["[0-9a-f-]{36}"\]' "${CONFIG_FILE}"
grep -Eq 'dashboard_password = "[0-9a-f]{32}"' "${CONFIG_FILE}"
grep -q 'path = "/vless"' "${CONFIG_FILE}"

deploy_camouflage >/dev/null
test -s "${INSTALL_DIR}/camouflage.html"
grep -qi '<html' "${INSTALL_DIR}/camouflage.html"

mkdir -p "${TEST_ROOT}/package"
cat >"${TEST_ROOT}/package/trojan-rs-server" <<'EOF'
#!/bin/sh
echo 'trojan-rs-test 1.0.0'
EOF
chmod +x "${TEST_ROOT}/package/trojan-rs-server"
tar -czf "${TEST_ROOT}/release.tar.gz" -C "${TEST_ROOT}/package" trojan-rs-server
FIXTURE_ARCHIVE="${TEST_ROOT}/release.tar.gz"
CAMOUFLAGE_FIXTURE="${TEST_ROOT}/camouflage-fixture.html"
CURL_LOG="${TEST_ROOT}/curl.log"
CURL_FAIL_PATTERN=""
printf '%s\n' '<html><body>updated camouflage page</body></html>' >"${CAMOUFLAGE_FIXTURE}"

curl() {
    local output=""
    local url=""
    while (($#)); do
        case "$1" in
            --output|-o)
                output=$2
                shift 2
                ;;
            http://*|https://*)
                url=$1
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    printf '%s\n' "${url}" >>"${CURL_LOG}"
    if [ -n "${CURL_FAIL_PATTERN}" ] && [[ "${url}" == *"${CURL_FAIL_PATTERN}"* ]]; then
        return 22
    fi
    case "${url}" in
        */config/camouflage.html) cp "${CAMOUFLAGE_FIXTURE}" "${output}" ;;
        *) cp "${FIXTURE_ARCHIVE}" "${output}" ;;
    esac
}

uname() {
    printf '%s\n' x86_64
}

download_bin >/dev/null
test -x "${BIN_FILE}"
[[ "$("${BIN_FILE}" --version)" == 'trojan-rs-test 1.0.0' ]]
grep -q 'trojan-rs-server-linux-amd64.tar.gz' "${CURL_LOG}"

rm -f "${BIN_FILE}"
: >"${CURL_LOG}"
CURL_FAIL_PATTERN="trojan-rs-server-linux-amd64.tar.gz"
download_bin >/dev/null
test -x "${BIN_FILE}"
[[ "$("${BIN_FILE}" --version)" == 'trojan-rs-test 1.0.0' ]]
grep -q 'trojan-rs-server-linux-amd64.tar.gz' "${CURL_LOG}"
grep -q 'trojan-rs-server-linux-musl-amd64.tar.gz' "${CURL_LOG}"

svc_is_active() {
    return 1
}
update_camouflage_page >/dev/null
grep -q 'updated camouflage page' "${INSTALL_DIR}/camouflage.html"
grep -q '/config/camouflage.html' "${CURL_LOG}"

cp "${INSTALL_DIR}/camouflage.html" "${TEST_ROOT}/expected-camouflage.html"
printf '%s\n' 'not an html page' >"${CAMOUFLAGE_FIXTURE}"
assert_fails update_camouflage_page >/dev/null
cmp -s "${TEST_ROOT}/expected-camouflage.html" "${INSTALL_DIR}/camouflage.html"

printf '%s\n' '<html><body>restarted camouflage page</body></html>' >"${CAMOUFLAGE_FIXTURE}"
RESTART_CALLS=0
svc_is_active() {
    return 0
}
restart_service() {
    RESTART_CALLS=$((RESTART_CALLS + 1))
    return 1
}
assert_fails update_camouflage_page >/dev/null
[[ ${RESTART_CALLS} -eq 2 ]]
cmp -s "${TEST_ROOT}/expected-camouflage.html" "${INSTALL_DIR}/camouflage.html"

restart_service() {
    RESTART_CALLS=$((RESTART_CALLS + 1))
    return 0
}
update_camouflage_page >/dev/null
[[ ${RESTART_CALLS} -eq 3 ]]
grep -q 'restarted camouflage page' "${INSTALL_DIR}/camouflage.html"

update_camouflage_page >/dev/null
[[ ${RESTART_CALLS} -eq 3 ]]

echo "install script tests passed"
