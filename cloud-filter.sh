#!/usr/bin/env bash
# ==============================================================================
# cloud-filter.sh
# rezmoss/cloud-provider-ip-addresses を参照し、ipset + iptables/ip6tables の
# DROPリストを日次更新・アトミック適用する管理スクリプト
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/config.env}"

# anyenv / rbenv の Ruby 4.x を最優先で解決する (sudo実行時のSUDO_USER環境も考慮)
SUDO_USER_HOME=""
if [[ -n "${SUDO_USER:-}" ]]; then
    SUDO_USER_HOME="$(eval echo "~${SUDO_USER}" 2>/dev/null || true)"
fi

for rbenv_root in \
    "${RBENV_ROOT:-}" \
    "${HOME}/.anyenv/envs/rbenv" \
    "${SUDO_USER_HOME:+"${SUDO_USER_HOME}/.anyenv/envs/rbenv"}" \
    "/opt/anyenv/envs/rbenv" \
    "${HOME}/.rbenv" \
    "${SUDO_USER_HOME:+"${SUDO_USER_HOME}/.rbenv"}"; do
    if [[ -n "${rbenv_root}" && -d "${rbenv_root}/shims" ]]; then
        export RBENV_ROOT="${rbenv_root}"
        export PATH="${rbenv_root}/shims:${rbenv_root}/bin:${PATH}"
        break
    fi
done
RUBY_BIN="${RUBY_BIN:-ruby}"

if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"
elif [[ -f "${SCRIPT_DIR}/config.env.example" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/config.env.example"
fi

# デフォルト設定値
PROVIDERS="${PROVIDERS:-gptbot claudebot perplexitybot amazonbot commoncrawl tor}"
EXCLUDE_PROVIDERS="${EXCLUDE_PROVIDERS:-cloudflare}"
ENABLE_IPV4="${ENABLE_IPV4:-true}"
ENABLE_IPV6="${ENABLE_IPV6:-true}"
WHITELIST_FILE="${WHITELIST_FILE:-${SCRIPT_DIR}/whitelist.txt}"
AUTO_WHITELIST_ENV="${AUTO_WHITELIST_ENV:-true}"
IPTABLES_CHAIN="${IPTABLES_CHAIN:-CLOUD_FILTER}"
IPTABLES_TARGET_CHAINS="${IPTABLES_TARGET_CHAINS:-INPUT}"
IPSET_DROP_V4="${IPSET_DROP_V4:-cloud_drop_v4}"
IPSET_DROP_V6="${IPSET_DROP_V6:-cloud_drop_v6}"
IPSET_ALLOW_V4="${IPSET_ALLOW_V4:-cloud_allow_v4}"
IPSET_ALLOW_V6="${IPSET_ALLOW_V6:-cloud_allow_v6}"
LOG_DROPS="${LOG_DROPS:-false}"
LOG_PREFIX="${LOG_PREFIX:-[CLOUD-FILTER-DROP] }"
PRIMARY_BASE_URL="${PRIMARY_BASE_URL:-https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main}"
FALLBACK_BASE_URL="${FALLBACK_BASE_URL:-https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/output}"

# 相対パスの解決
if [[ "${WHITELIST_FILE}" != /* ]]; then
    WHITELIST_FILE="${SCRIPT_DIR}/${WHITELIST_FILE#./}"
fi
if [[ "${OUTPUT_DIR}" != /* ]]; then
    OUTPUT_DIR="${SCRIPT_DIR}/${OUTPUT_DIR#./}"
fi

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log_error "この操作にはroot権限が必要です (sudo $0 $* を実行してください)"
        exit 1
    fi
}

require_commands() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing+=("${cmd}")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "必要なコマンドが見つかりません: ${missing[*]}"
        log_error "ファイアウォールパッケージ (Debian/Ubuntu): sudo apt update && sudo apt install -y ipset iptables"
        log_error "ファイアウォールパッケージ (RHEL/Alma/Rocky): sudo dnf install -y ipset iptables"
        log_error "Ruby は anyenv + rbenv で .ruby-version ($(cat "${SCRIPT_DIR}/.ruby-version" 2>/dev/null || echo '4.0.6')) をインストールしてください"
        exit 1
    fi
}

# 自動ロックアウト防止: 現在のSSH接続元IPやゲートウェイIPを検出
collect_auto_whitelist_args() {
    local extra_args=()
    if [[ "${AUTO_WHITELIST_ENV}" != "true" ]]; then
        return 0
    fi

    # 1. SSH_CONNECTION / SSH_CLIENT の接続元IPを保護
    local ssh_src=""
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        ssh_src="$(awk '{print $1}' <<<"${SSH_CONNECTION}")"
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        ssh_src="$(awk '{print $1}' <<<"${SSH_CLIENT}")"
    fi
    if [[ -n "${ssh_src}" ]]; then
        extra_args+=("--whitelist-cidr" "${ssh_src}")
    fi

    # 2. デフォルトゲートウェイやインターフェースのローカルIPを保護 (ip コマンドがある場合)
    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r gw; do
            [[ -n "${gw}" ]] && extra_args+=("--whitelist-cidr" "${gw}")
        done < <(ip route show default 2>/dev/null | awk '/default/ {print $3}' || true)

        while IFS= read -r gw6; do
            [[ -n "${gw6}" ]] && extra_args+=("--whitelist-cidr" "${gw6}")
        done < <(ip -6 route show default 2>/dev/null | awk '/default/ {print $3}' || true)
    fi

    if [[ ${#extra_args[@]} -gt 0 ]]; then
        printf '%s\n' "${extra_args[@]}"
    fi
}

build_lists() {
    require_commands "${RUBY_BIN}"

    local rb_args=(
        "${SCRIPT_DIR}/build_cidr_list.rb"
        "--providers" "${PROVIDERS}"
        "--exclude-providers" "${EXCLUDE_PROVIDERS}"
        "--output-dir" "${OUTPUT_DIR}"
        "--primary-base-url" "${PRIMARY_BASE_URL}"
        "--fallback-base-url" "${FALLBACK_BASE_URL}"
        "--ipset-drop-v4" "${IPSET_DROP_V4}"
        "--ipset-drop-v6" "${IPSET_DROP_V6}"
        "--ipset-allow-v4" "${IPSET_ALLOW_V4}"
        "--ipset-allow-v6" "${IPSET_ALLOW_V6}"
    )

    if [[ -f "${WHITELIST_FILE}" ]]; then
        rb_args+=("--whitelist-file" "${WHITELIST_FILE}")
    fi
    if [[ -f "${SCRIPT_DIR}/whitelist.local.txt" ]]; then
        rb_args+=("--whitelist-file" "${SCRIPT_DIR}/whitelist.local.txt")
    fi
    if [[ "${ENABLE_IPV4}" != "true" ]]; then
        rb_args+=("--no-ipv4")
    fi
    if [[ "${ENABLE_IPV6}" != "true" ]]; then
        rb_args+=("--no-ipv6")
    fi

    while IFS= read -r arg; do
        [[ -n "${arg}" ]] && rb_args+=("${arg}")
    done < <(collect_auto_whitelist_args)

    log_info "最新CIDRリストを取得・マージしています..."
    "${RUBY_BIN}" "${rb_args[@]}"
}

configure_firewall_chain() {
    local ipt_cmd="$1"
    local allow_set="$2"
    local drop_set="$3"

    # 専用チェインが存在しなければ作成、存在すれば中身を洗い替え
    if ! "${ipt_cmd}" -L "${IPTABLES_CHAIN}" -n >/dev/null 2>&1; then
        "${ipt_cmd}" -N "${IPTABLES_CHAIN}"
    else
        "${ipt_cmd}" -F "${IPTABLES_CHAIN}"
    fi

    # 1. ループバック通信は常に許可
    "${ipt_cmd}" -A "${IPTABLES_CHAIN}" -i lo -j RETURN

    # 2. 確立済みセッション (ESTABLISHED, RELATED) は許可 (自サーバー発の通信の戻りを遮断しない)
    "${ipt_cmd}" -A "${IPTABLES_CHAIN}" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    # 3. ホワイトリスト ipset にマッチする通信は最優先で RETURN (許可)
    "${ipt_cmd}" -A "${IPTABLES_CHAIN}" -m set --match-set "${allow_set}" src -j RETURN

    # 4. (任意) DROP前のレート制限付きログ出力
    if [[ "${LOG_DROPS}" == "true" ]]; then
        "${ipt_cmd}" -A "${IPTABLES_CHAIN}" -m set --match-set "${drop_set}" src \
            -m limit --limit 10/min --limit-burst 20 \
            -j LOG --log-prefix "${LOG_PREFIX}" --log-level 4
    fi

    # 5. DROP ipset にマッチする通信を DROP
    "${ipt_cmd}" -A "${IPTABLES_CHAIN}" -m set --match-set "${drop_set}" src -j DROP

    # 6. マッチしなかった通信は親チェインへ戻す
    "${ipt_cmd}" -A "${IPTABLES_CHAIN}" -j RETURN

    # 親チェイン (INPUT や DOCKER-USER など) の先頭にジャンプを登録 (未登録の場合のみ)
    for target_chain in ${IPTABLES_TARGET_CHAINS}; do
        if "${ipt_cmd}" -L "${target_chain}" -n >/dev/null 2>&1; then
            if ! "${ipt_cmd}" -C "${target_chain}" -j "${IPTABLES_CHAIN}" >/dev/null 2>&1; then
                "${ipt_cmd}" -I "${target_chain}" 1 -j "${IPTABLES_CHAIN}"
                log_info "${ipt_cmd}: ${target_chain} チェインの先頭に ${IPTABLES_CHAIN} を適用しました"
            fi
        else
            log_info "${ipt_cmd}: 親チェイン ${target_chain} が存在しないためスキップしました"
        fi
    done
}

apply_rules() {
    require_root
    require_commands ipset

    local restore_file="${OUTPUT_DIR}/ipset_restore.txt"
    if [[ ! -f "${restore_file}" ]]; then
        log_error "ipsetリストアファイル (${restore_file}) が見つかりません。先に update または dry-run を実行してください。"
        exit 1
    fi

    log_info "ipset をアトミック更新 (swap) しています..."
    ipset restore < "${restore_file}"

    if [[ "${ENABLE_IPV4}" == "true" ]]; then
        require_commands iptables
        log_info "iptables (IPv4) チェイン ${IPTABLES_CHAIN} を設定しています..."
        configure_firewall_chain "iptables" "${IPSET_ALLOW_V4}" "${IPSET_DROP_V4}"
    fi

    if [[ "${ENABLE_IPV6}" == "true" ]]; then
        require_commands ip6tables
        log_info "ip6tables (IPv6) チェイン ${IPTABLES_CHAIN} を設定しています..."
        configure_firewall_chain "ip6tables" "${IPSET_ALLOW_V6}" "${IPSET_DROP_V6}"
    fi

    log_info "すべての DROP ルールの適用が完了しました。"
}

remove_firewall_chain() {
    local ipt_cmd="$1"
    if ! command -v "${ipt_cmd}" >/dev/null 2>&1; then
        return 0
    fi

    for target_chain in ${IPTABLES_TARGET_CHAINS}; do
        while "${ipt_cmd}" -C "${target_chain}" -j "${IPTABLES_CHAIN}" >/dev/null 2>&1; do
            "${ipt_cmd}" -D "${target_chain}" -j "${IPTABLES_CHAIN}"
            log_info "${ipt_cmd}: ${target_chain} から ${IPTABLES_CHAIN} ジャンプを削除しました"
        done
    done

    if "${ipt_cmd}" -L "${IPTABLES_CHAIN}" -n >/dev/null 2>&1; then
        "${ipt_cmd}" -F "${IPTABLES_CHAIN}"
        "${ipt_cmd}" -X "${IPTABLES_CHAIN}"
        log_info "${ipt_cmd}: チェイン ${IPTABLES_CHAIN} を削除しました"
    fi
}

flush_rules() {
    require_root
    log_info "iptables / ip6tables の ${IPTABLES_CHAIN} ルールと ipset を解除しています..."

    remove_firewall_chain "iptables"
    remove_firewall_chain "ip6tables"

    if command -v ipset >/dev/null 2>&1; then
        for set_name in "${IPSET_DROP_V4}" "${IPSET_DROP_V6}" "${IPSET_ALLOW_V4}" "${IPSET_ALLOW_V6}"; do
            if ipset list -n "${set_name}" >/dev/null 2>&1; then
                ipset destroy "${set_name}"
                log_info "ipset: セット ${set_name} を削除しました"
            fi
        done
    fi

    log_info "解除が完了しました。"
}

show_status() {
    echo "======================================================================"
    echo " cloud-filter Status"
    echo "======================================================================"
    echo "Config file        : ${CONFIG_FILE}"
    echo "Target providers   : ${PROVIDERS}"
    echo "Excluded providers : ${EXCLUDE_PROVIDERS:-<none>}"
    echo "Output directory   : ${OUTPUT_DIR}"
    if [[ -f "${OUTPUT_DIR}/summary.json" ]]; then
        echo "--- Last Built List Summary (${OUTPUT_DIR}/summary.json) ---"
        cat "${OUTPUT_DIR}/summary.json"
    fi
    echo ""

    if command -v ipset >/dev/null 2>&1 && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        echo "--- ipset Sets ---"
        for set_name in "${IPSET_ALLOW_V4}" "${IPSET_DROP_V4}" "${IPSET_ALLOW_V6}" "${IPSET_DROP_V6}"; do
            if ipset list -t "${set_name}" >/dev/null 2>&1; then
                ipset list -t "${set_name}" | grep -E "^(Name:|Type:|Number of entries:|Size in memory:)"
                echo ""
            fi
        done
    fi

    if command -v iptables >/dev/null 2>&1 && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        echo "--- iptables (${IPTABLES_CHAIN}) ---"
        iptables -L "${IPTABLES_CHAIN}" -n -v --line-numbers 2>/dev/null || echo "Chain ${IPTABLES_CHAIN} not active."
        echo ""
    fi

    if command -v ip6tables >/dev/null 2>&1 && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        echo "--- ip6tables (${IPTABLES_CHAIN}) ---"
        ip6tables -L "${IPTABLES_CHAIN}" -n -v --line-numbers 2>/dev/null || echo "Chain ${IPTABLES_CHAIN} not active."
        echo ""
    fi
}

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  update          最新IPリストを取得・マージし、ipset + iptables/ip6tables にアトミック適用します (要root)
  apply           生成済みの output/ipset_restore.txt を ipset + iptables/ip6tables に適用します (要root)
  dry-run         IPリストの取得・マージ・ipsetファイル生成のみ行います (root不要・テスト用)
  status          現在の生成リスト統計および ipset / iptables 適用状態を表示します
  flush           iptables/ip6tables の専用チェインと ipset をすべて削除・解除します (要root)
  list-providers  利用可能な全プロバイダー一覧を表示します
EOF
}

main() {
    local cmd="${1:-}"
    case "${cmd}" in
        update)
            build_lists
            apply_rules
            ;;
        apply)
            apply_rules
            ;;
        dry-run|build)
            build_lists
            log_info "dry-run 完了: 生成ファイルは ${OUTPUT_DIR} に出力されました。"
            ;;
        status)
            show_status
            ;;
        flush|remove|stop)
            flush_rules
            ;;
        list-providers)
            "${RUBY_BIN}" "${SCRIPT_DIR}/build_cidr_list.rb" --list-providers
            ;;
        -h|--help|help|"")
            usage
            ;;
        *)
            log_error "不明なコマンドです: ${cmd}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
