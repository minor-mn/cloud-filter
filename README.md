# cloud-filter

[`rezmoss/cloud-provider-ip-addresses`](https://github.com/rezmoss/cloud-provider-ip-addresses) の日次更新データセットを参照し、**`ipset` + `iptables` / `ip6tables`** でクラウドプロバイダー・AIクローラー・Tor等のIPレンジを高速・無停止（アトミック）にDROPするシステムです。

---

## 特長

1. **`ipset` ハッシュテーブルによる $O(1)$ 高速フィルタリング & 無停止更新 (`swap`)**
   - 数千〜数十万件のCIDRでも `iptables` ルールを1行ずつ走査せず、`ipset` (`hash:net`) で高速に判定します。
   - 日次更新時は一時セット（`*_tmp`）へ一括投入後に `ipset swap` で入れ替えるため、**通信断やルール空白期間が一切発生しません**。
2. **対象プロバイダーの自由な選択（個別指定 / 全プロバイダー一括）**
   - `config.env` の `PROVIDERS` で 67種類のプロバイダー（`aws`, `azure`, `googlecloud`, `gptbot`, `claudebot`, `tor` 等）または `all_providers`（全統合リスト）を指定可能です。
3. **二重の誤遮断防止（ホワイトリスト）機構**
   - **CIDR演算による除外**: Ruby標準ライブラリ `ipaddr` をベースにしたビット演算により、`whitelist.txt` や `EXCLUDE_PROVIDERS`（自社利用のCloudflare等）のCIDRをDROPリストから数学的に分割・除外します。
   - **iptables/ipset 最優先 RETURN**: 専用チェイン `CLOUD_FILTER` の先頭でループバック・確立済み通信（`ESTABLISHED,RELATED`）・`cloud_allow_v4`/`v6` セットを最優先で `RETURN`（許可）します。
   - **SSHロックアウト自動防止**: 実行時の `SSH_CONNECTION` 接続元IPおよびデフォルトゲートウェイIPを自動検出してホワイトリストへ追加します。
4. **IPv4 / IPv6 両対応 & CDNミラー自動フォールバック**
   - jsDelivr CDN (`cdn.jsdelivr.net`) をプライマリとし、障害時は GitHub Raw (`raw.githubusercontent.com`) へ自動フォールバックします。

---

## ファイル構成

- `cloud-filter.sh` : メイン管理CLIスクリプト (`update`, `apply`, `dry-run`, `status`, `flush`, `list-providers`)
- `build_cidr_list.rb` : CIDR取得・統合・ホワイトリスト減算・`ipset restore` ファイル生成スクリプト（Ruby 標準ライブラリのみ・外部gem依存ゼロ）
- `config.env` (`config.env.example`) : 対象プロバイダー・除外設定ファイル
- `whitelist.txt` : 誤遮断防止用の固定ホワイトリスト（IPv4/IPv6 CIDR）
- `install_cron.sh` / `cron.d/cloud-filter.example` : 日次自動更新 & OS起動時復元用の cron インストーラ
- `test/test_build_cidr_list.rb` : 単体テスト (Minitest)

---

## セットアップ手順 (Linux: Ubuntu / Debian / RHEL / Rocky 等)

### 1. OSパッケージ（`ipset`, `iptables`、およびRubyビルド依存ライブラリ）のインストール

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y ipset iptables git build-essential libssl-dev libyaml-dev zlib1g-dev libffi-dev libreadline-dev

# RHEL / AlmaLinux / Rocky Linux
sudo dnf install -y ipset iptables git gcc make openssl-devel libyaml-devel zlib-devel libffi-devel readline-devel
```

### 2. `anyenv` + `rbenv` による Ruby 4系のインストール

OS標準パッケージの古いRubyではなく、`anyenv` → `rbenv` 経由で [`.ruby-version`](file:///Users/lightningdaisy/devel/private/cloud-filter/.ruby-version) に指定された Ruby（`4.0.6`）をインストールします。

```bash
# 1. anyenv のインストールと初期化
git clone https://github.com/anyenv/anyenv ~/.anyenv
export PATH="$HOME/.anyenv/bin:$PATH"
~/.anyenv/bin/anyenv install --init
echo 'export PATH="$HOME/.anyenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(anyenv init -)"' >> ~/.bashrc
eval "$(~/.anyenv/bin/anyenv init -)"

# 2. rbenv のインストール
anyenv install rbenv
exec $SHELL -l

# 3. .ruby-version (4.0.6) の Ruby をインストール
cd /path/to/cloud-filter
rbenv install "$(cat .ruby-version)"
rbenv rehash
ruby -v  # => ruby 4.0.6 ...
```

> **補足**: `cloud-filter.sh` と `install_cron.sh` は、`sudo` や `cron`（root）実行時でも実行元ユーザーの `~/.anyenv/envs/rbenv/shims`（または `/root/.anyenv/envs/rbenv/shims`）を自動検出して `PATH` と `RBENV_ROOT` に引き継ぐようになっているため、`sudo` 時にシステム標準の古いRubyへフォールバックしてしまう問題を防ぎます。

### 3. 設定ファイルとホワイトリストの編集

```bash
cp -n config.env.example config.env
chmod +x cloud-filter.sh build_cidr_list.rb install_cron.sh
```

- **`config.env`**:
  - `PROVIDERS`: ブロックしたいプロバイダー名をスペース区切りで指定（例: `"gptbot claudebot perplexitybot amazonbot tor"`、または全一括 `"all_providers"`）
  - `EXCLUDE_PROVIDERS`: ブロック対象から除外したいプロバイダー（例: `"cloudflare github googlebot"`）
- **`whitelist.txt`**:
  - 自身の管理拠点IPや監視サーバーIP、絶対に遮断したくないCIDRを1行ずつ記載します。

利用可能なプロバイダー一覧は以下のコマンドで確認できます：

```bash
./cloud-filter.sh list-providers
```

### 3. テスト生成 (`dry-run`) と初回適用 (`update`)

まずは `iptables` を変更せずにリスト生成のみをテストできます（root権限不要）：

```bash
./cloud-filter.sh dry-run
```

`./output/` ディレクトリに `drop_v4.txt`, `drop_v6.txt`, `allow_v4.txt`, `allow_v6.txt`, `ipset_restore.txt`, `summary.json` が生成されます。内容を確認したら、root権限で適用します：

```bash
sudo ./cloud-filter.sh update
```

### 4. 適用状態の確認 (`status`) と解除 (`flush`)

```bash
# 現在のipsetエントリ数・iptablesパケットカウンタの確認
sudo ./cloud-filter.sh status

# すべてのルールとipsetを即座に削除・解除する場合
sudo ./cloud-filter.sh flush
```

### 5. cron による日次自動更新の有効化

上流リポジトリは毎日 **02:00 UTC (11:00 JST)** に更新されます。以下のスクリプトを実行すると、`/etc/cron.d/cloud-filter` に日次更新ジョブおよびOS再起動時（`@reboot`）の自動復元ジョブが登録されます：

```bash
sudo ./install_cron.sh
```

更新時間を変更したい場合は環境変数 `CRON_SCHEDULE` を指定して実行できます：

```bash
sudo CRON_SCHEDULE="35 11 * * *" ./install_cron.sh
```

cron 設定を解除する場合：

```bash
sudo ./install_cron.sh --uninstall
```
