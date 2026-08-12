# Firefox IP Protection SOCKS5 / HTTP 代理池

将 Firefox IP Protection（Mozilla FPN）的多国家 TCP 出口转换为本地 SOCKS5 和 HTTP 代理。默认同步 Remote Settings 中的可用国家，为每个节点分配稳定地址，并提供跨国家的综合随机入口。

综合入口先等概率选择一个国家，再从该国选择节点；节点较多的国家不会获得更高权重。上游的 `REC` 推荐记录使用独立模式，不参与默认随机池。

> 仅使用你本人有权使用的 Firefox Account、网络和 IP Protection 服务，并遵守适用条款与法律。

## 快速开始

从拿到一个具有 IP Protection 资格的 Firefox Account 到代理可用，共 4 步：

```bash
# 1. 安装
git clone https://github.com/multi-zhangyang/firefox-ip-protection-pool.git
cd firefox-ip-protection-pool
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# 2. 在桌面 Firefox 中导出登录凭据（见下方"桌面 Firefox 准备凭据"）
#    -> 得到 fxa-renewal-credentials.json

# 3. 导入 VPS（把文件放到 .ipp-import 后执行）
sudo -u ipp-pool -H .venv/bin/python import_credentials.py \
  tokens/.credential-import.json --delete-source

# 4. 启动并验证
.venv/bin/python ipp_pool.py run
curl -x socks5h://127.0.0.1:1090 https://ipinfo.io/json
```

如果不想用桌面 Firefox（或者无法访问桌面），也可以在本机直接跑 `login_and_bootstrap.py` 命令行引导完成认证，见[备用登录方式](#备用登录方式)。

## 工作原理

Firefox 桌面端当前的链路：

```text
Firefox Account / OAuth
    -> Guardian（vpn.mozilla.org）
    -> GET /api/v1/fpn/token
    -> 短时 ProxyPass JWT（每 10 分钟过期）
    -> TLS 连接 Remote Settings 提供的出口节点
    -> HTTPS CONNECT + Proxy-Authorization: Bearer <JWT>
    -> 目标网站
```

本项目在这条链路前增加本地监听器：

```text
应用程序
    -> 独立国家 SOCKS5/HTTP 入口，或所有启用国家的等权随机综合入口
    -> 本项目建立 TLS + CONNECT 上游隧道
    -> Firefox IP Protection 出口
    -> 目标网站
```

上游目前优先使用 `CONNECT`。MASQUE/HTTP3/QUIC/UDP 数据面尚未实现；MASQUE-only 记录会被明确标记为不支持，不会被当成 CONNECT 节点。

## 主要功能

- 从 Firefox Remote Settings 的 `vpn-serverlist` 同步多国家节点。
- 对 Firefox 版本门控、`filter_expression`、锁定、隔离和协议字段做保守解析。
- 为每个可用节点启动独立 SOCKS5 和 HTTP 监听器。
- 为所有已启用国家提供国家等权随机的 SOCKS5/HTTP 综合入口。
- 持久化稳定端口映射，避免上游列表重排导致已有地址漂移。
- 支持本地监听认证，并拒绝无认证的非回环开放代理。
- 自动续期 ProxyPass JWT，支持 Guardian 配额查询与有界退避重试。
- 使用 ETag、`If-None-Match`、`304` 和 last-known-good 适配上游热更新。
- 导出不含认证的地址、可直接使用的 URL 和结构化节点元数据。

## 目录结构

| 文件/目录 | 作用 |
| --- | --- |
| `ipp_pool.py` | 主程序：同步节点、检查 token、启动监听器和综合入口 |
| `refresh_tokens.py` | 用 FxA session 换取 OAuth token 和短时 ProxyPass JWT |
| `import_credentials.py` | 在 VPS 上导入桌面导出的凭据并执行续期验收 |
| `login_and_bootstrap.py` | 备用的命令行登录引导（无需桌面 Firefox） |
| `refresh_state.py` | 续期状态持久化与跨进程锁 |
| `tools/firefox-credential-export.html` | 从桌面 Firefox 离线导出最小续期凭据 |
| `run_service.sh` / `start_pool.sh` | systemd 启动辅助脚本 |
| `examples/` | systemd unit 与 env 模板 |
| `docs/` | 上游兼容性记录（含 2026-08-12 认证链路观察） |

## 环境要求

- Python 3.10+，Linux 推荐；核心代码也可在其他具有相应网络能力的平台运行。
- 具有 IP Protection 使用资格的 Firefox Account。
- 能访问 Firefox Accounts、Guardian、Remote Settings 和记录中的上游节点。

核心依赖只有 `requests` 与 `PyFxA`，不需要安装 Playwright 或浏览器（仅备用登录方式需要）。

## 桌面 Firefox 准备凭据

登录和验证码在用户自己的 Windows / macOS 电脑上完成。VPS 只接收登录完成后的最小续期凭据，不需要安装 Firefox、Playwright 或图形桌面。

建议为这台 VPS 新建一个独立 Firefox 配置：

1. 在 Firefox 地址栏打开 `about:profiles`，新建并启动一个配置。
2. 在账户菜单或"设置 → 同步"中登录具有 IP Protection 资格的 Firefox Account（登录 Firefox 本身，不只是网页）。
3. 输入密码并完成邮箱验证码、CAPTCHA、TOTP 或安全密钥验证。
4. 打开 Firefox 的 IP Protection 面板完成首次启用，保持联网直到账户和设备注册完成。
5. 回到 `about:profiles`，记下该配置的"根目录"路径。

> 如果 Firefox 中没有 IP Protection 面板，先确认 Firefox 版本、账号和服务范围具备使用资格；VPS 端不能替未获资格的账号启用服务。

然后导出最小凭据包：

1. 下载本仓库 ZIP 并解压（或直接克隆到桌面机器）。
2. 用 Firefox 双击打开 `tools/firefox-credential-export.html`（必须是本地文件，不要用 GitHub 预览页；该页面不联网）。
3. 选择上述配置根目录中的 `signedInUser.json`，页面会检查账户验证和设备注册状态，生成 `fxa-renewal-credentials.json`。

导出的 JSON 只包含 `email`、`uid`、`session_token` 三个字段。**不要**直接复制整个 `signedInUser.json`（它还包含无关的 OAuth 缓存）。凭据包等同于登录会话：不要发送到聊天、邮件、issue 或公共网盘。

## 将凭据导入 VPS

创建服务用户并安装：

```bash
getent group ipp-pool >/dev/null 2>&1 || sudo groupadd --system ipp-pool
id -u ipp-pool >/dev/null 2>&1 || \
  sudo useradd --system --gid ipp-pool --create-home \
  --home-dir /var/lib/ipp-pool --shell /usr/sbin/nologin ipp-pool

sudo git clone https://github.com/multi-zhangyang/firefox-ip-protection-pool.git \
  /opt/firefox-ip-protection-pool
sudo python3 -m venv /opt/firefox-ip-protection-pool/.venv
sudo /opt/firefox-ip-protection-pool/.venv/bin/python -m pip install \
  -r /opt/firefox-ip-protection-pool/requirements.txt

sudo install -d -o ipp-pool -g ipp-pool -m 0700 \
  /opt/firefox-ip-protection-pool/tokens \
  /opt/firefox-ip-protection-pool/data \
  /opt/firefox-ip-protection-pool/logs \
  /opt/firefox-ip-protection-pool/export
```

在远端用户主目录建立仅自己可访问的传输目录并上传凭据：

```bash
ssh VPS_USER@VPS_HOST 'install -d -m 700 ~/.ipp-import'
```

Windows PowerShell：

```powershell
scp "$HOME\Downloads\fxa-renewal-credentials.json" VPS_USER@VPS_HOST:.ipp-import/
```

macOS / Linux：

```bash
scp ~/Downloads/fxa-renewal-credentials.json VPS_USER@VPS_HOST:.ipp-import/
```

在 VPS 上交给服务用户并导入：

```bash
sudo install -o ipp-pool -g ipp-pool -m 0600 \
  "$HOME/.ipp-import/fxa-renewal-credentials.json" \
  /opt/firefox-ip-protection-pool/tokens/.credential-import.json
rm -f "$HOME/.ipp-import/fxa-renewal-credentials.json"

sudo -u ipp-pool -H \
  /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/import_credentials.py \
  /opt/firefox-ip-protection-pool/tokens/.credential-import.json \
  --delete-source
```

导入命令会把 session 原子写入 `tokens/renewal_credentials.json`（0600），立即强制请求新的 ProxyPass。验收失败会保留 `.credential-import.json` 供重试。

检查状态：

```bash
sudo -u ipp-pool -H \
  /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/ipp_pool.py token-status
```

有效状态：

```text
automatic_renewal_ready: true
proxy_pass.valid: true
refresh_state.result: success
```

确认成功后删除 Windows / macOS 下载目录中的 `fxa-renewal-credentials.json`。

## 启动与使用

最简单的方式：

```bash
.venv/bin/python ipp_pool.py run
```

默认行为：

- 绑定 `127.0.0.1`，启动所有可用的非 `REC` 国家。
- 每个节点分配独立 SOCKS5/HTTP 端口；在 `127.0.0.1:1090`（SOCKS5）和 `127.0.0.1:8080`（HTTP）启动综合随机入口。
- 综合入口按国家等权随机选择，国家内再选择节点。

默认端口布局：

| 类型 | 默认地址 |
| --- | --- |
| 独立 SOCKS5 节点 | `127.0.0.1:21000+` |
| 独立 HTTP 节点 | `127.0.0.1:31000+` |
| SOCKS5 综合随机入口 | `127.0.0.1:1090` |
| HTTP 综合随机入口 | `127.0.0.1:8080` |

使用示例：

```bash
# 独立节点；socks5h 让域名解析也经过代理
curl -x socks5h://127.0.0.1:21000 https://ipinfo.io/json
curl -x http://127.0.0.1:31000 https://ipinfo.io/json

# 所有已启用国家的等权随机综合入口
curl -x socks5h://127.0.0.1:1090 https://ipinfo.io/json
curl -x http://127.0.0.1:8080 https://ipinfo.io/json
```

HTTP 转发器只接受 absolute-form 的明文 `http://` 请求；HTTPS 必须使用 `CONNECT`。请求体上限 8 MiB，拒绝 chunked 编码、冲突/非法 `Content-Length` 和危险的 hop-by-hop 头。

### 国家筛选与 REC 模式

```bash
# 只运行指定国家
.venv/bin/python ipp_pool.py run \
  --countries COUNTRY_CODE_A,COUNTRY_CODE_B \
  --rotate-mode random

# 关闭综合入口
.venv/bin/python ipp_pool.py run --rotator off
.venv/bin/python ipp_pool.py run --http-rotator off

# 独立的 REC 推荐模式（不混入普通国家池）
.venv/bin/python ipp_pool.py run --recommended
```

`REC` 是上游推荐/Anycast 记录，不属于普通国家，不要与 `--countries` 混用。

### 监听认证与公网部署

默认只绑定回环地址。绑定非回环地址时**必须**配置完整监听认证，否则拒绝启动（除非显式使用 `--allow-open-proxy`，生产环境不要使用）。

认证文件 `tokens/proxy_listen_auth.txt`，格式 `USER=ipp` / `PASS=<随机长密码>`，权限 0600：

```bash
chmod 600 tokens/proxy_listen_auth.txt
```

客户端使用：

```bash
curl --proxy-user 'USER:PASSWORD' -x socks5h://127.0.0.1:1090 https://ipinfo.io/ip
```

安全策略会检查所有实际监听地址：只要任一综合入口使用非回环 IP、通配地址或 DNS 名称，就必须配置认证。公网部署还应限制防火墙来源、只开放必要端口、定期轮换密码。

### systemd 部署

```bash
sudo install -d -m 0755 /etc/firefox-ip-protection-pool
sudo install -m 0644 /opt/firefox-ip-protection-pool/examples/ipp-pool.env.example \
  /etc/firefox-ip-protection-pool/ipp-pool.env
sudo install -m 0644 /opt/firefox-ip-protection-pool/examples/ipp-pool.service \
  /etc/systemd/system/ipp-pool.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipp-pool.service
sudo systemctl --no-pager --full status ipp-pool.service
```

不要往 `ipp-pool.env` 写密码或 token；监听认证放在 `tokens/proxy_listen_auth.txt`。

日志与状态：

```bash
sudo journalctl -u ipp-pool.service -f
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/ipp_pool.py token-status
```

### 环境变量（run_service.sh）

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `IPP_PYTHON` | 项目 `.venv/bin/python`，否则 `python3` | Python 可执行文件 |
| `IPP_BIND` | `127.0.0.1` | 本地监听地址 |
| `IPP_ADVERTISE_HOST` | 同 `IPP_BIND` | 导出文件中的主机名/地址 |
| `IPP_COUNTRIES` | 空 | 可选的 ISO 国家列表；空 = 所有非 `REC` 国家 |
| `IPP_LIMIT` | 空 | 可选的全局节点上限 |
| `IPP_ROTATOR` | `<IPP_BIND>:1090` | SOCKS5 综合入口，`off` 关闭 |
| `IPP_HTTP_ROTATOR` | `<IPP_BIND>:8080` | HTTP 综合入口，`off` 关闭 |
| `IPP_ROTATE_MODE` | `random` | 综合入口模式：`random` 或 `rr` |
| `IPP_FIREFOX_VERSION` | `155.0a1` | Remote Settings 版本门控用的 Firefox 版本 |
| `IPP_CLIENT_COUNTRY` | 空 | 客户端所在国家 ISO 码，仅用于上游 `env.country` 过滤 |
| `IPP_REFRESH_BEFORE_START` | `1` | 启动前是否尽力刷新一次 token |

### 导出文件

```text
export/socks5.txt           # 不含认证的独立 SOCKS5 地址
export/http.txt             # 不含认证的独立 HTTP 地址
export/socks5_urls.txt      # 可能含认证，配置认证时为 0600
export/http_urls.txt        # 可能含认证，配置认证时为 0600
export/public_endpoints.txt # 综合入口，配置认证时为 0600
export/pool.json            # 运行节点、国家与端口元数据
export/exits.json           # 同步得到的节点详情
```

不要公开带认证的导出文件。

## 备用登录方式

不想用（或无法使用）桌面 Firefox 时，可在 VPS 上直接命令行登录。需要额外依赖：

```bash
.venv/bin/python -m pip install -r requirements-bootstrap.txt
.venv/bin/playwright install firefox
sudo apt install -y xvfb   # 仅 headed 模式需要
```

Fastly 会向自动化登录下发图形验证码，本地 OCR 无法稳定识别；推荐配置视觉模型 API 自动答题（OpenAI 兼容网关，消息含 `image_url` 数据）：

```bash
export ANTHROPIC_BASE_URL=https://your-gateway.example.com
export ANTHROPIC_AUTH_TOKEN=your-token
export ANTHROPIC_MODEL=your-vision-model
```

启动：

```bash
# headless（默认）
.venv/bin/python login_and_bootstrap.py --email YOUR_EMAIL

# headed + xvfb，Fastly 挑战通过率更高
FXA_HEADLESS=0 xvfb-run -a .venv/bin/python login_and_bootstrap.py --email YOUR_EMAIL
```

脚本依次处理 Fastly challenge（POW/CAPTCHA）、密码、邮箱 6 位验证码，完成后自动保存续期凭据并获取初始 ProxyPass。之后：

```bash
.venv/bin/python refresh_tokens.py --force
.venv/bin/python ipp_pool.py token-status
```

已知上游行为与复刻要点见 [`docs/firefox-upstream-compatibility.md`](docs/firefox-upstream-compatibility.md) 的"认证链路观察"一节。

## 故障排查

### `reauth_required` / 401（最常见）

FxA session 会被 Mozilla 服务端周期性撤销（实测约 10 天一次）。此时自动续期暂停，服务可能反复重启失败：

```text
[!] token not ready: automatic renewal is paused (reauth_required)
```

恢复方法（二选一）：

1. **重新导入桌面凭据**：在桌面 Firefox 重新登录 → 重新导出 → 在 VPS 上重跑导入命令 → `systemctl restart ipp-pool`。
2. **命令行重新认证**：跑 `login_and_bootstrap.py` 走完整登录（需要邮箱验证码）。

监控 `tokens/refresh_state.json` 的 `result` 字段，连续出现 `reauth_required` 时提前安排重新认证。

### Fastly CAPTCHA 循环

`login_and_bootstrap.py` 卡在"CAPTCHA characters"反复出题：说明 OCR 答错或未配置视觉 API。配置 `ANTHROPIC_*` 环境变量后重跑；仍不行就用 headed + xvfb 模式。

### API 返回 406

FxA `account/*` API 对浏览器/自动化 UA（Playwright、Firefox UA）的请求返回 406，且 `account/login` 必须携带浏览器会话 cookie。新版代码已自动处理（requests 默认 UA + context cookie），旧版本或手写脚本需注意。

### 服务启动失败但 token 正常

```bash
sudo journalctl -u ipp-pool.service -n 100 --no-pager
.venv/bin/python ipp_pool.py token-status
.venv/bin/python ipp_pool.py probe --country COUNTRY_CODE
```

检查监听端口占用（默认 1090/8080/21000+/31000+）与上游连通性。

## 命令速查

```bash
.venv/bin/python ipp_pool.py sync            # 只同步公开节点列表
.venv/bin/python ipp_pool.py how-to-token    # token 获取指南
.venv/bin/python ipp_pool.py token-status    # 检查 token/续期状态
.venv/bin/python ipp_pool.py usage           # 查询 Guardian 配额
.venv/bin/python ipp_pool.py token-refresh   # 手动刷新
.venv/bin/python ipp_pool.py probe --country COUNTRY_CODE  # 探测指定出口
.venv/bin/python ipp_pool.py run             # 启动代理池
```

## 自动续期机制

服务每 30 秒检查一次 ProxyPass，到期前 120 秒更新。刷新时用 FxA session 获取临时 OAuth token，再从 Guardian 获取新 ProxyPass；临时 token 不落盘，用完后尝试销毁。

网络错误和服务端限流按响应退避，尚未过期的 ProxyPass 在退避期间继续可用。刷新状态保存在 `tokens/refresh_state.json`，服务重启后仍遵守冷却时间。systemd 负责开机启动与进程恢复，无需 cron。

## 安全注意事项

漏洞请按 [`SECURITY.md`](SECURITY.md) 私下报告，不要在公开 issue 张贴漏洞细节或真实凭据。

- 只操作属于自己且有权使用的账号、token 和出口。
- 把 `fxa-renewal-credentials.json` 当作登录凭据，导入成功后删除传输副本。
- 把 FxA session token、ProxyPass JWT、Cookie、HAR、浏览器 storage 和监听密码视为高价值凭据。
- 不要提交 `tokens/`、运行时 `data/`、认证导出、日志、截图或浏览器配置文件。
- 非回环监听必须启用认证，并配合防火墙限制来源。
- Guardian 可能返回配额耗尽或限流；程序尊重服务端响应，不能绕过配额。
- 当前实现只提供 TCP CONNECT 兼容性，不等同于完整 VPN，不支持 UDP/MASQUE 数据面。
- JWT 未做签名密码学验证；本地结构校验不等于对 token 来源的完整信任证明。
- 节点列表依赖 HTTPS、schema、ETag 与 last-known-good；尚未实现 Kinto canonical records、P-384 内容签名与 Mozilla PKI 证书链验证。

## 开发与测试

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m py_compile ipp_pool.py refresh_tokens.py refresh_state.py renewal_credentials.py login_and_bootstrap.py import_credentials.py
bash -n run_service.sh start_pool.sh
git diff --check
```

GitHub Actions 在 Python 3.10 和 3.12 上运行测试与语法检查。

## 许可证

MIT。本项目是独立开源工具，与 Mozilla、Firefox 或 Fastly 没有官方隶属关系。
