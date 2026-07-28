# Firefox IP Protection SOCKS5 / HTTP 代理池

本项目将 Firefox IP Protection 的多国家 TCP 出口转换为 SOCKS5 和 HTTP 代理。默认同步 Remote Settings 中的可用国家，为每个节点分配稳定地址，并提供跨国家的综合随机入口。

综合入口先等概率选择一个国家，再从该国选择节点；节点较多的国家不会获得更高权重。上游的 `REC` 推荐记录使用独立模式，不参与默认随机池。

> 仅使用你本人有权使用的 Firefox Account、网络和 IP Protection 服务，并遵守适用条款与法律。

## 工作原理

Firefox 桌面端当前的大致链路如下：

```text
Firefox Account / OAuth
    -> Guardian（vpn.mozilla.org）
    -> GET /api/v1/fpn/token
    -> 短时 ProxyPass JWT
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

上游目前优先使用 `CONNECT`。完整的 MASQUE/HTTP3/QUIC/UDP 数据面尚未实现；只有 MASQUE 的记录会被明确标记为不支持，不会被错误地当成 CONNECT 节点。

## 主要功能

- 从 Firefox Remote Settings 的 `vpn-serverlist` 同步多国家节点。
- 对 Firefox 版本门控、`filter_expression`、锁定、隔离和协议字段进行保守解析。
- 为每个可用节点启动独立 SOCKS5 和 HTTP 监听器。
- 为所有已启用国家提供国家等权的随机 SOCKS5/HTTP 综合入口。
- 持久化稳定端口映射，避免上游列表重排导致已有地址漂移。
- 支持本地监听认证，并拒绝无认证的非回环开放代理。
- 支持 ProxyPass JWT 检查、Guardian 配额查询和有界 token 刷新。
- 使用 ETag、`If-None-Match`、`304` 和最后已知有效缓存适配上游热更新。
- 导出不含认证的地址、可直接使用的 URL 和结构化节点元数据。

主要组件：

| 组件 | 作用 |
| --- | --- |
| `ipp_pool.py` | 同步节点、检查 token、启动独立监听器和综合入口 |
| `refresh_tokens.py` | 用已保存的 FxA session 换取 OAuth token 和短时 ProxyPass JWT |
| `tools/firefox-credential-export.html` | 从桌面 Firefox 配置中离线导出最小续期凭据 |
| `import_credentials.py` | 在 VPS 上导入凭据并执行续期验收 |
| `login_and_bootstrap.py` | 备用的命令行登录引导工具 |
| `run_service.sh` | 使用环境变量启动服务 |
| `start_pool.sh` | 重启并查看 systemd 服务状态的辅助脚本 |
| `data/vpn-serverlist.json` | Remote Settings 最后已知有效节点缓存 |
| `data/port-map.json` | 节点身份到本地端口的稳定映射 |

## 环境要求

- Python 3.10 或更高版本。
- Linux 为推荐运行环境；核心 Python 代码也可在具备相应网络能力的其他环境中运行。
- 具有 IP Protection 使用资格的 Firefox Account。
- 能访问 Firefox Accounts、Guardian、Remote Settings 和记录中的上游节点。

## 安装与公开节点同步

```bash
git clone https://github.com/multi-zhangyang/firefox-ip-protection-pool.git
cd firefox-ip-protection-pool

python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# 只同步公开节点列表，不需要读取 token
.venv/bin/python ipp_pool.py sync
```

同步日志只应包含节点数量、国家统计和缓存状态，不应包含账号凭据。上游节点会随 Firefox 版本和服务端配置变化，以当前同步结果为准。

`requirements.txt` 只安装核心代理池和无浏览器 token 刷新所需的 `requests` 与 `PyFxA`，不会安装 Playwright 或下载浏览器。

## 在桌面 Firefox 中准备凭据

登录和验证码在用户自己的 Windows 或 macOS 电脑上完成。VPS 只接收登录完成后的最小续期凭据，不需要安装 Firefox、Playwright 或图形桌面。

账号密码和验证码只输入 Firefox 显示的 Mozilla 登录界面；本项目的导出页面和 VPS 都不会询问这些内容。

建议在桌面 Firefox 中为这台 VPS 新建一个独立配置：

1. 在 Firefox 地址栏打开 `about:profiles`，新建并启动一个配置。
2. 在 Firefox 的账户菜单或“设置 → 同步”中登录具有 IP Protection 资格的 Firefox Account。这里需要登录 Firefox 本身，而不只是登录 `accounts.firefox.com` 网页。
3. 在正常的浏览器页面中输入密码并完成邮箱验证码、CAPTCHA、TOTP 或安全密钥验证。
4. 打开 Firefox 的 IP Protection 面板并完成首次启用，保持联网直到账户和设备注册完成。
5. 再次打开 `about:profiles`，找到这个配置的“根目录”。

如果 Firefox 中没有 IP Protection 面板，先确认所用 Firefox 版本、账号和当前服务范围具备使用资格；VPS 端不能替未获资格的账号启用服务。

在桌面电脑上通过 GitHub 的“Code → Download ZIP”下载并解压本仓库，双击本地的 [`tools/firefox-credential-export.html`](tools/firefox-credential-export.html) 并选择使用 Firefox 打开。不要直接使用 GitHub 文件预览页；导出器必须作为本地文件运行。该页面不连接网络；选择上述根目录中的 `signedInUser.json` 后，它会检查账户验证和 Firefox 设备注册状态，并生成 `fxa-renewal-credentials.json`。导出的 JSON 只包含：

```text
email
uid
session_token
```

Windows 和 macOS 使用同一个导出页面。Windows 的 `about:profiles` 会在资源管理器中打开根目录，macOS 会在 Finder 中显示根目录。

不要直接复制整个 `signedInUser.json`，其中还可能包含与本项目无关的 OAuth 缓存和账户资料。导出的最小凭据包同样等同于 Firefox 登录会话，不要将它发送到聊天、邮件、issue 或公共网盘。关闭 Firefox 不会撤销会话；在该 Firefox 配置中退出账户、从账号设备列表撤销会话或执行“退出所有设备”，会使 VPS 上的自动续期停止。

## 将凭据导入 VPS

在 VPS 上安装核心程序。服务用户不需要登录 shell，运行时目录由它单独拥有：

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

先在远端用户的主目录建立只允许该用户访问的传输目录：

```bash
ssh VPS_USER@VPS_HOST 'install -d -m 700 ~/.ipp-import'
```

Windows PowerShell：

```powershell
scp "$HOME\Downloads\fxa-renewal-credentials.json" `
  VPS_USER@VPS_HOST:.ipp-import/fxa-renewal-credentials.json
```

Windows 10/11 如果没有 `ssh` 或 `scp`，请先在“可选功能”中安装 OpenSSH Client，或使用 WinSCP/SFTP 将文件上传到同一个 `.ipp-import` 目录。

macOS 终端：

```bash
scp ~/Downloads/fxa-renewal-credentials.json \
  VPS_USER@VPS_HOST:.ipp-import/fxa-renewal-credentials.json
```

在 VPS 上将文件交给服务用户，然后导入：

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

导入命令会把 session 原子写入 `tokens/renewal_credentials.json`，权限设为 `0600`，并立即强制请求一个新的 ProxyPass。新凭据验收成功前，旧 ProxyPass 不会被用于建立新连接。验收成功后检查状态：

```bash
sudo -u ipp-pool -H \
  /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/ipp_pool.py token-status
```

有效状态包含：

```text
automatic_renewal_ready: true
proxy_pass.valid: true
refresh_state.result: success
```

如果续期验收失败，导入器会保留 `/opt/firefox-ip-protection-pool/tokens/.credential-import.json` 以便重试。处理网络、账号资格或限流问题后重新运行同一导入命令；不再使用时手动删除该文件。

确认导入成功后，删除 Windows 或 macOS 下载目录中的 `fxa-renewal-credentials.json`。

## 自动续期

服务每 30 秒检查一次 ProxyPass，并在到期前 120 秒更新。刷新时会使用 FxA session 获取临时 OAuth token，再从 Guardian 获取新的 ProxyPass；临时 OAuth token 不会写入磁盘，用完后会向 FxA 尝试销毁。

网络错误和服务端限流会按响应信息退避，尚未过期的 ProxyPass 在此期间仍可继续使用。刷新状态保存在 `tokens/refresh_state.json`，服务重启后仍会遵守冷却时间。systemd 负责开机启动和进程恢复，不需要额外配置 cron。

FxA session 被撤销后不能继续续期。出现 `reauth_required` 时，请在桌面 Firefox 中重新登录和验证，重新导出凭据并在 VPS 上再次导入。

## 默认启动：所有国家与综合随机入口

最简单的启动方式是：

```bash
.venv/bin/python ipp_pool.py run
```

默认行为：

- 绑定 `127.0.0.1`。
- 启动所有可用的非 `REC` 国家，不应用 `--countries` 和 `--limit`。
- 为每个节点分配独立 SOCKS5 和 HTTP 端口。
- 在 `127.0.0.1:1090` 启动 SOCKS5 综合随机入口。
- 在 `127.0.0.1:8080` 启动 HTTP 综合随机入口。
- 综合入口按国家等权随机选择，国家内再选择节点。

默认端口布局：

| 类型 | 默认地址 |
| --- | --- |
| 独立 SOCKS5 节点 | `127.0.0.1:21000+` |
| 独立 HTTP 节点 | `127.0.0.1:31000+` |
| 所有启用国家的 SOCKS5 综合随机入口 | `127.0.0.1:1090` |
| 所有启用国家的 HTTP 综合随机入口 | `127.0.0.1:8080` |

使用示例：

```bash
# 独立节点；socks5h 会让域名解析也经过代理
curl -x socks5h://127.0.0.1:21000 https://ipinfo.io/json
curl -x http://127.0.0.1:31000 https://ipinfo.io/json

# 所有已启用国家的等权随机综合入口
curl -x socks5h://127.0.0.1:1090 https://ipinfo.io/json
curl -x http://127.0.0.1:8080 https://ipinfo.io/json
```

HTTP 转发器只接受 absolute-form 的明文 `http://` 请求；访问 HTTPS 必须使用 `CONNECT`。请求体上限为 8 MiB，并拒绝 chunked 编码、冲突或非法的 `Content-Length` 以及危险的 hop-by-hop 头。

## 通用国家筛选

仅在确实需要缩小运行集合时使用 ISO 国家代码列表：

```bash
.venv/bin/python ipp_pool.py run \
  --countries COUNTRY_CODE_A,COUNTRY_CODE_B \
  --rotate-mode random
```

使用 `--countries` 后，综合入口只从指定国家中选择。`--limit` 用于限制启动的节点总数。

如需关闭某个综合入口：

```bash
.venv/bin/python ipp_pool.py run --rotator off
.venv/bin/python ipp_pool.py run --http-rotator off
```

## 独立的 REC 推荐模式

`REC` 是上游推荐/Anycast 记录，不代表普通国家，也不属于默认多国家综合随机池。仅在明确需要上游推荐记录时单独启动：

```bash
.venv/bin/python ipp_pool.py run --recommended
```

不要把 `--recommended` 与 `--countries` 混用。推荐模式与默认的“所有非 `REC` 国家等权随机”模式语义不同。

## 监听认证与公网部署

程序默认只绑定回环地址。绑定非回环地址时，核心程序要求完整的监听用户名和密码；没有认证时会拒绝启动，除非用户显式选择不安全的开放代理参数。生产环境不要使用开放代理参数。

认证文件格式：

```text
USER=ipp
PASS=替换为随机长密码
```

保存为 `tokens/proxy_listen_auth.txt` 并限制权限：

```bash
chmod 600 tokens/proxy_listen_auth.txt
```

核心程序也支持 `IPP_LISTEN_USER` 和 `IPP_LISTEN_PASS`。`run_service.sh` 不会把密码复制到命令行参数；Python 进程会直接读取环境变量或认证文件。长期 systemd 部署优先使用归属于服务用户的 `0600` 认证文件，不要把密码写进可公开读取的环境示例文件。配置认证后，使用客户端的独立认证参数，避免把密码嵌入代理 URL 或 shell 历史：

```bash
curl --proxy-user 'USER:PASSWORD' -x socks5h://127.0.0.1:1090 https://ipinfo.io/ip
```

安全检查覆盖所有实际监听地址，而不只检查 `--bind`。因此，即使独立节点绑定回环地址，只要 `--rotator` 或 `--http-rotator` 指向非回环 IP、通配地址或 DNS 名称，也必须配置完整认证；非法端口、裸 IPv6 authority 和 URL 形式的监听参数会在读取 token 或访问网络前被拒绝。IPv6 回环默认综合入口会规范化为 `[::1]:1090` 和 `[::1]:8080`。

公网部署还应限制防火墙来源、只开放必要端口并定期轮换密码。`--advertise-host` 只影响导出地址，不改变监听安全策略。

## 通用服务脚本

`run_service.sh` 读取以下环境变量并启动代理池。默认监听回环地址并启用所有可用的非 `REC` 国家。

可用环境变量：

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `IPP_PYTHON` | 项目 `.venv/bin/python`，不存在时使用 `python3` | Python 可执行文件 |
| `IPP_BIND` | `127.0.0.1` | 本地监听地址 |
| `IPP_ADVERTISE_HOST` | 与 `IPP_BIND` 相同 | 导出文件中的主机名或地址 |
| `IPP_COUNTRIES` | 空 | 可选的 ISO 国家代码列表；空表示所有非 `REC` 国家 |
| `IPP_LIMIT` | 空 | 可选的全局节点上限；空表示不限制 |
| `IPP_ROTATOR` | `<IPP_BIND>:1090` | SOCKS5 综合入口，使用 `off` 可关闭 |
| `IPP_HTTP_ROTATOR` | `<IPP_BIND>:8080` | HTTP 综合入口，使用 `off` 可关闭 |
| `IPP_ROTATE_MODE` | `random` | 综合入口模式，可选 `random` 或 `rr` |
| `IPP_FIREFOX_VERSION` | `155.0a1` | Remote Settings 版本门控使用的 Firefox 版本；需要复现其他版本时覆盖 |
| `IPP_CLIENT_COUNTRY` | 空 | 当前客户端所在国家的 ISO 代码，仅用于执行上游 `env.country` 过滤；程序不会自动猜测 |
| `IPP_REFRESH_BEFORE_START` | `1` | 启动前是否尽力刷新一次 token |

示例：

```bash
IPP_BIND=127.0.0.1 IPP_ROTATE_MODE=random ./run_service.sh
```

如果把 `IPP_BIND` 改成非回环地址，必须先提供认证文件或完整的 `IPP_LISTEN_USER`/`IPP_LISTEN_PASS`。脚本不会自动探测公网地址，也不会静默开放代理。

## systemd 部署

完成凭据导入和续期验收后，安装项目提供的环境配置与 unit：

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

`examples/ipp-pool.env.example` 只存放非敏感运行参数。修改安装后的副本并重启服务即可生效：

```bash
sudoedit /etc/firefox-ip-protection-pool/ipp-pool.env
sudo systemctl restart ipp-pool.service
```

不要把密码、session token、ProxyPass JWT 或 OAuth token 写入该环境文件。公网监听的认证信息应放在 `/opt/firefox-ip-protection-pool/tokens/proxy_listen_auth.txt`，并设置为 `0600 ipp-pool:ipp-pool`。

服务日志写入 journald：

```bash
sudo journalctl -u ipp-pool.service -n 100 --no-pager
sudo journalctl -u ipp-pool.service -f
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/ipp_pool.py token-status
```

如果状态显示 `reauth_required`，请回到桌面 Firefox 重新登录并导出，在 VPS 上重新运行导入命令，然后重启服务：

```bash
sudo systemctl restart ipp-pool.service
```

`start_pool.sh` 是 systemd 辅助脚本，可用 `IPP_SERVICE_NAME` 指定不同的 unit 名称。它会重启服务，因此不应用作无副作用的配置检查。

## 稳定端口映射与导出

节点端口由稳定节点身份决定，而不是由 Remote Settings 返回顺序决定。上游插入、删除或重排记录时，已有节点的端口不会随意改变；映射保存在 `data/port-map.json`。

常用导出文件：

```text
export/socks5.txt           # 不含认证的独立 SOCKS5 地址
export/http.txt             # 不含认证的独立 HTTP 地址
export/socks5_urls.txt      # 可能含认证，配置认证时为 0600
export/http_urls.txt        # 可能含认证，配置认证时为 0600
export/public_endpoints.txt # 综合入口，配置认证时为 0600
export/pool.json            # 运行节点、国家与端口元数据
export/exits.json           # 同步得到的节点详情
```

综合入口启动后会再次刷新导出，以记录实际监听地址。不要公开带认证的导出文件。

## 命令速查

```bash
.venv/bin/python ipp_pool.py sync
.venv/bin/python ipp_pool.py how-to-token
.venv/bin/python ipp_pool.py token-status
.venv/bin/python ipp_pool.py usage
.venv/bin/python ipp_pool.py token-refresh
.venv/bin/python ipp_pool.py probe --country COUNTRY_CODE
.venv/bin/python ipp_pool.py run
.venv/bin/python ipp_pool.py run --countries COUNTRY_CODE_A,COUNTRY_CODE_B
.venv/bin/python ipp_pool.py run --recommended
```

`usage` 使用 Guardian 的 `HEAD /api/v1/fpn/token` 查询配额。`probe` 用于检查指定出口，响应大小限制为 64 KiB。

## 备用登录方式

`login_and_bootstrap.py` 保留为兼容性工具。桌面 Firefox 导出是 Windows/macOS 用户和无图形 VPS 的标准安装方式；命令行引导不适合作为无图形 VPS 的首次登录方案。

## Firefox 兼容性

节点筛选会处理 Firefox 版本条件、客户端国家条件、`locked`、`quarantined` 和协议字段。`IPP_CLIENT_COUNTRY` 表示 VPS 所在国家，仅用于执行 Remote Settings 条件，不是出口国家选择器。详细兼容记录见 [`docs/firefox-upstream-compatibility.md`](docs/firefox-upstream-compatibility.md)。

## 安全注意事项

如果发现项目漏洞，请按 [`SECURITY.md`](SECURITY.md) 私下报告；不要在公开 issue 中张贴漏洞细节或真实凭据。

- 只操作属于自己且有权使用的账号、token 和出口。
- 把 `fxa-renewal-credentials.json` 当作登录凭据，导入成功后删除传输副本。
- 把 FxA session token、ProxyPass JWT、Cookie、HAR、浏览器 storage 和监听密码视为高价值凭据。
- 不要提交 `tokens/`、运行时 `data/`、认证导出、日志、截图或浏览器配置文件。
- 非回环监听必须启用认证，并配合防火墙限制来源。
- Guardian 可能返回配额耗尽或限流；程序会尊重服务端响应，不能绕过配额。
- 当前实现只提供 TCP CONNECT 兼容性，不等同于完整 VPN，也不支持 UDP/MASQUE 数据面。
- JWT 当前未做签名密码学验证；不应把本地结构校验理解为对 token 来源的完整信任证明。
- 节点列表目前依赖 HTTPS、schema、ETag 和 last-known-good；尚未实现 Firefox Remote Settings 使用的 Kinto canonical records、P-384 内容签名与 Mozilla PKI 证书链验证。metadata 中出现签名字段不等于本项目已经完成签名验证。

## 开发与测试

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m py_compile ipp_pool.py refresh_tokens.py refresh_state.py renewal_credentials.py login_and_bootstrap.py import_credentials.py
bash -n run_service.sh start_pool.sh
git diff --check
```

GitHub Actions 在 Python 3.10 和 3.12 上运行测试与语法检查。

## 许可证与声明

本项目采用 MIT 许可证。它是独立的开源工具，与 Mozilla、Firefox 或 Fastly 没有官方隶属关系。
