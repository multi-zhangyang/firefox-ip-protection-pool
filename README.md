# Firefox IP Protection SOCKS5 / HTTP 代理池

本项目将 Firefox 内置 IP Protection 提供的多国家 TCP 出口转换为本地或受保护的 SOCKS5、HTTP 代理。它不会绕过账号资格、服务配额或 Mozilla 的安全机制，也不是 Mozilla VPN 的 WireGuard 配置生成器。

项目对所有国家使用相同的同步、筛选、端口映射、协议回退、健康处理和导出逻辑，不包含任何国家特化：

- 默认启动 Remote Settings 中所有可用的非 `REC` 国家，不设置国家白名单或节点数量上限。
- 每个已启动国家都有独立的 SOCKS5 和 HTTP 节点地址；同一国家有多个可用节点时，它们也会保留各自的稳定地址。
- 默认提供一个覆盖所有已启用国家的 SOCKS5 综合随机入口和一个 HTTP 综合随机入口。
- 综合入口先等概率选择国家，再在该国的可用节点中选择后端。因此节点较多的国家不会获得更高的国家权重。
- `REC` 表示上游推荐/Anycast 记录，只能通过显式 `--recommended` 模式使用，不会混入默认综合随机池。

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
| `login_and_bootstrap.py` | 可选的浏览器登录与首次凭据引导工具 |
| `run_service.sh` | 使用通用环境变量启动服务，不包含本机路径或国家白名单 |
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

## 只登录一次，长期自动续期

长期运行不应依赖手工复制 ProxyPass JWT。ProxyPass 寿命很短，单独把它写入 `tokens/proxy_pass.jwt` 只适合临时调试，重启服务也不会把它变成可长期续期的凭据。

推荐流程是：使用 Playwright Firefox 交互登录一次，在本地保存 FxA session，强制验证该 session 确实能换取新 ProxyPass，然后交给常驻进程自动续期。不需要 cron，也不需要定期手工粘贴 JWT。

人与程序的分工如下：

| 谁负责 | 只需做什么 |
| --- | --- |
| 人 | 首次安装引导依赖，运行一次登录命令，在终端输入密码、邮箱验证码以及可能出现的 CAPTCHA，然后执行一次 `--force` 验收 |
| 程序 | 保存可续期的 FxA session；持续检查 ProxyPass；在到期前自动换取临时 OAuth token 和新 ProxyPass；销毁临时 OAuth token；按服务端指示退避并持久化状态 |
| 人无需做 | 不需要打开 Firefox 开发者工具抓 token，不需要复制 ProxyPass，不需要配置 cron，也不需要每隔几分钟或几小时更新凭据 |

在已有的项目虚拟环境中安装可选引导依赖和 Firefox：

```bash
.venv/bin/python -m pip install -r requirements-bootstrap.txt
.venv/bin/python -m playwright install firefox
```

使用你本人有权使用的 Firefox Account 执行一次交互登录：

```bash
.venv/bin/python login_and_bootstrap.py --email you@example.com
```

这条命令就是推荐的“获取凭据”方式：引导工具完成 Firefox Account 登录并从成功响应中取得续期所需的 session，不要求用户从浏览器 storage、Cookie、HAR 或网络面板手工抄取任何值。密码会由 `getpass` 直接从终端读取，Mozilla 发送的 6 位邮箱验证码也会在需要时交互读取。两者都不需要放入命令行、环境文件、shell 历史或 systemd unit。引导工具会使用短期 OAuth access token 完成 Guardian 请求，随后尽力销毁它，不会把它作为长期凭据保存。

自动续期必需的持久文件只有：

| 文件 | 用途 |
| --- | --- |
| `tokens/session_token.txt` | FxA session token，高价值凭据 |
| `tokens/account_meta.json` | 续期所需的 `email` 和 `uid` |

`tokens/proxy_pass.jwt` 是可再生成的短期运行缓存。以上文件都应是 `0600`，并由实际运行服务的同一用户所有。不要另行保存密码、邮箱验证码或短期 OAuth access token。

登录完成后，必须强制走一次完整续期链路，不要只看当前 ProxyPass 还没过期：

```bash
.venv/bin/python refresh_tokens.py --force
.venv/bin/python ipp_pool.py token-status
```

只有 `--force` 成功后才能说明本地 session 确实可用于自动续期。`token-status` 中应看到 `automatic_renewal_ready: true`、`proxy_pass.valid: true`，并且 `refresh_state.result` 为 `success` 或后续的 `fresh`。`tokens/refresh_state.json` 只保存最近成功时间、失败分类、到期时间和下次允许重试时间，不保存任何 token 或账号标识。

常驻进程会在 ProxyPass 到期前 120 秒进入主动轮换，默认每 30 秒检查一次。刷新期间其他请求仍可使用尚未真正到期的 last-good token；并发请求和独立进程只共享一轮刷新。网络和 5xx 失败采用有界重试及持久化指数退避。Guardian token 端点的 429 表示代理配额限制，会优先遵守 `Retry-After`，其次遵守配额重置时间并暂停新隧道；FxA OAuth 端点的 429 只表示暂时无法签发 OAuth token，会退避但不会误停仍有效的 last-good。OAuth 重新认证或账号资格被拒时会暂停新隧道，而不是高频请求或绕过限制；交互重新登录发布新凭据时会等待旧刷新结束，并在同一跨进程锁内清除旧会话留下的暂停状态。

`run_service.sh` 会在每次启动前通过同一续期状态机检查一次：健康且充足的缓存不会额外联网，已到期的限流或认证暂停则必须真实联网重验。运行中的后台 worker 才是持续续期的主机制。只要服务常驻，就不需要另装 cron，也不需要定期执行 `token-refresh` 或手工替换 JWT。

如果 FxA session 被 Mozilla 撤销、账号安全设置变更或服务端要求重新验证，程序不会也不应绕过重新登录。此时重新执行上述交互引导和 `--force` 验收即可。

临时手工 JWT 方式的只读说明仍可通过下列命令查看，但不要把它当成长期部署方案：

```bash
.venv/bin/python ipp_pool.py how-to-token
```

Firefox 使用的 OAuth scope 为：

```text
profile
https://identity.mozilla.com/apps/vpn
```

ProxyPass JWT 生命周期较短。不要把 JWT、FxA access token、session token、Cookie、HAR、浏览器 storage、监听密码或带认证的完整代理 URL 写入日志、issue、聊天记录或公共仓库。敏感文件和带认证导出应保持 `0600` 权限。

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

所有列出的国家仍使用相同逻辑，综合入口仍在这些已启用国家之间等权随机。`--limit` 是全局节点数量上限，可能使部分候选节点不启动；默认不设置它，以便所有可用国家平等参与。

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

`run_service.sh` 使用脚本自身目录，不包含固定安装路径。它默认绑定回环地址、启动全部可用非 `REC` 国家、不设置数量上限，并显式使用国家等权随机综合入口。启动前刷新的脱敏输出会保留在当前终端或 systemd journal 中，不会被静默丢弃。

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

## systemd 长期部署：从一次登录到自动续期

下面是一条从代码安装到常驻服务的 Linux 部署流程。示例假定系统已经安装 `sudo`、`git`、`python3` 和提供 `venv` 模块的 Python 包；不同发行版的基础包名称不同，请先用系统包管理器安装它们。示例使用专用的非 root 用户 `ipp-pool`、固定代码路径 `/opt/firefox-ip-protection-pool` 和带持久家目录的服务账号。

```bash
# 1. 创建专用服务用户，并以 root 拥有只读代码
getent group ipp-pool >/dev/null 2>&1 || sudo groupadd --system ipp-pool
id -u ipp-pool >/dev/null 2>&1 || \
  sudo useradd --system --gid ipp-pool --create-home \
  --home-dir /var/lib/ipp-pool --shell /usr/sbin/nologin ipp-pool
sudo git clone https://github.com/multi-zhangyang/firefox-ip-protection-pool.git \
  /opt/firefox-ip-protection-pool
sudo python3 -m venv /opt/firefox-ip-protection-pool/.venv
sudo /opt/firefox-ip-protection-pool/.venv/bin/python -m pip install \
  -r /opt/firefox-ip-protection-pool/requirements-bootstrap.txt

# 2. 只把运行时目录交给服务用户
sudo install -d -o ipp-pool -g ipp-pool -m 0700 \
  /opt/firefox-ip-protection-pool/tokens \
  /opt/firefox-ip-protection-pool/data \
  /opt/firefox-ip-protection-pool/logs \
  /opt/firefox-ip-protection-pool/export

# 3. 为实际执行引导的服务用户安装 Playwright Firefox
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  -m playwright install firefox

# 4. 交互登录一次；密码和邮箱码均由终端读取
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/login_and_bootstrap.py --email you@example.com

# 5. 强制验收 session 到新 ProxyPass 的完整续期链路
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/refresh_tokens.py --force
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/ipp_pool.py token-status

# 6. 安装非敏感环境配置和 systemd unit
sudo install -d -m 0755 /etc/firefox-ip-protection-pool
sudo install -m 0644 /opt/firefox-ip-protection-pool/examples/ipp-pool.env.example \
  /etc/firefox-ip-protection-pool/ipp-pool.env
sudo install -m 0644 /opt/firefox-ip-protection-pool/examples/ipp-pool.service \
  /etc/systemd/system/ipp-pool.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipp-pool.service
sudo systemctl --no-pager --full status ipp-pool.service
```

如果系统缺少 Firefox 所需共享库，先审核 Playwright 将安装的系统包，再以管理员身份执行：

```bash
sudo /opt/firefox-ip-protection-pool/.venv/bin/python -m playwright install-deps firefox
```

`examples/ipp-pool.env.example` 只存放非敏感运行参数。修改安装后的副本并重启服务即可生效：

```bash
sudoedit /etc/firefox-ip-protection-pool/ipp-pool.env
sudo systemctl restart ipp-pool.service
```

不要把密码、session token、ProxyPass JWT 或 OAuth token 写入该环境文件。公网监听的认证信息应放在 `/opt/firefox-ip-protection-pool/tokens/proxy_listen_auth.txt`，并设置为 `0600 ipp-pool:ipp-pool`。

常驻进程会自动刷新接近过期的 ProxyPass，因此不需要额外安装 cron。服务每次启动前的刷新输出与运行期错误都进入 journald：

```bash
sudo journalctl -u ipp-pool.service -n 100 --no-pager
sudo journalctl -u ipp-pool.service -f
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/ipp_pool.py token-status
```

unit 以 30 秒间隔对失败启动做慢速无限恢复，适合开机时短暂断网；它不会绕过长期的认证或账号资格失败。如果 journal 提示 session 失效，以 `ipp-pool` 用户重新执行第 4、5 步，然后重启服务。重新登录发布凭据时会与运行中的刷新 helper 互斥，因此不会让旧会话最后返回的 401 覆盖新会话的成功状态；为让主进程立即重新载入所有配置，验收后仍建议重启 unit。

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

`usage` 使用 Guardian 的 `HEAD /api/v1/fpn/token` 查询配额；没有 FxA access token 时会明确失败。`probe` 只应用于你有权使用的出口，输出中也不应包含凭据。探测请求现在完全在 Python 进程内建立，不会再把 ProxyPass JWT 放进 `curl` 或其他子进程的命令行；响应大小限制为 64 KiB。

## 浏览器引导的隐私边界

`login_and_bootstrap.py` 只用于可选的首次引导，不是启动代理池的必要步骤。Firefox Accounts 可能要求 CAPTCHA、邮箱验证码或其他交互验证。

遇到 CAPTCHA 且没有配置视觉 API 时，引导工具会把图片以 `0600` 临时文件写到 `tokens/`，在终端显示路径并让用户输入图中文字，输入后立即删除；这仍然只是首次登录交互，不是后续手工续期。如果用户主动同时配置 `OPENAI_BASE_URL`/`OPENAI_API_KEY`（或兼容的 `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`），工具会把 CAPTCHA 图片发送给该第三方视觉 API 识别；使用前应检查配置与第三方隐私政策。当前引导默认不保存页面截图或浏览器 storage，并会清理旧版本遗留的重复 OAuth 缓存和敏感浏览器产物。

## Firefox 上游适配说明

- 在客户端执行受限且保守的 `filter_expression` 子集；无法识别的表达式会拒绝匹配。
- Remote Settings 的 `env.country` 指当前客户端位置，不是希望选择的出口国家。程序不会通过外部定位服务自动推断它；若实际位于受上游条件约束的地区，应明确设置 `IPP_CLIENT_COUNTRY`。该值只执行 Mozilla 的记录过滤，不会给任何出口国家加权或做特化。
- 使用 Firefox 版本比较选择适用记录；截至 2026-07-28，默认跟随 Firefox 主干 `155.0a1`，可通过 `--firefox-version` 或 `IPP_FIREFOX_VERSION` 覆盖。
- 把 `REC` 与普通国家记录分离。
- 缺少协议端口时按兼容规则使用 `443`，存在 CONNECT 时优先选择 CONNECT。
- 默认跳过 `locked`、`quarantined` 和不支持协议的节点；`--include-locked` 只用于诊断。
- Remote Settings 缓存支持 ETag、304、节点快照差异和最后已知有效回退。
- Guardian token/usage/status/activate 请求对齐当前 Firefox 的 JSON content type 与 no-cache；有限配额严格校验 limit、remaining 和带时区的 reset，仍保留有界重试与 `Retry-After`。
- 后台自动续期只请求 `GET /api/v1/fpn/token`，不会在错误后擅自调用 `activate`；只有人工执行的首次引导在 entitlement 状态明确返回 404 时才尝试一次显式激活。
- ProxyPass JWT 会检查结构、算法字段、必需 claims、时间、issuer 和 audience；当前尚未用 Guardian JWKS 对签名做密码学校验。

更详细的记录见 `docs/firefox-upstream-compatibility.md`。

## 安全注意事项

如果发现项目漏洞，请按 [`SECURITY.md`](SECURITY.md) 私下报告；不要在公开 issue 中张贴漏洞细节或真实凭据。

- 只操作属于自己且有权使用的账号、token 和出口。
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
.venv/bin/python -m py_compile ipp_pool.py refresh_tokens.py refresh_state.py login_and_bootstrap.py
bash -n run_service.sh start_pool.sh
git diff --check
```

测试覆盖 Remote Settings 解析与版本筛选、`REC` 语义、CONNECT/MASQUE 选择、JWT claims、authority 解析、所有监听器的开放代理防护、IPv6 综合入口、无子进程 token 探测、HTTP framing、非幂等请求重放防护、原子写入、稳定端口映射、国家等权候选选择、跨进程续期状态、退避恢复、重新登录发布竞态和进程生命周期。GitHub Actions 会在 Python 3.10 与 3.12 上重复执行测试和静态检查。

## 许可证与声明

本项目采用 MIT 许可证。它是独立的开源工具，与 Mozilla、Firefox 或 Fastly 没有官方隶属关系。
