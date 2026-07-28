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
.venv/bin/pip install -r requirements.txt

# 只同步公开节点列表，不需要读取 token
.venv/bin/python ipp_pool.py sync
```

同步日志只应包含节点数量、国家统计和缓存状态，不应包含账号凭据。上游节点会随 Firefox 版本和服务端配置变化，以当前同步结果为准。

## 凭据准备

运行代理需要属于你自己的有效 ProxyPass JWT。可选择以下方式之一：

1. 将从自己的 Firefox 会话取得的短时 ProxyPass JWT 保存到 `tokens/proxy_pass.jwt`。
2. 保存自己的 FxA session 相关文件，再由 `refresh_tokens.py` 自动换取短时 ProxyPass JWT。

优先阅读内置的只读指引：

```bash
.venv/bin/python ipp_pool.py how-to-token
```

Firefox 使用的 OAuth scope 为：

```text
profile
https://identity.mozilla.com/apps/vpn
```

检查 token 状态：

```bash
.venv/bin/python ipp_pool.py token-status
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

核心程序也支持 `IPP_LISTEN_USER` 和 `IPP_LISTEN_PASS`。`run_service.sh` 不会把密码复制到命令行参数；Python 进程会直接读取环境变量或认证文件。配置认证后，使用客户端的独立认证参数，避免把密码嵌入代理 URL 或 shell 历史：

```bash
curl --proxy-user 'USER:PASSWORD' -x socks5h://127.0.0.1:1090 https://ipinfo.io/ip
```

公网部署还应限制防火墙来源、只开放必要端口并定期轮换密码。`--advertise-host` 只影响导出地址，不改变监听安全策略。

## 通用服务脚本

`run_service.sh` 使用脚本自身目录，不包含固定安装路径。它默认绑定回环地址、启动全部可用非 `REC` 国家、不设置数量上限，并显式使用国家等权随机综合入口。

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
| `IPP_REFRESH_BEFORE_START` | `1` | 启动前是否尽力刷新一次 token |

示例：

```bash
IPP_BIND=127.0.0.1 IPP_ROTATE_MODE=random ./run_service.sh
```

如果把 `IPP_BIND` 改成非回环地址，必须先提供认证文件或完整的 `IPP_LISTEN_USER`/`IPP_LISTEN_PASS`。脚本不会自动探测公网地址，也不会静默开放代理。

## systemd 部署

示例 unit 位于 `examples/ipp-pool.service`。安装到稳定路径后，检查 unit 的 `WorkingDirectory` 与 `ExecStart`，再执行：

```bash
sudo cp examples/ipp-pool.service /etc/systemd/system/ipp-pool.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipp-pool.service
sudo systemctl status ipp-pool.service
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

`usage` 使用 Guardian 的 `HEAD /api/v1/fpn/token` 查询配额；没有 FxA access token 时会明确失败。`probe` 只应用于你有权使用的出口，输出中也不应包含凭据。

## 可选浏览器引导工具

`login_and_bootstrap.py` 只用于可选的首次引导，不是启动代理池的必要步骤。Firefox Accounts 可能要求 CAPTCHA、邮箱验证码或其他交互验证。

如果用户主动配置第三方视觉 API，引导工具可能把 CAPTCHA 图片发送给该第三方处理；这会将图像交给外部服务。工具也可能在本地保存登录截图、浏览器 storage 或 Cookie，这些文件可能包含账号信息和会话凭据。使用前应检查配置与第三方隐私政策，使用后妥善保护或清理本地产物，绝不能把它们提交到仓库。

## Firefox 上游适配说明

- 在客户端执行受限且保守的 `filter_expression` 子集；无法识别的表达式会拒绝匹配。
- 使用 Firefox 版本比较选择适用记录，可通过 `--firefox-version` 覆盖默认版本。
- 把 `REC` 与普通国家记录分离。
- 缺少协议端口时按兼容规则使用 `443`，存在 CONNECT 时优先选择 CONNECT。
- 默认跳过 `locked`、`quarantined` 和不支持协议的节点；`--include-locked` 只用于诊断。
- Remote Settings 缓存支持 ETag、304、节点快照差异和最后已知有效回退。
- Guardian 请求使用 no-cache、有界重试并尊重合理范围内的 `Retry-After`。
- ProxyPass JWT 会检查结构、算法字段、必需 claims、时间、issuer 和 audience；当前尚未用 Guardian JWKS 对签名做密码学校验。

更详细的记录见 `docs/firefox-upstream-compatibility.md`。

## 安全注意事项

- 只操作属于自己且有权使用的账号、token 和出口。
- 把 FxA session token、ProxyPass JWT、Cookie、HAR、浏览器 storage 和监听密码视为高价值凭据。
- 不要提交 `tokens/`、运行时 `data/`、认证导出、日志、截图或浏览器配置文件。
- 非回环监听必须启用认证，并配合防火墙限制来源。
- Guardian 可能返回配额耗尽或限流；程序会尊重服务端响应，不能绕过配额。
- 当前实现只提供 TCP CONNECT 兼容性，不等同于完整 VPN，也不支持 UDP/MASQUE 数据面。
- JWT 当前未做签名密码学验证；不应把本地结构校验理解为对 token 来源的完整信任证明。

## 开发与测试

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m py_compile ipp_pool.py refresh_tokens.py login_and_bootstrap.py
bash -n run_service.sh start_pool.sh
git diff --check
```

测试覆盖 Remote Settings 解析与版本筛选、`REC` 语义、CONNECT/MASQUE 选择、JWT claims、authority 解析、监听认证、HTTP framing、非幂等请求重放防护、原子写入、稳定端口映射、国家等权候选选择和进程生命周期。

## 许可证与声明

本项目采用 MIT 许可证。它是独立的开源工具，与 Mozilla、Firefox 或 Fastly 没有官方隶属关系。
