# Firefox IP Protection 上游兼容性记录

更新时间：2026-08-12

这份记录说明本地代理池如何对齐 Firefox 桌面端 IP Protection 的现行行为。它只记录公开协议和代码结构，不包含账号、会话、代理口令或运行时地址。

## 研究范围

- Firefox 桌面端 `fpn`（Firefox Private Network / IP Protection）授权链路。
- Remote Settings 的 `vpn-serverlist` 集合及其筛选、协议和缓存字段。
- Guardian token、配额响应和上游代理错误的兼容性。
- 本项目的 SOCKS5/HTTP 转发边界；Android `gpn` 流程不在本次适配范围内。

## 公开参考

1. Firefox IP Protection 源码目录：
   <https://searchfox.org/mozilla-central/source/toolkit/components/ipprotection>
2. Remote Settings `vpn-serverlist` 集合：
   <https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records>
3. Guardian 服务入口（仅作协议形状参考）：
   <https://vpn.mozilla.org>
4. Firefox 网络代理与 Remote Settings 代码应以目标版本源码为准；服务端记录可能在不发布 Firefox 的情况下变化。
5. Firefox 主干版本文件：
   <https://searchfox.org/firefox-main/source/browser/config/version.txt>
6. Guardian Desktop 请求实现：
   <https://searchfox.org/firefox-main/rev/4b4e59946a3db5ddf42ea730fc44c22a99877303/toolkit/components/ipprotection/fxa/GuardianClient.sys.mjs>
7. `vpn-serverlist` 集合签名 metadata：
   <https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist>

## 现行桌面链路

```text
FxA/OAuth
  -> Guardian 激活/状态
  -> GET /api/v1/fpn/token（ProxyPass JWT）
  -> TLS 连接 Fastly 节点
  -> HTTPS CONNECT + Proxy-Authorization: Bearer <JWT>
  -> 目标站点
```

Firefox 的 token、usage、status 和 activate 请求都发送 `Content-Type: application/json` 并禁用缓存；配额查询使用对 token 端点的 `HEAD` 请求。代理层把 `401`、`403`、`407` 视为授权或资格相关错误，普通 `400` 不应盲目触发 token 刷新。

## 上游变化与本地适配

| 上游行为 | 兼容策略 | 结果 |
|---|---|---|
| `filter_expression` 在 Firefox 选择记录前执行 | 实现受限的 JEXL 子集，版本/国家条件不识别时 fail closed | 不会把版本不匹配的节点暴露给客户端 |
| 同一国家存在按 Firefox 版本门控的记录 | 默认跟随 2026-07-28 Firefox 主干 `155.0a1`；可用 `--firefox-version`/`IPP_FIREFOX_VERSION` 覆盖 | 旧版与新版记录选择一致，默认值不会停留在旧主干 |
| `REC` 是推荐/任意出口记录 | 保留记录但从显式国家和全国家池排除；`--recommended` 才优先使用 | 不把推荐记录误当成某一国家 |
| 记录或协议缺少端口 | 缺省为 `443`，随后做范围校验 | 兼容省略端口的 Remote Settings 记录 |
| 协议链可能为 `masque` 后跟 `connect` | 优先选择可用 `connect`；MASQUE-only 节点标记不支持 | 不会静默把 MASQUE 字段当成 CONNECT |
| 记录/城市/服务器可被 `locked` 或 `quarantined` 标记 | 默认跳过；`--include-locked` 只放宽 locked，不绕过 quarantine | 保守选择健康且可用节点 |
| Remote Settings 支持 `ETag`/`304` | 缓存 ETag，使用 `If-None-Match`，304 复用 last-known-good | 减少请求并避免坏响应替换好缓存 |
| 节点列表重排或插入 | 用节点稳定身份持久化端口映射 | 已分配端口不会因列表顺序改变而漂移 |
| 同一国家可能包含多个节点 | 综合入口先选择国家，再选择该国节点 | 每个启用国家权重相等，不因节点数量不同而倾斜 |
| Guardian Desktop 请求统一发送 JSON content type 和 no-cache | token、usage、status、activate 共用相同安全 header 形状 | 避免客户端行为与当前 Firefox 漂移 |
| `X-Quota-Unlimited: true` 或有限配额三元组 | unlimited 不要求有限字段；否则严格校验 limit/remaining/reset、非负值和时间区 | 坏 quota 不会静默伪装成有效数值，也不会阻止有效 ProxyPass 使用 |
| Guardian 返回 429/5xx 或 `Retry-After` | 有界重试、尊重有限等待、保留最后有效 token | 避免刷新风暴和凭据回退为空 |
| 代理 JWT 字段异常或即将过期 | 校验三段结构、必要 claims、issuer/audience、时间关系 | 坏 token 不覆盖 last-good；不输出 token 内容 |

## 认证链路观察（2026-08-12）

以下为 `login_and_bootstrap.py` 重新认证时实测到的上游行为，供复刻者参考：

### Fastly 挑战循环与图形验证码

- 访问 `accounts.firefox.com` 会先经过 Fastly challenge（POW 与/或图形 CAPTCHA）。
- 图形 CAPTCHA 每轮最多下发 8 题；答案错误或无法识别时 Fastly 会持续下发新题，
  8 轮耗尽后即使未放行，脚本也会继续执行登录步骤，但登录表单可能不会渲染。
- tesseract / 传统 OCR 对这类带干扰线的 CAPTCHA 识别率极低，实测多题全错。
- 可靠方案：配置视觉模型 API，脚本会把题图交给模型识别。环境变量
  （供应商无关命名，兼容任何 OpenAI 格式 `/v1/chat/completions` 网关；
  `ANTHROPIC_*` / `OPENAI_*` 仍作为回退支持）：
  `VISION_API_BASE_URL`、`VISION_API_KEY`、`VISION_MODEL`。
- Fastly 对 headless 浏览器指纹更严格；`FXA_HEADLESS=0` 配合
  `xvfb-run -a` 改用 headed 模式可显著提升通过率。

### FxA API 的 406 反自动化

- `POST /v1/account/credentials/status`：带浏览器/自动化 UA（Playwright、Firefox UA）
  的请求会被 Fastly 边缘层以 406 拒绝；requests 默认 UA 放行。
- `POST /v1/account/login`：即使使用 requests 默认 UA 也返回 406（空 body，
  走 Fastly 边缘层），必须携带浏览器会话 cookie（Fastly CAPTCHA 通过的凭证）才放行。
- 结论：`account/*` API 调用应使用 requests 默认 UA + 从 Playwright context
  复制的 cookie，二者缺一不可（见 `login_and_bootstrap.py::api_login_with_page`）。

### FxA 会话生命周期

- Guardian 每 10 分钟签发一次 ProxyPass，长期无人值守自动续期可用。
- FxA session 会被 Mozilla 服务端周期性撤销（实测约 10 天一次），下次续期返回
  HTTP 401 `reauth_required`，必须重新交互式登录（邮箱 6 位验证码）或重新导入
  桌面 Firefox 凭据；无法通过纯 API 恢复。
- 运维上应监控 `tokens/refresh_state.json` 的 `result`，连续出现
  `reauth_required` 时提前安排重新认证，避免代理池空转。

## 本地转发边界

- 默认启动全部可用的非 `REC` 国家，每个国家使用完全相同的筛选、端口、回退、健康检查和导出逻辑。
- 每个国家保留独立 SOCKS5/HTTP 节点；综合随机入口在所有已启用国家之间等权选择。
- `REC` 只属于显式 `--recommended` 模式，不混入普通国家综合池。
- 默认监听地址为 loopback；独立节点、SOCKS 综合入口和 HTTP 综合入口中的任何一个使用非 loopback 地址时，都必须配置完整监听认证，除非显式使用 `--allow-open-proxy`。
- HTTP 明文转发只接受 absolute-form `http://`；HTTPS 必须走 `CONNECT`。
- 拒绝 chunked、冲突或超限 `Content-Length`，并移除 hop-by-hop 与 `Connection` 指定的头。
- SOCKS5 使用 `socks5h://` 导出，让目标域名在代理端解析。
- 当前实现为 TCP CONNECT；没有实现 MASQUE/HTTP3/UDP。遇到 MASQUE-only 记录会明确标记 unsupported。

## 验证建议

```bash
python3 ipp_pool.py sync
python3 ipp_pool.py token-status
python3 ipp_pool.py usage
python3 ipp_pool.py probe --country COUNTRY_CODE
python3 ipp_pool.py run --rotate-mode random
python3 -m unittest discover -s tests -v
```

验证时只记录国家、协议、节点数量、HTTP 状态和出口地理结果。不要把 JWT、FxA token、Cookie、Basic 密码、完整代理 URL 或浏览器 storage 写入日志、报告或 issue。

## 未覆盖的上游风险

1. MASQUE/QUIC 与 UDP 转发仍未实现；Firefox 未来可能把 CONNECT fallback 移除。
2. 当前 JWT 校验验证结构和 claims，不验证 Guardian 签名；若 Guardian 公布稳定 JWKS，应增加可选的密码学验证。
3. Firefox 的 `RemoteSettings("vpn-serverlist")` 会验证 Mozilla 内容签名；本项目目前只依赖 HTTPS、ETag、schema 检查与 last-known-good，尚未实现 Kinto canonical records、P-384 内容签名和 Mozilla PKI 证书链的完整验证。不能仅凭 metadata 中存在 `signature` 字段宣称签名有效。
4. Remote Settings schema、锁定语义和配额 header 仍可能在服务端热更新；应保留 last-known-good，并定期运行兼容性测试。
5. 桌面 `fpn` 与 Android `gpn` 端点不能混用；新增移动端支持前应单独完成协议审计。
