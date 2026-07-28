# Firefox IP Protection 上游兼容性记录

更新时间：2026-07-28

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

## 现行桌面链路

```text
FxA/OAuth
  -> Guardian 激活/状态
  -> GET /api/v1/fpn/token（ProxyPass JWT）
  -> TLS 连接 Fastly 节点
  -> HTTPS CONNECT + Proxy-Authorization: Bearer <JWT>
  -> 目标站点
```

Firefox 对 token 请求使用 `Cache-Control: no-cache`；配额查询使用对 token 端点的 `HEAD` 请求。代理层把 `401`、`403`、`407` 视为授权或资格相关错误，普通 `400` 不应盲目触发 token 刷新。

## 上游变化与本地适配

| 上游行为 | 兼容策略 | 结果 |
|---|---|---|
| `filter_expression` 在 Firefox 选择记录前执行 | 实现受限的 JEXL 子集，版本/国家条件不识别时 fail closed | 不会把版本不匹配的节点暴露给客户端 |
| 同一国家存在按 Firefox 版本门控的记录 | `--firefox-version` 默认使用当前适配版本，可显式覆盖 | 旧版与新版记录选择一致 |
| `REC` 是推荐/任意出口记录 | 保留记录但从显式国家和全国家池排除；`--recommended` 才优先使用 | 不把推荐记录误当成某一国家 |
| 记录或协议缺少端口 | 缺省为 `443`，随后做范围校验 | 兼容省略端口的 Remote Settings 记录 |
| 协议链可能为 `masque` 后跟 `connect` | 优先选择可用 `connect`；MASQUE-only 节点标记不支持 | 不会静默把 MASQUE 字段当成 CONNECT |
| 记录/城市/服务器可被 `locked` 或 `quarantined` 标记 | 默认跳过；`--include-locked` 只放宽 locked，不绕过 quarantine | 保守选择健康且可用节点 |
| Remote Settings 支持 `ETag`/`304` | 缓存 ETag，使用 `If-None-Match`，304 复用 last-known-good | 减少请求并避免坏响应替换好缓存 |
| 节点列表重排或插入 | 用节点稳定身份持久化端口映射 | 已分配端口不会因列表顺序改变而漂移 |
| 同一国家可能包含多个节点 | 综合入口先选择国家，再选择该国节点 | 每个启用国家权重相等，不因节点数量不同而倾斜 |
| Guardian 返回 429/5xx 或 `Retry-After` | 有界重试、尊重有限等待、保留最后有效 token | 避免刷新风暴和凭据回退为空 |
| 代理 JWT 字段异常或即将过期 | 校验三段结构、必要 claims、issuer/audience、时间关系 | 坏 token 不覆盖 last-good；不输出 token 内容 |

## 本地转发边界

- 默认启动全部可用的非 `REC` 国家，每个国家使用完全相同的筛选、端口、回退、健康检查和导出逻辑。
- 每个国家保留独立 SOCKS5/HTTP 节点；综合随机入口在所有已启用国家之间等权选择。
- `REC` 只属于显式 `--recommended` 模式，不混入普通国家综合池。
- 默认监听地址为 loopback；非 loopback 监听必须配置完整监听认证，除非显式使用 `--allow-open-proxy`。
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
3. Remote Settings schema、锁定语义和配额 header 可能在服务端热更新；应保留 last-known-good，并定期运行兼容性测试。
4. 桌面 `fpn` 与 Android `gpn` 端点不能混用；新增移动端支持前应单独完成协议审计。
