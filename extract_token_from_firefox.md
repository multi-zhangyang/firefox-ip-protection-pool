# 从自己的 Firefox 获取 IP Protection token

本文只适用于你本人拥有且有权使用的 Firefox Account。不要抓取、复制或使用他人的账号会话，也不要尝试绕过资格、配额、CAPTCHA 或其他安全机制。

## 优先使用内置指引

项目提供不读取、不打印任何 token 的只读帮助命令：

```bash
.venv/bin/python ipp_pool.py how-to-token
```

先运行该命令，并优先使用当前 Firefox 版本支持的正常登录和授权流程。ProxyPass JWT 是短时凭据，长期运行通常需要由自己的 FxA session 定期刷新。

## Firefox 授权链路

Firefox 桌面端会用带有以下 scope 的 FxA access token 请求 Guardian：

```text
profile
https://identity.mozilla.com/apps/vpn
```

随后请求：

```http
GET https://vpn.mozilla.org/api/v1/fpn/token
Authorization: Bearer <自己的 FxA access token>
```

成功响应中的 `token` 字段是短时 ProxyPass JWT。它与 FxA access token、session token 一样都属于敏感凭据。

## 从自己的浏览器会话观察请求

如果正常引导流程无法使用，可以在自己的 Firefox 中使用 Browser Toolbox 网络面板观察 Guardian 请求。不同 Firefox 版本的工具菜单和内部符号可能变化，应以当前版本的官方开发者工具说明为准。

可以在 `about:config` 中临时启用相关日志，再在 Browser Console 中筛选 IP Protection、Guardian 或 ProxyPass 相关记录。调试完成后恢复不需要的日志选项，避免凭据长期进入控制台历史。

代理抓包工具需要安装本地证书，会改变浏览器或系统信任边界。只有在你理解影响、只分析自己的会话并能在完成后撤销证书时才应使用。HAR、抓包文件和 Browser Toolbox 导出可能包含完整请求头、Cookie、账号标识和 token，不能上传到 issue、网盘或公共仓库。

## 安全保存 ProxyPass JWT

在项目目录内创建仅当前用户可读写的目标文件，再用不会回显内容的编辑器写入 token：

```bash
mkdir -p tokens
install -m 600 /dev/null tokens/proxy_pass.jwt
${EDITOR:-vi} tokens/proxy_pass.jwt
```

文件应只包含 token 本身和可选的末尾换行。不要使用会把 token 留在 shell 历史、进程参数或终端回滚缓冲区中的命令。写入后检查状态时，项目只输出解析后的安全摘要，不输出原文：

```bash
.venv/bin/python ipp_pool.py token-status
```

## 使用自己的 FxA access token 刷新

如果已经通过正常授权流程取得带有所需 scope 的个人 FxA access token，可将它安全保存到 `tokens/fxa_token.txt`，再执行：

```bash
.venv/bin/python ipp_pool.py token-refresh
.venv/bin/python ipp_pool.py token-status
```

同样不要把 access token 直接写进命令行。长期刷新所需的 session 与账号元数据也必须保持本地私有，并设置 `0600` 权限。

## 验证

先从公开列表选择你有权使用的国家代码，再做单次连接验证：

```bash
.venv/bin/python ipp_pool.py sync
.venv/bin/python ipp_pool.py probe --country COUNTRY_CODE
```

验证结果只应记录状态码、协议、国家或节点数量等非敏感信息。不要保存完整认证代理 URL、请求头或 token。

## 必须保护的调试产物

- ProxyPass JWT、FxA access token 和 session token。
- Cookie、浏览器 storage、登录截图和浏览器配置文件。
- HAR、代理抓包、Browser Toolbox 导出和控制台历史。
- 邮箱、账号 UID、验证码、监听用户名与密码。
- 包含认证信息的完整 SOCKS5/HTTP URL。

如果这些数据曾被上传、提交或分享，应立即撤销相关会话、轮换凭据，并从公开历史中彻底移除泄露内容。
