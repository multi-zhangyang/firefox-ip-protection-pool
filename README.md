# Firefox IP Protection 代理池

将 Firefox IP Protection（Mozilla FPN）的多国家出口转换为本地 SOCKS5 / HTTP 代理：每个节点独立端口 + 全国家等权随机综合入口。

> 仅使用你本人有权使用的 Firefox Account 与服务，遵守适用条款与法律。

## 快速开始

```bash
git clone https://github.com/multi-zhangyang/firefox-ip-protection-pool.git
cd firefox-ip-protection-pool
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

.venv/bin/python ipp_pool.py sync          # 同步公开节点列表
.venv/bin/python ipp_pool.py run           # 启动代理池
```

跑通 `run` 后先验证节点与端口，然后准备凭据（见下）。

## 工作原理

```text
Firefox Account/OAuth -> Guardian(vpn.mozilla.org) -> 短时 ProxyPass JWT
  -> TLS + CONNECT 上游节点 -> 目标网站

你的程序 -> 本地 SOCKS5/HTTP 监听器 -> (同上链路) -> 目标网站
```

上游优先使用 `CONNECT`；MASQUE/QUIC/UDP 数据面未实现（MASQUE-only 节点会被跳过）。ProxyPass 每 10 分钟过期，程序自动续期。

## 目录结构

| 文件 | 作用 |
| --- | --- |
| `ipp_pool.py` | 主程序：同步节点、续期、启动代理 |
| `import_credentials.py` | 导入桌面 Firefox 导出的凭据 |
| `login_and_bootstrap.py` | 备用：命令行登录引导（无桌面 Firefox 时） |
| `tools/firefox-credential-export.html` | 桌面 Firefox 凭据导出器 |
| `run_service.sh` / `examples/` | systemd 部署 |
| `docs/firefox-upstream-compatibility.md` | 上游兼容性与认证链路记录 |

核心依赖仅 `requests` + `PyFxA`（`requirements.txt`）。

## 准备凭据

### 方式 A：桌面 Firefox 导出（推荐）

1. `about:profiles` 新建配置 → 登录具有 IP Protection 资格的 Firefox Account → 完成 IP Protection 面板首次启用。
2. 用 Firefox 本地打开 `tools/firefox-credential-export.html`，选择配置根目录的 `signedInUser.json`，生成 `fxa-renewal-credentials.json`（仅含 `email`/`uid`/`session_token`，等同登录凭据，勿外传）。

### 方式 B：命令行引导（VPS 直接登录）

```bash
.venv/bin/python -m pip install -r requirements-bootstrap.txt
.venv/bin/playwright install firefox

# Fastly 会下发图形验证码，推荐配置视觉模型 API 自动答题
# （任何提供标准 /v1/chat/completions 视觉接口的模型网关均可）：
export VISION_API_BASE_URL=https://你的网关
export VISION_API_KEY=你的key
export VISION_MODEL=视觉模型名

.venv/bin/python login_and_bootstrap.py --email YOUR_EMAIL
# 或 headed 模式（通过率更高）：
# FXA_HEADLESS=0 xvfb-run -a .venv/bin/python login_and_bootstrap.py --email YOUR_EMAIL
```

脚本自动过 Fastly challenge、密码、邮箱 6 位验证码并保存凭据。

## 导入 VPS 并启动

```bash
sudo groupadd --system ipp-pool; sudo useradd --system --gid ipp-pool \
  --create-home --home-dir /var/lib/ipp-pool --shell /usr/sbin/nologin ipp-pool
sudo git clone <本仓库> /opt/firefox-ip-protection-pool
sudo python3 -m venv /opt/firefox-ip-protection-pool/.venv
sudo /opt/firefox-ip-protection-pool/.venv/bin/python -m pip install \
  -r /opt/firefox-ip-protection-pool/requirements.txt
sudo install -d -o ipp-pool -g ipp-pool -m 0700 \
  /opt/firefox-ip-protection-pool/{tokens,data,logs,export}

# 上传 fxa-renewal-credentials.json 到 ~/.ipp-import/ 后：
sudo install -o ipp-pool -g ipp-pool -m 0600 \
  "$HOME/.ipp-import/fxa-renewal-credentials.json" \
  /opt/firefox-ip-protection-pool/tokens/.credential-import.json
sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/import_credentials.py \
  /opt/firefox-ip-protection-pool/tokens/.credential-import.json --delete-source

sudo -u ipp-pool -H /opt/firefox-ip-protection-pool/.venv/bin/python \
  /opt/firefox-ip-protection-pool/ipp_pool.py token-status   # 确认 success
```

systemd 常驻：

```bash
sudo mkdir -p /etc/firefox-ip-protection-pool
sudo install -m 0644 /opt/firefox-ip-protection-pool/examples/ipp-pool.env.example \
  /etc/firefox-ip-protection-pool/ipp-pool.env
sudo install -m 0644 /opt/firefox-ip-protection-pool/examples/ipp-pool.service \
  /etc/systemd/system/ipp-pool.service
sudo systemctl daemon-reload && sudo systemctl enable --now ipp-pool.service
```

## 使用

默认端口：

| 类型 | 地址 |
| --- | --- |
| 独立 SOCKS5 节点 | `127.0.0.1:21000+` |
| 独立 HTTP 节点 | `127.0.0.1:31000+` |
| SOCKS5 综合随机入口 | `127.0.0.1:1090` |
| HTTP 综合随机入口 | `127.0.0.1:8080` |

```bash
curl -x socks5h://127.0.0.1:1090 https://ipinfo.io/json   # 综合入口
curl -x http://127.0.0.1:31000 https://ipinfo.io/json     # 独立节点
```

- 筛选国家：`ipp_pool.py run --countries US,JP --rotate-mode random`
- 关闭综合入口：`--rotator off` / `--http-rotator off`
- 推荐模式：`--recommended`（REC 记录独立使用，不与 `--countries` 混用）
- 公网监听必须配置认证：`tokens/proxy_listen_auth.txt`（`USER=..`/`PASS=..`，0600）

## 命令速查

```bash
ipp_pool.py sync | token-status | token-refresh | usage | how-to-token
ipp_pool.py probe --country US
ipp_pool.py run [--countries US,JP] [--limit N] [--recommended] [--rotator off]
refresh_tokens.py --force
import_credentials.py <bundle.json> [--delete-source]
```

## 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| 日志反复 `reauth_required`，服务重启失败 | FxA 会话被 Mozilla 服务端撤销（实测约 10 天一次）。重新导出凭据导入，或跑 `login_and_bootstrap.py` 重新认证 |
| 引导卡在 CAPTCHA 循环 | 未配置视觉 API 或 OCR 答错。设置 `VISION_API_BASE_URL` / `VISION_API_KEY` / `VISION_MODEL`；改用 `FXA_HEADLESS=0 xvfb-run` |
| FxA API 返回 406 | 浏览器/自动化 UA 被拒，且 `account/login` 需带会话 cookie。新版代码已处理；手写脚本注意 requests 默认 UA + cookie |
| 代理连不通 | `token-status` 查 token；`probe --country XX` 测出口；检查端口占用与上游连通 |

详见 [`docs/firefox-upstream-compatibility.md`](docs/firefox-upstream-compatibility.md)。

## 安全

- 凭据包、session token、JWT、监听密码均为高价值机密，勿提交/外传；仓库 `.gitignore` 已排除 `tokens/` 等。
- 非回环监听必须认证 + 防火墙限制来源。
- 当前为 TCP CONNECT 兼容，非完整 VPN；JWT 未做签名验证。

## 开发与测试

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m py_compile *.py
bash -n run_service.sh start_pool.sh
git diff --check
```
## 友链
- [Linux.Do](https://linux.do)

MIT 许可证。独立开源工具，与 Mozilla/Firefox/Fastly 无官方隶属关系。
