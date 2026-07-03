# chatgpt-register-sub2api

ChatGPT 账号自动注册 → K12 母号加入 → Sub2API JSON 导出，一条龙自动化工具。

从 [chatgpt2api](https://github.com/basketikun/chatgpt2api) 提取注册机核心逻辑，融合 workspace 加入和 sub2api 格式转换。

## 安装

```bash
git clone <this-repo> && cd chatgpt-register-sub2api
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

依赖（仅 2 个）：`curl-cffi`（TLS 指纹伪装）、`pyyaml`（配置文件）。

## 快速开始

```bash
# 1. 生成配置文件
chatgpt-register init

# 2. 编辑 config.yaml，填入：
#    - Outlook 邮箱池（email----password----client_id----refresh_token）
#    - 代理地址（可选但推荐）
#    - K12 workspace ID
#    详见配置文件内注释

# 3. 一条龙运行
chatgpt-register run -n 10 -v
```

## 命令

| 命令 | 说明 |
|------|------|
| `init` | 生成默认 config.yaml |
| `register` | 只注册 ChatGPT 账号 |
| `join-workspace` | 只执行 workspace 加入 |
| `login-team` | 只执行重新登录（team 空间） |
| `login-export` | 用已有账号重新登录，并只导出登录成功账号 |
| `export` | 只导出 sub2api JSON |
| `run` | 完整流水线（上面四步串行） |

### 已有账号登录并导出

`login-export` 从当前目录的 `registered_accounts.json` 读取账号密码，命令行直接传入要处理的邮箱：

```bash
chatgpt-register login-export user1@example.com user2@example.com
```

找不到账号、缺少密码或登录失败的邮箱会被提示并跳过，不会使用旧 token 兜底导出。

## 完整流水线

```
[1] 注册账号 (Outlook 邮箱池接验证码)
      │  输出: email, password, AT_personal, refresh_token, id_token
      ▼
[2] 加入 K12 母号 workspace (POST /invites/request, 自动加入)
      │
      ▼
[3] ⚡ 重新登录 + 选 Team 空间 (OAuth login → workspace 选择 → 获取 AT_team)
      │  输出: AT_team (team scope), RT_team, ID_team
      ▼
[4] 导出 Sub2API JSON
      输出: sub2api_bundle.json
```

## 配置文件 (config.yaml)

```yaml
mail:
  providers:
    - type: outlook_token
      enable: true
      mode: graph
      mailboxes: |
        user1@outlook.com----password1----client_id_1----refresh_token_1
        user2@hotmail.com----password2----client_id_2----refresh_token_2

proxy:
  url: "socks5://127.0.0.1:1080"     # 代理（推荐）
  flaresolverr_url: ""                # FlareSolverr（可选）

registration:
  threads: 3
  total: 10

workspace:
  enabled: true
  ids:
    - "your-k12-workspace-uuid"

sub2api:
  output_file: "sub2api_bundle.json"
```

## Outlook 邮箱池格式

每行一个邮箱，4 个字段用 `----` 分隔：

```
email----password----client_id----refresh_token
```

从 Microsoft Azure 应用注册获取 `client_id` 和 `refresh_token`。

## 输出文件

- `registered_accounts.json` — 注册成功的账号信息（含 token）
- `sub2api_bundle.json` — Sub2API 格式的账号 bundle

## 注意事项

- 建议使用代理，同一 IP 注册超过 3 个号容易触发风控
- curl_cffi 需要 TLS 指纹伪装，这是绕过 OpenAI 反爬的关键
- Team 空间重新登录步骤需要实际 OpenAI 环境调试确认 workspace 选择 API

## 致谢

感谢 [LINUX DO](https://linux.do/) 社区的交流与支持。
