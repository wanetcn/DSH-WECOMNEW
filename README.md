# DSH-WECOMNEW（dsh-wecom 增强版）

> 基于 [michaelcode-wang/dsh-wecom](https://github.com/michaelcode-wang/dsh-wecom)（MIT）增强：在上游桥接能力之上，新增企业微信文件收发、多用户工作区隔离与管理员分级、待办提醒，以及 **ask_user_question / 权限确认向企业微信的透传**（不再依赖 web 界面应答）。

企业微信（WeCom）智能机器人桥接插件：通过 `aibot` WebSocket 网关，让 DeepSeek Harness 的智能体变成能在企业微信里双向对话的助手。**无需公网地址、无需自建应用回调**，只需智能机器人的 `bot_id` + `secret`。

协议移植自 Hermes Agent 的 `plugins/platforms/wecom/adapter.py`（`aibot_subscribe` 认证 → `aibot_msg_callback` 收消息 → `aibot_respond_msg` / `aibot_send_msg` 回复）。

## 特性

- 企业微信智能机器人 WebSocket 长连接（`wss://openws.work.weixin.qq.com`），断线自动退避重连
- 每个聊天一个独立 agent 会话，多轮上下文保留，空闲自动回收
- 白名单访问控制（`allowedUserIds`）
- markdown 回复 + 超长消息自动分片（默认 4000 字符）
- **交互透传**：模型调用 `ask_user_question`（提问/选择题）或触发工具权限确认时，提示自动推送到企业微信；用户直接回复文字即完成应答，会话继续（见下文「交互问答」）
- **文件收发**：企业微信发来的文件自动下载、AES 解密并落盘到用户工作区；**图片消息（含图文混排中的图片）同样支持**——解密保存后以视觉块直接传给 vision 模型分析（每条最多 6 张，同时落盘留档）；模型也可通过 `wecom_send_file` 工具把文件反向发给用户（走网关分片上传，单文件上限约 50MB；**仅限当前用户私有工作区目录和公共工作区目录内的文件**，realpath 解析后强制校验，其他路径一律拒绝，可用 `files.sendEnabled=false` 关闭）
- **多用户隔离**：每个企业微信用户独立私有工作区（会话 cwd 即写边界），管理员可获完整沙箱权限
- **群聊支持**：把机器人拉进企微群即可使用。群会话使用独立的共享目录（`security.groupsRoot`，默认 `groups/<chatId>`）作为写空间，标题为 `wecom-group/<群ID>`；群会话**固定** workspace-write 沙箱 + 禁止提权审批，不随发言者身份变化（管理员先发言也不会升权）
- **侧栏状态入口**：dsh web 界面侧栏底部（设置上方）有 📱「企微」入口，直接显示总用户数、总会话数与连接状态，点击弹出完整面板（在线时长、活动会话、收发消息计数、待用户应答数；数据来自插件注册的 `/api/wecom/status` 路由）
- **会话自动归组**：每个企微用户的会话自动挂到侧栏的「wecom」工作区分组（历史会话启动时回填，新会话创建即挂载）；因每用户目录是沙箱写边界，每个用户一个 wecom 文件夹
- **流式进度直播**：收到消息立刻出现一个「🤔 正在处理…」气泡，agent 干活过程中实时刷新（工具调用、耗时），完成后气泡定格为最终答案——全程只有一条消息；超过 10 分钟（网关流上限）自动转为主动推送模式，可用 `progress.enabled=false` 关闭
- 聊天命令：`/help`、`/todo`、`/history`、`/switch`、`/reset`、`/status`，**支持最短唯一前缀**（如 `/hi` 即 `/history`；前缀有歧义时会列出候选）
- 待办提醒：`/todo` 显示用户待办事宜；待办行带日期时间（如 `2026-09-05 20:00`）时，系统在到期前主动推送企业微信提醒（默认提前 30 分钟，行内可用 `提前N分钟/提前N小时` 自定义）

## 历史会话管理

```text
/history     列出本聊天的历史会话（新→旧，含标题、创建时间，标注当前会话）
/switch 2    切换到列表中第 2 个会话，上下文完整恢复，继续对话即可
```

- 列表范围 = 当前聊天的工作区（私聊 = 你的私有目录；群聊 = 群共享目录）
- 任务执行中会拒绝切换；切换失败自动回退原会话
- 待办提醒：`/todo` 显示用户待办事宜；待办行带日期时间（如 `2026-09-05 20:00`）时，系统在到期前主动推送企业微信提醒（默认提前 30 分钟，行内可用 `提前N分钟/提前N小时` 自定义）

## 交互问答

模型需要用户输入时（`ask_user_question` 提问/选择题、工具权限确认），提示会以 markdown 消息推送到当前企业微信聊天，用户的下一条文字消息即被视为回答：

```text
❓ 智能体需要你的输入
【Confirm】要继续执行部署吗？
   1. 是，继续 (Recommended)
   2. 取消
回复选项序号或直接输入你的答案；回复「取消」放弃本次提问。
```

- 单问题：回复选项序号（`1`、`B`）、选项文字，或任意自定义文字（作为自由答案回传模型）
- 多问题：按「序号: 答案」逐行回复，如 `1: 是`、`2: PostgreSQL`
- 权限确认：回复「允许 / 拒绝 / 取消」
- 回复「取消」会让工具以取消状态结束，模型自行调整后续动作
- 交互挂起期间会话不会被空闲回收；`/reset` 可随时放弃挂起的提问并重开会话
- 超过企业微信被动回复窗口（约 5 秒）的答复自动降级为主动推送，长等待后不丢消息

实现上仅使用 dsh 的标准扩展接口：权限走 `approval/request` 瀑布应答器（前置认领企业微信会话的请求，其余请求交还宿主），提问走 `userQuestions` provider 槽（代理宿主 provider，按会话路由），不修改 dsh 本体。

## 安装

```bash
# 从 GitHub
dsh plugin --profile im add github:wanetcn/DSH-WECOMNEW
```

## 前置条件

1. **企业微信智能机器人**：在企业微信后台创建一个「智能机器人」，拿到 `bot_id` 和 `secret`。
2. **im profile 需要 preset roster**：独立 `im` profile（`dsh-base` + 本插件）没有 web 层，而 preset roster（`agent-presets`）默认由 `dsh-web-app` 提供。若要让 agent 挂载某个 preset，需在 im profile 的 `cordis.patch.yml` 里手动插入 roster（见下方完整示例）。

## 配置

在 `$DSH_HOME/profiles/im/cordis.patch.yml` 中：

```yaml
# 1) 插入 preset roster（im profile 无 web 层，需手动补）
- insert:
    - id: agent-presets
      name: '@deepseek-ai/dsh-agent-presets'
      config:
        default: standard          # 默认 preset；可按需改成你自己的 preset

# 2) 启用本插件
- id: dsh-wecom
  disabled: false
  config:
    botId: '你的机器人ID'
    secret: '你的机器人密钥'
    allowedUserIds: ['你的企业微信userid']
    agent:
      preset: standard             # 每个企业微信聊天对应的 agent preset
```

> 启动：`dsh --profile im`（建议配 launchd / systemd 常驻）。

## 配置项

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 总开关 |
| `botId` | `''` | 企业微信智能机器人 ID |
| `secret` | `''` | 企业微信智能机器人密钥（只写） |
| `websocketUrl` | `wss://openws.work.weixin.qq.com` | WebSocket 网关地址 |
| `allowedUserIds` | `[]` | 允许对话的 userid 白名单；留空=所有人 |
| `agent.preset` | `standard` | 挂载的 agent preset |
| `agent.cwd` | `''` | agent 工作目录（默认进程 cwd） |
| `agent.provider` / `agent.model` | `''` | 模型覆盖；留空=部署默认 |
| `agent.maxMessageLength` | `4000` | 单条外发消息最大字符数 |
| `agent.idleTimeoutMs` | `1800000` | 聊天空闲多久后释放 agent（0=永不） |
| `files.enabled` | `true` | 接收文件开关（WeCom → DSH） |
| `files.dir` | `''` | 文件保存根目录；默认 `<usersRoot>/.wecom-uploads/<userId>/` |
| `files.maxBytes` | `104857600` | 单文件上限（字节），默认 100MB |
| `files.timeoutMs` | `30000` | 文件下载超时（ms）；下载链接约 5 分钟有效 |
| `files.sendEnabled` | `true` | 发送文件开关（`wecom_send_file` 工具，DSH → WeCom） |
| `files.maxSendBytes` | `50331648` | 单个外发文件上限（字节），默认 48MB；网关硬上限约 50MB |
| `security.adminIds` | `[]` | 超级用户 userid 列表（管理员：完整沙箱权限、可改 dsh/系统配置、可查看所有用户会话） |
| `security.usersRoot` | `''` | 所有用户（含管理员）的私有工作区根目录；`<usersRoot>/<userId>`，上传存 `<usersRoot>/.wecom-uploads/<userId>/`；默认 `<agent.cwd>/users` |
| `security.publicDir` | `''` | 公共工作区（普通用户只读）；默认 `<agent.cwd>/public` |
| `security.groupsRoot` | `''` | 群聊共享工作区根目录；每群 `<groupsRoot>/<chatId>`，默认 usersRoot 同级 `groups/` |
| `security.boundaryPrompt` | `true` | 是否注入每用户权限边界提示 |
| `progress.enabled` | `true` | 流式进度气泡开关（收消息秒回 + 工具活动实时刷新，完成定格为答案） |
| `todo.file` | `待办事宜文件.md` | 每个用户私有工作区中的待办文件名（`/todo` 读取并展示） |
| `todo.defaultRemindMinutes` | `30` | 未写 `提前N` 时的默认提醒提前量（分钟） |
| `todo.checkIntervalMs` | `300000` | 提醒扫描周期（ms，默认 5 分钟，最小 5000） |
| `todo.graceMinutes` | `5` | 到达提醒点前 5 分钟内即触发发送（可提前、不推后；提醒窗口为 `时间−提前量−5分钟` 到 `事件时间` 之间） |

## 安全

- **务必配置 `allowedUserIds` 白名单**——留空意味着任何人都能驱动你的智能体执行主机工具。
- `secret` 标记为 `role('secret')`，不会回显到浏览器。
