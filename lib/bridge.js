// Bridge core: inbound WeCom messages -> dsh agents -> outbound replies.
//
// The driving pattern mirrors @deepseek-ai/dsh-headless and dsh-im-hub:
// create one agent per chat, followup a user message, wait for quiescence,
// and read the assistant text back from the session log. Agents are kept
// alive per chat so multi-turn conversations retain context.
//
// File support (WeCom -> dsh): inbound msgtype "file" arrives with an
// encrypted download url + aeskey. The bridge downloads, AES-256-CBC
// decrypts, and stores the file under <usersRoot>/.wecom-uploads/<userId>/
// (usersRoot defaults to <agent.cwd>/users). The storage path is then replied
// back to the WeCom channel ("✅ 文件已上传到：<path>") so the user can reuse
// it in follow-up messages. Pure file messages stop there; a file sent with
// text also forwards the agent a user message mentioning the saved path as
// an `@path` file reference, so the agent reads it with its file tools.
//
// User isolation (security): every WeCom user — admins included — resolves to
// a private workspace <usersRoot>/<userId> as their session cwd, fully
// separated from the public workspace (security.publicDir, e.g.
// <agent.cwd>/public). Admins (security.adminIds, e.g. ['alice']) additionally
// get the danger-full-access sandbox mode, so their agent may modify
// dsh/system configs and read every session. Non-admin users keep
// workspace-write: the sandbox blocks writes outside their own workspace
// (uploads and files stay private, the public workspace is read-only for
// them), and a per-session prompt section forbids reading other users'
// sessions, uploads, or configs. Reads are inherently unrestricted in
// workspace-write mode, so the prompt boundary is the guard against
// cross-user reads.

import { randomUUID } from 'node:crypto';
import { mkdir, readFile, realpath, stat as fsStat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { installModelSelection } from '@deepseek-ai/dsh-agent';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { SessionId } from '@deepseek-ai/dsh-session';
import { setSandboxMode } from '@deepseek-ai/dsh-sandbox-policy';
import { setApprovalPolicy } from '@deepseek-ai/dsh-user-approval';
import { admitEncodedImages } from '@deepseek-ai/dsh-attachment';
import { WeComAdapter } from './wecom-adapter.js';
import { registerSendFileTool } from './sendfile.js';
import { decryptFile, downloadFile, sanitizeFileName, saveUnique, sizeText, sniffImageMediaType } from './media.js';
import {
  DEFAULT_TODO_FILE,
  loadState,
  loadTodoItems,
  pruneSent,
  reminderKey,
  saveState
} from './todos.js';

/** Aggregate the plain-text content of an assistant message. */
function assistantText(message) {
  return message.content
    .filter((block) => block.type === 'text')
    .map((block) => block.text)
    .join('');
}

/** Chunk a long text into <= maxLen pieces on newline boundaries when possible. */
export function splitText(text, maxLen) {
  if (text.length <= maxLen) return [text];
  const chunks = [];
  let rest = text;
  while (rest.length > maxLen) {
    let cut = rest.lastIndexOf('\n', maxLen);
    if (cut < maxLen / 2) cut = rest.lastIndexOf(' ', maxLen);
    if (cut < maxLen / 2) cut = maxLen;
    chunks.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut).trimStart();
  }
  if (rest.length > 0) chunks.push(rest);
  return chunks;
}

/** Approval outcome vocabulary (mirrors @deepseek-ai/dsh-user-approval). */
const APPROVAL_OUTCOMES = ['allowed-once', 'rejected', 'cancelled', 'unavailable'];

/** Slash command vocabulary (without the leading slash) for prefix matching. */
const COMMANDS = ['help', 'todo', 'history', 'switch', 'compress', 'stop', 'cron', 'new', 'name', 'reset', 'status'];

/** Per-session prompt section for non-admin users: what they may/may not touch. */
function userBoundaryPrompt(cwd, publicDir, departments = []) {
  const lines = [
    '【企业微信普通用户权限边界】',
    `- 你的用户工作区（可读写）：${cwd}`,
    `- 公共工作区（所有人只读，你不可修改）：${publicDir}`
  ];
  if (departments.length > 0) {
    lines.push('- 已授权你的部门文档目录（只读，不可修改）：');
    for (const dept of departments) lines.push(`    · ${dept.name}：${dept.dir}`);
  }
  lines.push(
    '- 未授权的部门目录、其他用户的工作区、上传目录、会话记录（包括 $DSH_HOME/sessions 下的会话文件）以及 dsh 配置、系统配置，一律禁止读取或查看。',
    '- 你无权对操作系统做任何修改：不得安装/卸载软件、不得运行影响系统的脚本、不得修改系统或服务配置、不得重启/停止系统或任何服务（对工作区和 /tmp 之外的写入，文件沙箱也会强制拒绝）。',
    '- 任务确实需要上述操作时，不要尝试绕过或变通执行，直接告知用户：「该操作需要管理员权限，请联系管理员处理。」'
  );
  return lines.join('\n');
}

/** Per-session prompt section for admins: full access + caution. */
function adminBoundaryPrompt(cwd, departments = []) {
  const lines = [
    '【企业微信管理员权限】',
    '你是管理员（超级用户），拥有完整访问权限。',
    `- 管理会话工作区：${cwd}`,
    '- 可以查看所有用户的工作区、上传目录与会话信息（包括 $DSH_HOME/sessions 下的会话文件）。',
    '- 可以修改 dsh 配置与系统配置、管理服务。'
  ];
  if (departments.length > 0) {
    lines.push('- 部门文档目录（管理员可读写）：');
    for (const dept of departments) lines.push(`    · ${dept.name}：${dept.dir}`);
  }
  lines.push('- 破坏性或影响面大的操作（如重启服务、改动生产配置）前应先向用户确认。');
  return lines.join('\n');
}

/** Per-session prompt section for group chats: shared space, fixed limits. */
function groupBoundaryPrompt(cwd, publicDir) {
  return [
    '【企业微信群聊权限边界】',
    `- 本群的共享工作区（群成员可读写）：${cwd}`,
    `- 公共工作区（所有人只读，不可修改）：${publicDir}`,
    '- 禁止读取或查看任何群成员的私有工作区、上传目录、会话记录（包括 $DSH_HOME/sessions 下的会话文件）以及 dsh 配置、系统配置。',
    '- 本会话无权对操作系统做任何修改：不得安装/卸载软件、不得运行影响系统的脚本、不得修改系统或服务配置、不得重启/停止系统或任何服务（对工作区和 /tmp 之外的写入，文件沙箱也会强制拒绝）。',
    '- 任务确实需要上述操作时，不要尝试绕过或变通执行，直接告知用户：「该操作需要管理员权限，请联系管理员处理。」'
  ].join('\n');
}

export class Bridge {
  constructor(ctx, config) {
    this.ctx = ctx;
    this.config = config;
    /** key (wecom:chatId) -> chat state. */
    this.chats = new Map();
    /** sessionId -> pending reply collector for in-flight turns. */
    this.pending = new Map();
    /** userId -> last known chatId (used for proactive todo reminders). */
    this.userChats = new Map();
    /** Persisted bridge state for todos ({ sent, chats }), loaded at start. */
    this.todoState = undefined;
    /** Absolute path of the shared todo-state file (resolved in start). */
    this.todoStateFile = undefined;
    this.adapter = undefined;
    this.disposeListener = undefined;
    this.stopped = false;
    this.idleTimer = undefined;
    this.reminderTimer = undefined;
    this.reminderRunning = false;
    /** Interactive prompts currently waiting for the user, per chat. */
    this.restoreUserQuestions = undefined;
    this.disposeApprovalListener = undefined;
    this.installTimer = undefined;
    /** Lifetime counters shown in the web status panel (persisted). */
    this.stats = { messagesIn: 0, messagesOut: 0, userIds: [] };
    /** Absolute path of the persisted stats file (resolved in start). */
    this.statsFile = undefined;
    this.statsSaveTimer = undefined;
    /** userId -> live workspace entity (wecom group in the web sidebar). */
    this.workspaceEntities = new Map();
    /** chatId -> live workspace entity for group chats (wecom-group/*). */
    this.groupWorkspaceEntities = new Map();
    /** Session ids attached to a wecom workspace (status panel 总会话数). */
    this.wecomSessions = new Set();
    /** Process start time + web route disposer for the status endpoint. */
    this.startedAt = Date.now();
    this.disposeWebRoute = undefined;
    /** wecom_send_file tool registration disposer. */
    this.disposeSendTool = undefined;
    /** User-level scheduled prompts (/cron), persisted in the plugin state. */
    this.cronJobs = [];
    this.cronStateFile = undefined;
    this.cronTimer = undefined;
    /** chat key -> { id, cwd } of the last live session, persisted so a
     *  restart can resume the previous conversation instead of forking a
     *  brand-new one. */
    this.chatSessionMap = new Map();
  }

  // ------------------------------------------------------------------ life

  async start() {
    const loader = this.ctx.get('loader');
    if (loader?.await) await loader.await();
    // Route approval/ask_user prompts to WeCom before the first agent runs.
    this.installInteractionBridge();
    this.disposeListener = this.ctx.on('session/event', (session, event) => {
      const collector = this.pending.get(session.id);
      if (collector === undefined) return;
      if (event.type === 'assistant/message') {
        const text = assistantText(event.data.message);
        if (text !== '') collector.parts.push(text);
      } else if (event.type === 'turn/end') {
        collector.reason = event.data.reason;
      } else if (event.type === 'tool/call') {
        // Live progress: surface tool activity in the streaming bubble.
        const progress = collector.progress;
        if (progress === undefined) return;
        const data = event.data ?? {};
        const name = data.toolName ?? data.name ?? data.tool ?? '工具';
        const args = typeof data.arguments === 'string' ? data.arguments.replace(/\s+/g, ' ').trim() : '';
        progress.lines.push(`🔧 ${name}${args ? `：${args.slice(0, 60)}` : ''}`);
        this.streamPush(progress);
      } else if (event.type === 'assistant/chunk') {
        // Typewriter preview: remember the model's visible text output so the
        // progress bubble can show what is being written right now.
        const progress = collector.progress;
        if (progress === undefined) return;
        const chunk = event.data?.chunk;
        if (chunk?.type === 'text-delta' && typeof chunk.text === 'string' && chunk.text !== '') {
          progress.draft = (progress.draft + chunk.text).slice(-4_000);
          this.streamPush(progress);
        }
      }
    });

    this.adapter = new WeComAdapter({
      botId: this.config.botId,
      secret: this.config.secret,
      websocketUrl: this.config.websocketUrl,
      // Containment: a bridge bug must never surface as an unhandled
      // rejection — that would take down the whole dsh process.
      onMessage: (input) => {
        Promise.resolve(this.handleMessage(input)).catch((error) => {
          console.error(`[dsh-wecom] message handling failed: ${error instanceof Error ? error.stack : String(error)}`);
        });
      },
      logger: this.ctx.logger
    });
    await this.adapter.start();

    // Ensure the shared public workspace exists (host side; non-admins get
    // read-only access to it through the session sandbox).
    try {
      const baseCwd = resolve(this.config.agent.cwd || process.cwd());
      const publicDir = resolve((this.config.security || {}).publicDir || join(baseCwd, 'public'));
      await mkdir(publicDir, { recursive: true, mode: 0o755 });
    } catch (error) {
      console.error(`[dsh-wecom] public workspace setup failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Ensure configured department directories exist.
    for (const dept of this.allDepartments()) {
      try {
        await mkdir(dept.dir, { recursive: true, mode: 0o755 });
      } catch (error) {
        console.error(`[dsh-wecom] department dir "${dept.name}" setup failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    if (this.config.agent.idleTimeoutMs > 0) {
      this.idleTimer = setInterval(() => this.reapIdle(), Math.min(this.config.agent.idleTimeoutMs, 60_000));
      this.idleTimer.unref?.();
    }

    // Todo reminder loop: periodically scan users' todo files and push
    // proactive WeCom reminders for upcoming items.
    const todoCfg = this.config.todo || {};
    const intervalMs = Math.max(Number(todoCfg.checkIntervalMs) || 300_000, 5_000);
    this.todoStateFile = join(this.resolveWorkspace('').usersRoot, '.wecom-todo-state.json');
    this.todoState = pruneSent(await loadState(this.todoStateFile));
    // Lifetime counters for the web status panel survive restarts.
    this.statsFile = join(this.resolveWorkspace('').usersRoot, '.wecom-bridge-stats.json');
    try {
      const raw = JSON.parse(await readFile(this.statsFile, 'utf8'));
      if (typeof raw === 'object' && raw !== null) {
        this.stats.messagesIn = Number(raw.messagesIn) || 0;
        this.stats.messagesOut = Number(raw.messagesOut) || 0;
        this.stats.userIds = Array.isArray(raw.userIds) ? raw.userIds.filter((id) => typeof id === 'string' && id !== '') : [];
        // chat key -> last live session { id, cwd } — lets a post-restart
        // message resume the previous conversation.
        if (raw.chats && typeof raw.chats === 'object') {
          for (const [key, value] of Object.entries(raw.chats)) {
            if (value && typeof value.id === 'string' && typeof value.cwd === 'string') {
              this.chatSessionMap.set(key, { id: value.id, cwd: value.cwd });
            }
          }
        }
      }
    } catch {
      /* first run or unreadable file: start from zero */
    }
    // User-level scheduled prompts (/cron) — persisted plugin state, never
    // the system cron. Overdue jobs run once on startup.
    this.cronStateFile = join(this.resolveWorkspace('').usersRoot, '.wecom-cron-jobs.json');
    try {
      const raw = JSON.parse(await readFile(this.cronStateFile, 'utf8'));
      this.cronJobs = Array.isArray(raw?.jobs) ? raw.jobs.filter((job) => job && typeof job.id === 'string') : [];
    } catch {
      this.cronJobs = [];
    }
    const cronConfig = this.config.cron || {};
    if (cronConfig.enabled !== false) {
      this.cronTimer = setInterval(() => this.checkCronJobs().catch((error) => {
        console.error(`[dsh-wecom] cron tick failed: ${error instanceof Error ? error.message : String(error)}`);
      }), Math.max(Number(cronConfig.checkIntervalMs) || 30_000, 10_000));
      this.cronTimer.unref?.();
    }
    // The registry only auto-attaches sessions created through the web UI;
    // pull existing (bridge-created) sessions into the wecom groups here.
    // Workspaces are created LAZILY (only users that actually have sessions
    // at the current usersRoot get a group) so empty wecom folders never
    // pile up in the sidebar.
    await this.backfillWecomSessions().catch((error) => {
      console.error(`[dsh-wecom] session backfill failed: ${error instanceof Error ? error.message : String(error)}`);
    });
    // Expose the status snapshot to the web UI at /api/wecom/status (the
    // client half in lib/client.js polls it from the status panel).
    try {
      const webServer = this.ctx.get('webServer');
      if (webServer !== undefined) {
        this.disposeWebRoute = webServer.register({
          kind: 'exact',
          path: '/api/wecom/status',
          handler: (req, res) => this.handleStatusRequest(req, res)
        });
      }
    } catch (error) {
      console.error(`[dsh-wecom] status route registration failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Register the wecom_send_file tool (agent → WeCom file handoff).
    if ((this.config.files || {}).sendEnabled !== false) {
      try {
        const tools = this.ctx.get('tools');
        if (tools !== undefined) {
          this.disposeSendTool = registerSendFileTool(tools, this);
          console.error('[dsh-wecom] wecom_send_file tool registered');
        } else {
          console.error('[dsh-wecom] tools service unavailable; wecom_send_file not registered');
        }
      } catch (error) {
        console.error(`[dsh-wecom] send-file tool registration failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    // Restore the userId -> chatId mapping so reminders survive restarts.
    for (const [userId, chatId] of Object.entries(this.todoState.chats || {})) {
      if (userId && chatId) this.userChats.set(userId, chatId);
    }
    this.reminderTimer = setInterval(() => this.checkTodoReminders().catch((error) => {
      console.error(`[dsh-wecom] todo reminder scan failed: ${error instanceof Error ? error.message : String(error)}`);
    }), intervalMs);
    this.reminderTimer.unref?.();
  }

  stop() {
    this.stopped = true;
    if (this.disposeListener !== undefined) this.disposeListener();
    if (this.disposeWebRoute !== undefined) {
      try {
        this.disposeWebRoute();
      } catch {
        /* containment */
      }
      this.disposeWebRoute = undefined;
    }
    if (this.disposeSendTool !== undefined) {
      try {
        this.disposeSendTool();
      } catch {
        /* containment */
      }
      this.disposeSendTool = undefined;
    }
    if (this.statsSaveTimer !== undefined) {
      clearTimeout(this.statsSaveTimer);
      this.statsSaveTimer = undefined;
      this.persistStats().catch(() => {});
    }
    if (this.cronTimer !== undefined) {
      clearInterval(this.cronTimer);
      this.cronTimer = undefined;
    }
    if (this.idleTimer !== undefined) clearInterval(this.idleTimer);
    if (this.reminderTimer !== undefined) clearInterval(this.reminderTimer);
    this.teardownInteractionBridge();
    try {
      this.adapter?.stop();
    } catch {
      /* containment */
    }
    this.adapter = undefined;
    for (const chat of this.chats.values()) {
      this.abandonPendingInteraction(chat);
      void Promise.resolve(chat.dispose?.()).catch(() => {});
    }
    this.chats.clear();
  }

  // -------------------------------------------------------------- messaging

  /**
   * Entry point called by the adapter for an inbound user message.
   * @param input - { chatId, userId, text, file, reply(content) }.
   *   `file` is { url, aeskey, name?, size? } | undefined (file messages).
   */
  async handleMessage(input) {
    const { chatId, userId, text, file, images, unsupportedType, reply } = input;
    const hasText = typeof text === 'string' && text.trim() !== '';
    const hasImages = Array.isArray(images) && images.length > 0;
    if (!hasText && !file && !hasImages) {
      // Unknown payload (e.g. 合并转发). The adapter logs the shape; give the
      // user explicit feedback instead of silently ignoring the message.
      if (unsupportedType !== undefined && userId) {
        await reply(`⚠️ 暂不支持的消息类型「${unsupportedType}」。请把内容以文字直接发送，或逐条转发文本/图片/文件。`);
      }
      return;
    }

    // Remember the last chat this user talked to us from, so proactive todo
    // reminders can be delivered later. Persist the mapping so it survives
    // bridge restarts.
    if (chatId && userId) {
      const uid = String(userId);
      if (this.userChats.get(uid) !== chatId) {
        this.userChats.set(uid, chatId);
        this.persistTodoState().catch(() => {});
      }
    }

    if (!this.isAllowed(userId)) {
      await reply('⛔ 你没有权限使用此助手 / You are not allowed to use this assistant.');
      return;
    }

    this.stats.messagesIn += 1;
    this.queuePersistStats();

    // Track the user for the status panel (总用户数). Personal wecom
    // workspaces are created lazily by createChat/backfill — never here, or
    // group members who never private-chat would leave empty sidebar folders.
    const uid = String(userId || '');
    if (uid !== '' && !this.stats.userIds.includes(uid)) {
      this.stats.userIds.push(uid);
      this.queuePersistStats();
    }

    if (hasText && text.startsWith('/')) {
      // Command errors must always reach the user — a silent failure here
      // would look like the bot ignoring the command.
      try {
        await this.handleCommand(chatId, text, input);
      } catch (error) {
        const why = error instanceof Error ? error.message : String(error);
        console.error(`[dsh-wecom] command "${text}" failed: ${why}`);
        try {
          await input.reply(`❌ 命令执行失败：${why}`);
        } catch {
          /* containment */
        }
      }
      return;
    }

    // A pending interactive prompt (approval / ask_user_question) in this
    // chat consumes the next text message as its answer instead of starting
    // a new agent turn.
    const liveChat = this.chats.get(`wecom:${chatId}`);
    if (liveChat !== undefined && hasText) {
      if (await this.deliverPendingAnswer(liveChat, text, reply)) return;
    }

    // 纯文件消息（无文字）：保存后把存储路径作为回答。图片不在此列——
    // 纯图片同样进入 agent 回合，让 vision 模型直接查看内容。
    if (file && !hasText && !hasImages) {
      await this.receiveFileOnly(userId, file, reply);
      return;
    }

    const key = `wecom:${chatId}`;
    const chat = await this.getOrCreateChat(key, userId, input.isGroup === true);
    const run = chat.busy.then(() => this.runTurn(chat, input));
    chat.busy = run.catch(() => {});
    await run;
  }

  /**
  /**
   * Download, decrypt and durably store one inbound WeCom image, sniffing
   * the raster format off the decrypted bytes (WeCom declares no format).
   * @returns {Promise<{ path: string, name: string, size: number, mediaType: string, data: string }>}
   *   `data` is the canonical base64 encoding for the attachment admission.
   */
  async saveInboundImage(usersRoot, userId, image, index) {
    const filesConfig = this.config.files || {};
    if (filesConfig.enabled === false) {
      throw new Error('文件接收已禁用 (files.enabled=false)');
    }
    const root = resolve(filesConfig.dir || join(usersRoot, '.wecom-uploads'));
    const dir = join(root, sanitizeFileName(String(userId), 'user'));
    const { buffer } = await downloadFile(image.url, {
      timeoutMs: Number(filesConfig.timeoutMs) || 30_000,
      maxBytes: Number(filesConfig.maxBytes) || 100 * 1024 * 1024
    });
    const decrypted = image.aeskey ? decryptFile(buffer, image.aeskey) : buffer;
    const mediaType = sniffImageMediaType(decrypted);
    if (mediaType === undefined) throw new Error('无法识别的图片格式');
    const name = `wecom-image-${Date.now()}-${index + 1}.${mediaType.split('/')[1]}`;
    const path = await saveUnique(dir, name, decrypted);
    return { path, name, size: decrypted.length, mediaType, data: decrypted.toString('base64') };
  }

  // ---------------------------------------------------------------- status

  /** Live status snapshot served at /api/wecom/status and shown in the web panel. */
  statusSnapshot() {
    let pendingInteractions = 0;
    for (const chat of this.chats.values()) {
      if (chat.pendingQuestion !== undefined || chat.pendingApproval !== undefined) pendingInteractions += 1;
    }
    return {
      ok: true,
      connected: this.adapter?.isConnected?.() ?? false,
      connectedSec: this.adapter?.connectedSec?.() ?? 0,
      totalUsers: this.stats.userIds.length,
      activeChats: this.chats.size,
      totalSessions: this.wecomSessions.size,
      messagesIn: this.stats.messagesIn,
      messagesOut: this.stats.messagesOut,
      pendingInteractions,
      startedAt: this.startedAt,
      uptimeSec: Math.round((Date.now() - this.startedAt) / 1000)
    };
  }

  /**
   * Register the user's workspace directory as a web-sidebar workspace titled
   * "wecom", so their sessions (historical and future — membership is the
   * session header's canonical cwd) group under a wecom folder instead of
   * 未分组. Per-user directories stay the sandbox write boundary, so each
   * user gets their own folder.
   * @returns the live workspace entity, or undefined while the registry is
   *   unavailable.
   */
  async ensureUserWorkspace(userId) {
    const cached = this.workspaceEntities.get(userId);
    if (cached !== undefined) return cached;
    const registry = this.ctx.get('workspaceRegistry');
    if (registry === undefined) return undefined;
    const { cwd } = this.resolveWorkspace(userId);
    await this.ensureWorkspace(cwd);
    // Title carries the user id (wecom/<userId>) so the flat sidebar reads
    // as one wecom family with one folder per user — dsh has no sub-groups.
    const title = `wecom/${userId}`;
    const entity = await registry.create(cwd, title);
    try {
      // create() keeps an existing record's title; align it if it predates
      // the title convention (setTitle is durable and replayable).
      if (entity.title !== title) await entity.setTitle(title);
      await this.orderWecomWorkspaces(registry, entity, title);
    } catch {
      /* ordering/retitle is cosmetic — grouping itself already works */
    }
    this.workspaceEntities.set(userId, entity);
    return entity;
  }

  /**
   * Keep wecom/<userId> workspaces sorted by title in the sidebar (the
   * durable registry order otherwise puts newly created ones on top).
   */
  async orderWecomWorkspaces(registry, entity, title) {
    const siblings = registry
      .list()
      .filter((w) => w.id !== entity.id && typeof w.title === 'string' && w.title.startsWith('wecom/'));
    const anchor = siblings
      .slice()
      .sort((a, b) => (a.title < b.title ? -1 : 1))
      .find((w) => w.title > title);
    if (anchor !== undefined) await registry.insertBefore(entity.workspaceId, anchor.workspaceId);
    else await registry.insertBefore(entity.workspaceId);
  }

  /** Which wecom user's directory a session cwd belongs to, if any. */
  wecomUserForCwd(cwd) {
    if (typeof cwd !== 'string' || cwd === '') return undefined;
    const normalized = cwd.replace(/\/+$/, '');
    for (const uid of this.stats.userIds) {
      if (normalized === this.resolveWorkspace(uid).cwd) return uid;
    }
    return undefined;
  }

  /** Root directory holding per-group-chat shared workspaces. */
  groupsRootDir() {
    const security = this.config.security || {};
    return resolve(security.groupsRoot || join(dirname(this.resolveWorkspace('').usersRoot), 'groups'));
  }

  /** All configured department entries ({ name, dir, userids }). */
  allDepartments() {
    const list = (this.config.security || {}).departments;
    return Array.isArray(list) ? list.filter((dept) => dept && typeof dept.dir === 'string' && dept.dir !== '') : [];
  }

  /** Department entries the given user is a member of. */
  userDepartments(userId) {
    const uid = String(userId || '');
    if (uid === '') return [];
    return this.allDepartments().filter((dept) => Array.isArray(dept.userids) && dept.userids.includes(uid));
  }

  /** Shared workspace directory of one group chat. */
  groupWorkspaceDir(chatId) {
    return join(this.groupsRootDir(), sanitizeFileName(String(chatId), 'group'));
  }

  /**
   * Register (or reuse) the workspace entity of a group chat: a shared
   * directory titled wecom-group/<chatId> that every member's group session
   * uses as cwd, independent of any member's private workspace.
   */
  async ensureGroupWorkspace(chatId, cwd, title) {
    const cached = this.groupWorkspaceEntities.get(chatId);
    if (cached !== undefined) return cached;
    const registry = this.ctx.get('workspaceRegistry');
    if (registry === undefined) return undefined;
    await this.ensureWorkspace(cwd);
    const entity = await registry.create(cwd, title);
    this.groupWorkspaceEntities.set(chatId, entity);
    return entity;
  }

  /**
   * Attach existing bridge-created sessions to their user's wecom workspace.
   * Membership lives in the workspace record and only web-UI-created sessions
   * get attached by the host, so the backfill is what makes the sidebar's
   * wecom groups show history. attachSession() itself re-validates the cwd.
   */
  async backfillWecomSessions() {
    const persistence = this.ctx.get('sessionPersistence');
    if (persistence === undefined) return;
    const headers = await persistence.list();
    const groupsRoot = this.groupsRootDir().replace(/\/+$/, '');
    for (const header of headers) {
      const id = String(header.id);
      if (this.wecomSessions.has(id)) continue;
      const cwd = typeof header.cwd === 'string' ? header.cwd.replace(/\/+$/, '') : undefined;
      if (cwd === undefined) continue;
      let entity;
      const uid = this.wecomUserForCwd(cwd);
      if (uid !== undefined) {
        entity = await this.ensureUserWorkspace(uid);
      } else if (cwd === groupsRoot || cwd.startsWith(`${groupsRoot}/`)) {
        const name = basename(cwd);
        entity = await this.ensureGroupWorkspace(name, cwd, `wecom-group/${name}`);
      }
      if (entity === undefined) continue;
      try {
        await entity.attachSession(header.id);
        this.wecomSessions.add(id);
      } catch {
        /* not a wecom session (cwd mismatch etc.) — skip */
      }
    }
  }

  /** HTTP handler for the status route (registered in start). */
  handleStatusRequest(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end();
      return;
    }
    const body = JSON.stringify(this.statusSnapshot());
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(body);
  }

  /** Count one outbound WeCom message (reply chunk, panel push, reminder). */
  countOutbound() {
    this.stats.messagesOut += 1;
    this.queuePersistStats();
  }

  /** Debounced stats persist: bursts of messages collapse into one write. */
  queuePersistStats() {
    if (this.statsSaveTimer !== undefined) return;
    this.statsSaveTimer = setTimeout(() => {
      this.statsSaveTimer = undefined;
      this.persistStats().catch(() => {});
    }, 1_000);
    this.statsSaveTimer.unref?.();
  }

  /** Write the lifetime counters and the chat→session map to disk. */
  async persistStats() {
    if (this.statsFile === undefined) return;
    const payload = {
      ...this.stats,
      chats: Object.fromEntries(this.chatSessionMap)
    };
    await writeFile(this.statsFile, `${JSON.stringify(payload, null, 2)}\n`);
  }

  /** Persist /cron job definitions (plugin state, never the system cron). */
  async saveCronJobs() {
    if (this.cronStateFile === undefined) return;
    await writeFile(this.cronStateFile, `${JSON.stringify({ jobs: this.cronJobs }, null, 2)}\n`);
  }

  /** Save a standalone file message and reply with its storage path. */
  async receiveFileOnly(userId, file, reply) {
    const { cwd, usersRoot } = this.resolveWorkspace(userId);
    try {
      await this.ensureWorkspace(cwd);
      const saved = await this.saveInboundFile(usersRoot, userId, file);
      await reply(`✅ 文件已上传到：${saved.path}`);
    } catch (error) {
      const why = error instanceof Error ? error.message : String(error);
      try {
        await reply(`❌ 文件接收失败: ${why}`);
      } catch {
        /* containment */
      }
    }
  }

  isAllowed(userId) {
    const allow = this.config.allowedUserIds || [];
    return allow.length === 0 || allow.includes(String(userId));
  }

  async handleCommand(chatId, text, input) {
    const [rawCmd, ...rest] = text.split(/\s+/);
    const wanted = rawCmd.slice(1).toLowerCase();
    let cmd = wanted;
    if (!COMMANDS.includes(cmd)) {
      // Shortest-unique-prefix matching: /hi resolves to /history, /to to
      // /todo. An ambiguous prefix (e.g. /st → switch|status) is rejected
      // with the candidate list instead of guessing.
      const matches = COMMANDS.filter((candidate) => candidate.startsWith(wanted));
      if (matches.length === 1) {
        cmd = matches[0];
      } else if (matches.length === 0) {
        await input.reply(`未知命令: ${rawCmd}（输入 /help 查看可用命令）`);
        return;
      } else {
        await input.reply(`⚠️ 前缀 "${rawCmd}" 对应多个命令：${matches.map((candidate) => `/${candidate}`).join('、')}，请输入完整命令。`);
        return;
      }
    }
    switch (cmd) {
      case 'help':
        await input.reply(
          [
            '📖 可用命令（支持前缀简写，如 /hi = /history）:',
            '  /help    - 显示帮助',
            '  /new     - 立即新建一个会话',
            '  /name    - 给会话命名：/name [编号] <名称>',
            '  /todo    - 查看你的待办事宜',
            '  /history - 列出本聊天的历史会话',
            '  /switch N- 切换到 /history 列出的第 N 个会话',
            '  /compress- 压缩当前会话上下文（长对话后释放空间）',
            '  /stop    - 停止当前正在执行的任务',
            '  /cron    - 定时任务：add/list/exec/del/enable/disable',
            '             例：/cron add 日报 09:00 总结我的待办',
            '                 /cron add 巡检 every 30m 检查服务状态并汇报',
            '  /reset   - 清空当前会话上下文，重新开始',
            '  /status  - 显示运行状态',
            '直接发送消息即可与助手对话。'
          ].join('\n')
        );
        break;
      case 'todo':
        await this.showTodos(input.userId, input.reply);
        break;
      case 'history':
        await this.handleHistoryCommand(chatId, input);
        break;
      case 'switch':
        await this.handleSwitchCommand(chatId, rest, input);
        break;
      case 'compress':
        await this.handleCompressCommand(chatId, input);
        break;
      case 'stop':
        await this.handleStopCommand(chatId, input);
        break;
      case 'cron':
        await this.handleCronCommand(chatId, rest, input);
        break;
      case 'new':
        await this.handleNewCommand(chatId, input);
        break;
      case 'name':
        await this.handleNameCommand(chatId, rest, input);
        break;
      case 'reset': {
        const key = `wecom:${chatId}`;
        const chat = this.chats.get(key);
        if (chat !== undefined) {
          this.chats.delete(key);
          this.chatSessionMap.delete(key);
          this.queuePersistStats();
          this.abandonPendingInteraction(chat);
          await Promise.resolve(chat.dispose?.()).catch(() => {});
          await input.reply('🔄 已清空上下文，开始新的会话。');
        } else {
          await input.reply('当前没有活跃会话。');
        }
        break;
      }
      case 'status': {
        const agents = this.ctx.get('agents');
        const { isAdmin } = this.resolveWorkspace(input.userId);
        const depts = this.userDepartments(input.userId);
        await input.reply(
          [
            '📊 状态:',
            `  当前身份: ${isAdmin ? '👑 管理员' : '普通用户'}`,
            `  活跃 IM 会话: ${this.chats.size}`,
            `  活跃 dsh 智能体: ${agents?.list?.().length ?? '未知'}`,
            `  授权部门目录: ${depts.length > 0 ? depts.map((dept) => `${dept.name}(${dept.dir})`).join('、') : '无'}`,
            '  通道: 企业微信 (WebSocket)'
          ].join('\n')
        );
        break;
      }
      default:
        await input.reply(`未知命令: /${cmd}（输入 /help 查看可用命令）`);
    }
  }

  // ---------------------------------------------------- compress / stop

  /** /compress — manually compact the chat's session context. */
  async handleCompressCommand(chatId, input) {
    const chat = this.chats.get(`wecom:${chatId}`);
    if (chat === undefined) {
      await input.reply('📭 当前没有活跃会话。');
      return;
    }
    if (chat.turnActive) {
      await input.reply('⏳ 当前有任务正在执行，完成后再压缩。');
      return;
    }
    const compaction = this.ctx.get('compaction');
    if (compaction === undefined) {
      await input.reply('⚠️ 压缩服务不可用（部署未启用 compaction）。');
      return;
    }
    const thinking = await input.reply('🗜️ 正在压缩会话上下文…');
    try {
      const result = await compaction.compactNow(chat.agent, undefined, `wecom-compact-${randomUUID()}`);
      if (result === null) {
        await input.reply('📭 暂无可压缩的历史。');
        return;
      }
      await input.reply(`✅ 压缩完成：${result.shadowedSeqs.length} 条历史被归档（约 ${result.shadowedTokenCount} tokens）。`);
    } catch (error) {
      const code = error?.code;
      const why = code === 'busy' ? '有压缩正在进行或会话未空闲'
        : code === 'cancelled' ? '已取消'
        : code === 'summary' ? '无法生成有效摘要'
        : error instanceof Error ? error.message : String(error);
      console.error(`[dsh-wecom] compress failed: ${why}`);
      await input.reply(`❌ 压缩失败：${why}`);
    }
  }

  /** /stop — abort the chat's running turn (user cancellation cause). */
  async handleStopCommand(chatId, input) {
    const chat = this.chats.get(`wecom:${chatId}`);
    if (chat === undefined) {
      await input.reply('📭 当前没有活跃会话。');
      return;
    }
    if (!chat.turnActive) {
      await input.reply('当前没有正在执行的任务。');
      return;
    }
    chat.agent.cancel({ kind: 'user' });
    await input.reply('🛑 已发送停止指令，正在终止当前任务…');
  }

  // ---------------------------------------------------------------- cron

  /**
   * /cron — user-level scheduled prompts, stored in the plugin's own state
   * file (never the system cron). Each job belongs to the chat where it was
   * created; when due, the task text runs as a normal turn and the answer is
   * delivered back to that chat.
   *
   *   /cron add <名称> <HH:MM | every Nm|h> <任务>
   *   /cron list | exec <名称> | del <名称> | enable <名称> | disable <名称>
   */
  async handleCronCommand(chatId, rest, input) {
    const sub = (rest[0] ?? 'list').toLowerCase();
    const args = rest.slice(1);
    const { userId } = input;
    const key = `wecom:${chatId}`;
    const jobs = this.cronJobs.filter((job) => job.chatId === chatId);

    if (sub === 'add') {
      const tokens = args.slice();
      const name = tokens.shift();
      if (name === undefined) {
        await input.reply([
          '用法：/cron add <名称> <HH:MM | every N分钟> <任务>',
          '例：/cron add 日报 09:00 总结我的待办并发给我',
          '　　/cron add 巡检 every 30m 检查服务状态并汇报'
        ].join('\n'));
        return;
      }
      const schedule = this.parseCronScheduleFrom(tokens);
      if (schedule === undefined) {
        await input.reply('⚠️ 无法解析时间。支持：HH:MM（每天定时）或 every <N>m / every <N>h（间隔，最短 5 分钟）。');
        return;
      }
      const task = tokens.join(' ').trim();
      if (task === '') {
        await input.reply('⚠️ 缺少任务内容。例：/cron add 日报 09:00 总结我的待办并发给我');
        return;
      }
      if (jobs.some((job) => job.name === name)) {
        await input.reply(`⚠️ 已存在同名任务「${name}」，换个名称或先 /cron del ${name}。`);
        return;
      }
      const job = {
        id: randomUUID().slice(0, 8),
        name,
        ownerId: String(userId || ''),
        chatId,
        isGroup: input.isGroup === true,
        task,
        kind: schedule.kind,
        everyMinutes: schedule.everyMinutes,
        at: schedule.at,
        enabled: true,
        createdAt: Date.now(),
        lastRunAt: undefined,
        nextRunAt: schedule.nextRunAt
      };
      this.cronJobs.push(job);
      await this.saveCronJobs();
      await input.reply(`✅ 定时任务已创建：\n- 名称：${name}\n- 计划：${this.describeCronSchedule(job)}\n- 任务：${task}\n- 下次执行：${this.cronTimeString(job.nextRunAt)}`);
      return;
    }

    if (sub === 'list') {
      if (jobs.length === 0) {
        await input.reply('📭 本聊天还没有定时任务。用 /cron add 创建。');
        return;
      }
      const lines = ['⏰ 定时任务：'];
      for (const job of jobs) {
        lines.push(`- [${job.enabled ? '✅' : '⏸'}] ${job.name}（id:${job.id}）${this.describeCronSchedule(job)}，下次执行：${job.enabled ? cronTimeString(job.nextRunAt) : '—'}`);
      }
      await input.reply(lines.join('\n'));
      return;
    }

    if (sub === 'exec' || sub === 'del' || sub === 'enable' || sub === 'disable') {
      const target = args[0];
      if (target === undefined) {
        await input.reply(`用法：/cron ${sub} <名称或id>`);
        return;
      }
      const job = this.findCronJob(jobs, target);
      if (job === undefined) {
        await input.reply(`⚠️ 未找到任务「${target}」。用 /cron list 查看现有任务。`);
        return;
      }
      if (sub === 'exec') {
        await input.reply(`🚀 立即执行「${job.name}」…`);
        this.runCronJob(job).catch((error) => {
          console.error(`[dsh-wecom] cron exec failed: ${error instanceof Error ? error.message : String(error)}`);
        });
        return;
      }
      if (sub === 'del') {
        this.cronJobs = this.cronJobs.filter((candidate) => candidate !== job);
        await this.saveCronJobs();
        await input.reply(`🗑️ 已删除任务「${job.name}」。`);
        return;
      }
      job.enabled = sub === 'enable';
      if (job.enabled) job.nextRunAt = this.nextCronRun(job);
      await this.saveCronJobs();
      await input.reply(`${job.enabled ? '✅ 已启用' : '⏸ 已停用'}任务「${job.name}」。`);
      return;
    }

    await input.reply(`未知子命令：${sub}。可用：add / list / exec / del / enable / disable。`);
  }

  /** Exact id → exact name → unique prefix. */
  findCronJob(jobs, target) {
    const key = String(target).trim();
    return jobs.find((job) => job.id === key)
      ?? jobs.find((job) => job.name === key)
      ?? (jobs.filter((job) => job.name.startsWith(key) || job.id.startsWith(key)).length === 1
        ? jobs.find((job) => job.name.startsWith(key) || job.id.startsWith(key))
        : undefined);
  }

  /**
   * Parse "/cron add" schedule tokens: HH:MM (daily) or every <N>m|h.
   * Consumed tokens are removed from the front of the remaining array.
   */
  parseCronScheduleFrom(tokens) {
    if (tokens[0] === 'every') {
      const m = String(tokens[1] ?? '').match(/^(\d+)(m|min|分钟|h|小时)$/i);
      if (m === null) return undefined;
      const minutes = Number.parseInt(m[1], 10) * (m[2].toLowerCase().startsWith('h') ? 60 : 1);
      if (!(minutes >= 5)) return undefined;
      tokens.splice(0, 2);
      return { kind: 'every', everyMinutes: minutes, nextRunAt: Date.now() + minutes * 60_000 };
    }
    const m = String(tokens[0] ?? '').match(/^(\d{1,2}):(\d{2})$/);
    if (m === null) return undefined;
    const hours = Number.parseInt(m[1], 10);
    const minutes = Number.parseInt(m[2], 10);
    if (hours > 23 || minutes > 59) return undefined;
    tokens.splice(0, 1);
    const next = new Date();
    next.setHours(hours, minutes, 0, 0);
    if (next.getTime() <= Date.now()) next.setDate(next.getDate() + 1);
    return { kind: 'daily', at: `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`, nextRunAt: next.getTime() };
  }

  nextCronRun(job) {
    if (job.kind === 'every') return Date.now() + job.everyMinutes * 60_000;
    const next = new Date();
    const [hours, minutes] = String(job.at).split(':').map((part) => Number.parseInt(part, 10));
    next.setHours(hours, minutes, 0, 0);
    if (next.getTime() <= Date.now()) next.setDate(next.getDate() + 1);
    return next.getTime();
  }

  describeCronSchedule(job) {
    return job.kind === 'every' ? `每 ${job.everyMinutes} 分钟` : `每天 ${job.at}`;
  }

  cronTimeString(ts) {
    if (typeof ts !== 'number') return '—';
    const d = new Date(ts);
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  }

  /**
   * Scheduler tick: run every due enabled job. A job whose chat is busy
   * (running turn or waiting on the user) is deferred to the next tick.
   */
  async checkCronJobs() {
    const now = Date.now();
    const due = this.cronJobs.filter((job) => job.enabled && (job.nextRunAt ?? 0) <= now);
    for (const job of due) {
      const chat = this.chats.get(`wecom:${job.chatId}`);
      if (chat !== undefined && (chat.turnActive || chat.pendingQuestion !== undefined || chat.pendingApproval !== undefined)) {
        job.nextRunAt = now + 60_000; // busy chat: retry shortly
        continue;
      }
      job.lastRunAt = now;
      job.nextRunAt = this.nextCronRun(job);
      await this.saveCronJobs();
      await this.runCronJob(job).catch((error) => {
        console.error(`[dsh-wecom] cron job "${job.name}" failed: ${error instanceof Error ? error.message : String(error)}`);
      });
    }
  }

  /**
   * Execute one cron job's task as a normal turn in its chat, delivering the
   * answer back to WeCom. Reuses the standard turn pipeline.
   */
  async runCronJob(job) {
    const input = {
      chatId: job.chatId,
      userId: job.ownerId,
      isGroup: job.isGroup,
      text: `⏰ 定时任务「${job.name}」，请执行：${job.task}`,
      headers: undefined,
      reply: async (content) => {
        this.countOutbound();
        await this.adapter?.sendMessage(job.chatId, content);
      }
    };
    const key = `wecom:${job.chatId}`;
    const chat = await this.getOrCreateChat(key, job.ownerId, job.isGroup);
    const run = chat.busy.then(() => this.runTurn(chat, input));
    chat.busy = run.catch(() => {});
    await run;
  }

  // -------------------------------------------------------- new / name

  /** /new — close the current session (if any) and open a fresh one now. */
  async handleNewCommand(chatId, input) {
    const key = `wecom:${chatId}`;
    const chat = this.chats.get(key);
    if (chat !== undefined) {
      if (chat.turnActive) {
        await input.reply('⏳ 当前有任务正在执行，完成后再新建会话（或先 /stop）。');
        return;
      }
      this.chats.delete(key);
      this.chatSessionMap.delete(key);
      this.queuePersistStats();
      this.abandonPendingInteraction(chat);
      await chat.dispose();
    }
    const fresh = await this.getOrCreateChat(key, input.userId, input.isGroup === true);
    await input.reply(`🆕 已新建会话，直接发送消息即可开始。`);
  }

  /**
   * /name [序号] <名称> — rename a session so it is easy to recognize in
   * /history and the web sidebar. Without a 序号 it renames the CURRENT
   * session; a 序号 must match a /history entry.
   */
  async handleNameCommand(chatId, rest, input) {
    const chat = this.chats.get(`wecom:${chatId}`);
    if (chat === undefined) {
      await input.reply('📭 当前没有活跃会话，先发一条消息开始对话。');
      return;
    }
    if (chat.turnActive) {
      await input.reply('⏳ 当前有任务正在执行，完成后再命名。');
      return;
    }
    const tokens = rest.filter((token) => token !== '');
    if (tokens.length === 0) {
      await input.reply('用法：/name <名称>，或 /name <会话编号> <名称>（编号见 /history）。例：/name 部署排查');
      return;
    }
    let targetSessionId = String(chat.agent.session.id);
    let label = '当前会话';
    let titleTokens = tokens;
    if (tokens.length >= 2 && /^\d+$/.test(tokens[0])) {
      const n = Number.parseInt(tokens[0], 10);
      const cache = chat.historyCache;
      if (cache === undefined || cache.length === 0) {
        await input.reply('请先发送 /history 获取会话列表，再按编号命名。');
        return;
      }
      if (!(n >= 1 && n <= cache.length)) {
        await input.reply(`会话编号超出范围（1-${cache.length}），请先发送 /history 查看。`);
        return;
      }
      targetSessionId = cache[n - 1];
      label = `会话 ${n}`;
      titleTokens = tokens.slice(1);
    }
    const title = titleTokens.join(' ').trim();
    if (title === '') {
      await input.reply('⚠️ 名称不能为空。例：/name 部署排查');
      return;
    }
    const targetLive = this.ctx.agents.get(SessionId(targetSessionId));
    const sessionTitle = this.ctx.get('sessionTitle');
    try {
      if (targetLive !== undefined) {
        // 已加载的会话：走标准命名接口（user 来源会固定标题，不被自动起名覆盖）。
        if (sessionTitle === undefined) throw new Error('命名服务不可用');
        sessionTitle.rename(targetLive.session, title);
      } else {
        // 未加载的历史会话：直接向持久化日志追加 user 来源的标题事件，
        // 恢复/侧栏展示时按同样的 fold 读取，无需先切过去。
        const persistence = this.ctx.get('sessionPersistence');
        if (persistence === undefined) throw new Error('会话存储不可用');
        const inspection = await persistence.inspect(SessionId(targetSessionId));
        const events = inspection?.events ?? [];
        const lastSeq = events.length > 0 ? Number(events[events.length - 1].seq ?? 0) : 0;
        await persistence.append(SessionId(targetSessionId), [{
          type: 'session/title',
          seq: lastSeq + 1,
          time: Date.now(),
          data: { title, messageSeqs: [], source: { kind: 'user' } }
        }]);
      }
      await input.reply(`✅ ${label}已命名为「${title}」。`);
    } catch (error) {
      const why = error instanceof Error ? error.message : String(error);
      await input.reply(`❌ 命名失败：${why}`);
    }
  }

  // ------------------------------------------------- session history cmds

  /**
   * /history — list this chat's historical sessions (all sessions whose cwd
   * is this chat's workspace), newest first, numbered for /switch.
   */
  async handleHistoryCommand(chatId, input) {
    const chat = this.chats.get(`wecom:${chatId}`);
    if (chat === undefined) {
      await input.reply('📭 当前没有活跃会话，先发一条消息开始对话。');
      return;
    }
    const persistence = this.ctx.get('sessionPersistence');
    if (persistence === undefined) {
      await input.reply('⚠️ 会话存储不可用，无法列出历史。');
      return;
    }
    const cwd = String(chat.cwd).replace(/\/+$/, '');
    const mine = (await persistence.list())
      .filter((header) => typeof header.cwd === 'string' && header.cwd.replace(/\/+$/, '') === cwd)
      .sort((a, b) => b.createdAt - a.createdAt);
    if (mine.length === 0) {
      await input.reply('📭 还没有历史会话。');
      return;
    }
    const current = String(chat.agent.session.id);
    const lines = ['📚 历史会话（回复 /switch 编号 切换）：'];
    const cache = [];
    for (const [index, header] of mine.entries()) {
      const id = String(header.id);
      cache.push(id);
      const title = (await this.sessionTitle(id)) ?? '(未命名)';
      const date = new Date(header.createdAt);
      const ds = `${date.getMonth() + 1}-${date.getDate()} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
      const mark = id === current ? '  ← 当前' : '';
      lines.push(`${index + 1}. ${title}（${ds}）${mark}`);
    }
    chat.historyCache = cache;
    for (const chunk of splitText(lines.join('\n'), this.config.agent.maxMessageLength)) {
      await input.reply(chunk);
    }
  }

  /**
   * /switch N — resume the Nth session from the last /history listing as
   * this chat's live agent. Refused while a turn is still running.
   */
  async handleSwitchCommand(chatId, rest, input) {
    const chat = this.chats.get(`wecom:${chatId}`);
    if (chat === undefined) {
      await input.reply('📭 当前没有活跃会话，先发一条消息开始对话。');
      return;
    }
    if (chat.turnActive) {
      await input.reply('⏳ 当前有任务正在执行，完成后再切换会话。');
      return;
    }
    const cache = chat.historyCache;
    if (cache === undefined || cache.length === 0) {
      await input.reply('请先发送 /history 获取会话列表。');
      return;
    }
    const n = Number.parseInt((rest[0] ?? '').trim(), 10);
    if (!(n >= 1 && n <= cache.length)) {
      await input.reply(`用法：/switch 编号（1-${cache.length}）。可先发送 /history 查看。`);
      return;
    }
    const targetId = cache[n - 1];
    if (targetId === String(chat.agent.session.id)) {
      await input.reply('当前已在该会话中。');
      return;
    }
    const previousId = String(chat.agent.session.id);
    this.abandonPendingInteraction(chat);
    this.pending.delete(chat.agent.session.id);
    await Promise.resolve(chat.dispose?.()).catch(() => {});
    try {
      await this.resumeChatAgent(chat, targetId);
      const title = (await this.sessionTitle(targetId)) ?? '(未命名)';
      await input.reply(`✅ 已切换到会话 ${n}：「${title}」，继续对话即可。`);
    } catch (error) {
      // Switch failed: fall back to the previous live agent if possible.
      try {
        if (String(chat.agent?.session?.id) === targetId) await this.resumeChatAgent(chat, previousId);
      } catch {
        /* containment */
      }
      const why = error instanceof Error ? error.message : String(error);
      console.error(`[dsh-wecom] session switch failed: ${why}`);
      await input.reply(`❌ 切换失败：${why}`);
    }
  }

  /** Best-effort human label for a session: generated title, else first user text. */
  async sessionTitle(sessionId) {
    try {
      const persistence = this.ctx.get('sessionPersistence');
      if (persistence === undefined) return undefined;
      const inspection = await persistence.inspect(SessionId(sessionId));
      const events = inspection?.events ?? [];
      for (let index = events.length - 1; index >= 0; index -= 1) {
        const event = events[index];
        if (event.type === 'session/title' && typeof event.data?.title === 'string' && event.data.title !== '') {
          return String(event.data.title).slice(0, 60);
        }
      }
      for (const event of events) {
        if (event.type !== 'user/message') continue;
        const content = event.data?.message?.content;
        if (!Array.isArray(content)) continue;
        const text = content.find((block) => block.type === 'text' && typeof block.text === 'string' && block.text.trim() !== '');
        if (text !== undefined) return String(text.text).trim().slice(0, 60);
      }
    } catch {
      /* containment */
    }
    return undefined;
  }

  /**
   * Resume one persisted session as this chat's live agent, reapplying the
   * chat's model selection, preset and boundary prompt. If the target is
   * already live (an earlier /switch left it registered), it is adopted as
   * instead of resumed. The previous agent is drained after the new one
   * is committed — it used to stay registered forever, which made any later
   * switch back to it fail with "cannot prepare session while it is live".
   * The caller owns error handling.
   */
  async resumeChatAgent(chat, targetSessionId) {
    const ctx = this.ctx;
    const defaultModel = ctx.get('agentDefaultModel');
    const selection = defaultModel?.currentSelection?.();
    if (selection === undefined) throw new Error('agentDefaultModel service is unavailable');
    const provider = this.config.agent.provider || selection.provider;
    const model = this.config.agent.model || selection.model;
    const security = this.config.security || {};
    const baseCwd = resolve(this.config.agent.cwd || process.cwd());
    const publicDir = resolve(security.publicDir || join(baseCwd, 'public'));
    const boundaryText = chat.isGroupChat
      ? groupBoundaryPrompt(chat.cwd, publicDir)
      : chat.isAdmin
        ? adminBoundaryPrompt(chat.cwd)
        : userBoundaryPrompt(chat.cwd, publicDir);
    const presets = ctx.get('agentPresets');
    let resolvedPresetId;
    if (presets !== undefined && this.config.agent.preset) {
      resolvedPresetId = (await presets.resolve(this.config.agent.preset)).id;
    }
    const previousDispose = chat.dispose;
    const previousSessionId = String(chat.agent?.session?.id ?? '');
    const existingLive = ctx.agents.get(SessionId(targetSessionId));
    let handle;
    if (existingLive !== undefined) {
      // Already live from an earlier switch — adopt it instead of failing.
      handle = { agent: existingLive, dispose: async () => {} };
    } else {
      handle = await ctx.agents.resume({
        resumeSessionId: SessionId(targetSessionId),
        agentOptions: { provider, model },
        setup: async (agentCtx) => {
          installModelSelection(agentCtx, { current: { provider, model }, assembled: undefined });
          if (presets !== undefined && resolvedPresetId) {
            await presets.mount(agentCtx, resolvedPresetId);
          }
          const scope = agentCtx.agent?.ctx ?? agentCtx;
          scope.systemPrompt?.section?.({
            name: 'wecom:identity-boundary',
            order: 10,
            text: boundaryText
          });
        }
      });
    }
    await handle.agent.whenIdle();
    if (chat.isGroupChat || !chat.isAdmin) {
      try {
        setApprovalPolicy(handle.agent.session, 'never');
      } catch {
        /* containment */
      }
    } else {
      try {
        setSandboxMode(handle.agent.session, 'danger-full-access');
      } catch {
        /* containment */
      }
    }
    chat.agent = handle.agent;
    chat.dispose = handle.dispose;
    chat.busy = Promise.resolve();
    chat.pendingQuestion = undefined;
    chat.pendingApproval = undefined;
    chat.turnActive = false;
    this.wecomSessions.add(String(handle.agent.session.id));
    // The switched-to session becomes this chat's persistent identity.
    this.chatSessionMap.set(chat.key, { id: String(handle.agent.session.id), cwd: chat.cwd });
    this.queuePersistStats();
    // Drain the previous agent AFTER the new one is committed — leaving it
    // registered made any later switch back fail with "while it is live".
    if (previousSessionId !== '' && previousSessionId !== String(handle.agent.session.id)) {
      try {
        previousDispose?.();
      } catch {
        /* containment */
      }
    }
    return handle;
  }

  // ------------------------------------------------------ interaction bridge

  /**
   * Route dsh's two interactive seams to WeCom so prompts surface in the
   * chat instead of silently blocking on the web UI:
   *
   * - `approval/request` (dsh-user-approval waterfall): a prepended answerer
   *   claims asks from WeCom-owned agents (returned outcome = claim); every
   *   other agent falls through via `next()` to the host's own answerers.
   * - `userQuestions` (dsh-user-questions): the seam holds ONE active UI
   *   provider, claimed by the host api-proxy for the web UI. The provider
   *   slot is wrapped with a property trap: asks from WeCom-owned agents are
   *   answered in WeCom, all others delegate to the wrapped web provider.
   *   The trap reads as `undefined` until a provider is registered, so the
   *   host's registerProvider() keeps working whichever mounts first.
   *
   * Both services may mount after this plugin starts, so installation polls
   * until they appear.
   */
  installInteractionBridge() {
    const attempt = () => {
      if (this.stopped) return;
      let missing = false;
      if (this.restoreUserQuestions === undefined) {
        const uq = this.ctx.get('userQuestions');
        if (uq !== undefined) {
          this.wrapUserQuestions(uq);
        } else {
          missing = true;
        }
      }
      if (this.disposeApprovalListener === undefined) {
        const approval = this.ctx.get('approval');
        if (approval !== undefined) {
          // `true` = prepend: WeCom answerer sits outermost in the waterfall,
          // so it decides for WeCom sessions before the host's answerer.
          this.disposeApprovalListener = this.ctx.on('approval/request', (req, next) => this.onApprovalRequest(req, next), true);
        } else {
          missing = true;
        }
      }
      if (missing) {
        this.installTimer = setTimeout(attempt, 2_000);
        this.installTimer.unref?.();
      } else {
        console.error('[dsh-wecom] interaction bridge installed (ask_user + approval → WeCom)');
      }
    };
    attempt();
  }

  /** Undo the interaction wiring (bridge stop). */
  teardownInteractionBridge() {
    if (this.installTimer !== undefined) {
      clearTimeout(this.installTimer);
      this.installTimer = undefined;
    }
    if (this.disposeApprovalListener !== undefined) {
      try {
        this.disposeApprovalListener();
      } catch {
        /* containment */
      }
      this.disposeApprovalListener = undefined;
    }
    if (this.restoreUserQuestions !== undefined) {
      try {
        this.restoreUserQuestions();
      } catch {
        /* containment */
      }
      this.restoreUserQuestions = undefined;
    }
  }

  /** Map a live agent to its WeCom chat state, if the bridge owns it. */
  chatForAgent(agent) {
    const sessionId = agent?.session?.id;
    if (sessionId === undefined) return undefined;
    for (const chat of this.chats.values()) {
      if (chat.agent.session.id === sessionId) return chat;
    }
    return undefined;
  }

  /**
   * Wrap the single user-questions provider slot with a router: asks from
   * WeCom-owned agents are answered in WeCom, everything else is delegated
   * to the provider registered by the host (the web UI). The slot is
   * intercepted with a property trap so the host can still register its
   * provider after us — the trap reads as `undefined` until a provider is
   * actually present, keeping registerProvider()'s duplicate guard intact.
   */
  wrapUserQuestions(service) {
    const state = { inner: service.provider, wrapper: undefined };
    const bridge = this;
    state.wrapper = {
      async ask(request) {
        const chat = bridge.chatForAgent(request.agent);
        if (chat !== undefined) return bridge.askViaWecom(chat, request);
        if (state.inner !== undefined && typeof state.inner.ask === 'function') {
          return state.inner.ask(request);
        }
        const error = new Error('no user-questions provider is registered');
        error.code = 'NO_PROVIDER';
        throw error;
      }
    };
    const original = Object.getOwnPropertyDescriptor(service, 'provider');
    Object.defineProperty(service, 'provider', {
      configurable: true,
      enumerable: true,
      get() {
        return state.inner === undefined ? undefined : state.wrapper;
      },
      set(value) {
        state.inner = value;
      }
    });
    this.restoreUserQuestions = () => {
      if (service.provider !== state.wrapper) return; // slot re-defined elsewhere; leave it
      if (original !== undefined) {
        Object.defineProperty(service, 'provider', { ...original, value: state.inner });
      } else {
        delete service.provider;
      }
    };
  }

  /** approval/request answerer: claim WeCom asks, defer everything else. */
  onApprovalRequest(req, next) {
    const chat = this.chatForAgent(req.agent);
    if (chat === undefined) return next();
    return this.approvalViaWecom(chat, req);
  }

  /**
   * Ask the WeCom user to decide one approval request. The approval service
   * wraps this inside its durable audit pair and normalizes the outcome.
   */
  async approvalViaWecom(chat, req) {
    if (req.signal?.aborted) return 'cancelled';
    const outcome = await new Promise((resolve) => {
      const onAbort = () => resolve('cancelled');
      req.signal?.addEventListener('abort', onAbort, { once: true });
      chat.pendingApproval = {
        req,
        resolve: (value) => {
          req.signal?.removeEventListener('abort', onAbort);
          if (chat.pendingApproval?.req === req) chat.pendingApproval = undefined;
          resolve(value);
        }
      };
      this.deliverText(chat, this.formatApproval(req)).catch(() => {});
      const progress = chat.progress;
      if (progress !== undefined) {
        progress.lines.push('❓ 等待你在企微里回复「允许/拒绝」…');
        this.streamPush(progress, true);
      }
    });
    return APPROVAL_OUTCOMES.includes(outcome) ? outcome : 'unavailable';
  }

  /**
   * Answer one ask_user_question request through WeCom. Resolves with the
   * AskUserQuestionAnswer, or rejects with a coded error (ASK_ABORTED /
   * ASK_CANCELLED) so the model sees the tool fail — mirroring the semantics
   * of the web provider.
   */
  askViaWecom(chat, request) {
    const fail = (code, message) => {
      const error = new Error(message);
      error.code = code;
      return error;
    };
    return new Promise((resolve, reject) => {
      if (request.signal?.aborted) {
        reject(fail('ASK_ABORTED', 'ask_user_question was aborted before the user answered'));
        return;
      }
      const onAbort = () => {
        if (chat.pendingQuestion?.request === request) chat.pendingQuestion = undefined;
        reject(fail('ASK_ABORTED', 'ask_user_question was aborted before the user answered'));
      };
      request.signal?.addEventListener('abort', onAbort, { once: true });
      chat.pendingQuestion = {
        request,
        settle: (answer) => {
          request.signal?.removeEventListener('abort', onAbort);
          if (chat.pendingQuestion?.request === request) chat.pendingQuestion = undefined;
          resolve(answer);
        },
        cancel: (code, message) => {
          request.signal?.removeEventListener('abort', onAbort);
          if (chat.pendingQuestion?.request === request) chat.pendingQuestion = undefined;
          reject(fail(code, message));
        }
      };
      this.deliverText(chat, this.formatQuestions(request)).catch(() => {});
      const qProgress = chat.progress;
      if (qProgress !== undefined) {
        qProgress.lines.push('❓ 等待你在企微里回答上面的问题…');
        this.streamPush(qProgress, true);
      }
    });
  }

  /** Push a proactive WeCom message for a chat, splitting long text. */
  async deliverText(chat, text) {
    for (const chunk of splitText(text, this.config.agent.maxMessageLength)) {
      this.countOutbound();
      await this.adapter?.sendMessage(chat.chatId, chunk);
    }
  }

  formatQuestions(request) {
    const questions = request.questions || [];
    const lines = ['❓ 智能体需要你的输入'];
    questions.forEach((question, index) => {
      const many = questions.length > 1;
      if (many) lines.push('');
      lines.push(`${many ? `${index + 1}. ` : ''}${question.header ? `【${question.header}】` : ''}${question.question}`);
      (question.options || []).forEach((option, optionIndex) => {
        lines.push(`   ${optionIndex + 1}. ${option.label}${option.description ? ` — ${option.description}` : ''}`);
      });
    });
    lines.push('');
    lines.push(questions.length > 1
      ? '请按「序号: 答案」逐行回复（可回复选项序号或自定义文字），回复「取消」放弃。'
      : '回复选项序号或直接输入你的答案；回复「取消」放弃本次提问。');
    return lines.join('\n');
  }

  formatApproval(req) {
    const lines = ['🔐 权限确认', `工具：${req.toolName}`];
    if (req.reason) lines.push(`原因：${req.reason}`);
    lines.push('', '回复「允许」继续执行，「拒绝」阻止，「取消」放弃。');
    return lines.join('\n');
  }

  /**
   * Route a non-command inbound text to the chat's pending interactive
   * prompt. @returns true when the message was consumed as an answer.
   */
  async deliverPendingAnswer(chat, text, reply) {
    if (chat.pendingApproval !== undefined) {
      const pending = chat.pendingApproval;
      const t = text.trim();
      if (/^(允许|同意|批准|可以|确认|好|是|yes|y|allow|ok)$/i.test(t)) {
        pending.resolve('allowed-once');
        await reply('✅ 已允许，继续执行…');
      } else if (/^(拒绝|不允许|否|不行|不要|deny|no|n)$/i.test(t)) {
        pending.resolve('rejected');
        await reply('⛔ 已拒绝。');
      } else if (/^(取消|放弃|cancel)$/i.test(t)) {
        pending.resolve('cancelled');
        await reply('↩️ 已取消。');
      } else {
        await reply('请回复「允许」或「拒绝」（也可回复「取消」）。');
      }
      return true;
    }
    if (chat.pendingQuestion !== undefined) {
      const parsed = this.parseQuestionAnswer(chat.pendingQuestion, text);
      if (parsed.action === 'cancel') {
        chat.pendingQuestion.cancel('ASK_CANCELLED', 'the user cancelled ask_user_question');
        await reply('↩️ 已取消本次提问。');
      } else if (parsed.action === 'reprompt') {
        await reply(`🤔 ${parsed.message}`);
      } else {
        chat.pendingQuestion.settle({ answers: parsed.answers });
        await reply('✅ 已收到回答，继续处理中…');
      }
      return true;
    }
    return false;
  }

  parseQuestionAnswer(entry, text) {
    const trimmed = text.trim();
    if (/^(取消|放弃|cancel|算了)$/i.test(trimmed)) return { action: 'cancel' };
    const questions = entry.request.questions || [];
    if (questions.length === 1) {
      const answer = this.matchQuestionAnswer(questions[0], trimmed);
      if (answer !== undefined) return { action: 'resolve', answers: [answer] };
      return {
        action: 'reprompt',
        message: '没有匹配到答案，请回复选项序号、选项文字，或直接输入你的答案。'
      };
    }
    // Multiple questions: expect one "序号: 答案" line per question.
    const answers = new Array(questions.length);
    const missing = new Set(questions.map((_, index) => index));
    for (const line of trimmed.split(/\r?\n/)) {
      const m = line.trim().match(/^(\d+)\s*[:：.、)）]\s*(.+)$/);
      if (m === null) continue;
      const index = Number.parseInt(m[1], 10) - 1;
      if (!(index >= 0 && index < questions.length)) continue;
      const answer = this.matchQuestionAnswer(questions[index], m[2].trim());
      if (answer === undefined) continue;
      answers[index] = answer;
      missing.delete(index);
    }
    if (missing.size > 0) {
      return {
        action: 'reprompt',
        message: `还有 ${missing.size} 个问题未回答，请按「序号: 答案」逐行回复，例如：\n1: 是\n2: PostgreSQL`
      };
    }
    return { action: 'resolve', answers };
  }

  /** Match one answer text against a question's options; fallback = custom. */
  matchQuestionAnswer(question, text) {
    if (text === '') return undefined;
    const options = question.options || [];
    if (options.length > 0) {
      const num = text.match(/^(\d+)\s*[.、)）]?\s*$/);
      const letter = text.toUpperCase().match(/^([A-Z])\s*[.、)）]?\s*$/);
      let picked;
      if (num !== null) {
        const index = Number.parseInt(num[1], 10) - 1;
        picked = index >= 0 && index < options.length ? options[index] : undefined;
      } else if (letter !== null) {
        const index = letter[1].charCodeAt(0) - 65;
        picked = index < options.length ? options[index] : undefined;
      } else {
        picked = options.find((option) => option.label === text)
          ?? options.find((option) => option.label.includes(text) || text.includes(option.label));
      }
      if (picked !== undefined) return { id: question.id, selected: [picked.label] };
    }
    return { id: question.id, selected: [], custom: text };
  }

  /** Fail any interactive prompt still pending when a turn ends. */
  abandonPendingInteraction(chat) {
    if (chat.pendingQuestion !== undefined) {
      const pending = chat.pendingQuestion;
      chat.pendingQuestion = undefined;
      pending.cancel?.('ASK_ABORTED', 'the turn ended before the question was answered');
    }
    if (chat.pendingApproval !== undefined) {
      const pending = chat.pendingApproval;
      chat.pendingApproval = undefined;
      pending.resolve?.('cancelled');
    }
  }

  // ---------------------------------------------------------------- todos

  /** Resolve the absolute path of a user's todo Markdown file. */
  todoFilePath(userId) {
    const { cwd } = this.resolveWorkspace(userId);
    const todoCfg = this.config.todo || {};
    const name = todoCfg.file || DEFAULT_TODO_FILE;
    return join(cwd, name);
  }

  /** `/todo` command: reply with the user's todo file content. */
  async showTodos(userId, reply) {
    const file = this.todoFilePath(userId);
    let raw;
    try {
      raw = await readFile(file, 'utf8');
    } catch {
      raw = '';
    }
    const body = raw.trim();
    if (body === '') {
      await reply(`📋 你还没有待办事宜。\n可让助手在个人目录创建“${DEFAULT_TODO_FILE}”，或在待办事项里加上日期时间（如 \`2026-09-05 20:00\`），系统会按时提醒（默认提前30分钟，可用“提前1小时/提前N分钟”自定义）。`);
      return;
    }
    const lines = body.split(/\r?\n/);
    for (const chunk of splitText(lines.join('\n'), this.config.agent.maxMessageLength)) {
      await reply(`📋 你的待办事宜:\n\n${chunk}`);
    }
  }

  /**
   * Periodic scan: for every user we've seen, parse their todo file and push
   * a proactive WeCom reminder for items whose reminder window just opened.
   * Reminder time = item datetime − lead (explicit `提前N分钟/小时`, else the
   * configured default, normally 30 minutes). Each item is reminded once.
   */
  async checkTodoReminders() {
    if (this.reminderRunning) return; // no overlapping scans
    this.reminderRunning = true;
    const todoCfg = this.config.todo || {};
    const defaultLead = Math.max(Number(todoCfg.defaultRemindMinutes) || 30, 1);
    // Fire as soon as we're within `grace` minutes of the reminder point;
    // the scan only runs every checkIntervalMs, so early is acceptable and
    // the reminder must never land after the event itself.
    const graceMs = Math.max(Number(todoCfg.graceMinutes) || 5, 1) * 60_000;

    try {
      if (this.todoState === undefined) {
        this.todoStateFile = join(this.resolveWorkspace('').usersRoot, '.wecom-todo-state.json');
        this.todoState = pruneSent(await loadState(this.todoStateFile));
      }
      const now = Date.now();
      let changed = false;

      for (const [userId, chatId] of this.userChats) {
        const items = await loadTodoItems(this.todoFilePath(userId), defaultLead);
        for (const item of items) {
          const remindAt = item.when.getTime() - item.remindBeforeMin * 60_000;
          // Reminder window: [remindAt − grace, when). Never after the event,
          // at most `grace` minutes before the nominal reminder point.
          if (now < remindAt - graceMs || now >= item.when.getTime()) continue;
          const key = reminderKey(userId, item);
          if (this.todoState.sent[key] !== undefined) continue;
          this.todoState.sent[key] = now;
          changed = true;
          const fmt = `${item.when.getFullYear()}-${String(item.when.getMonth() + 1).padStart(2, '0')}-${String(item.when.getDate()).padStart(2, '0')} ${String(item.when.getHours()).padStart(2, '0')}:${String(item.when.getMinutes()).padStart(2, '0')}`;
          const leftMin = Math.max(0, Math.round((item.when.getTime() - now) / 60_000));
          this.countOutbound();
          await this.adapter?.sendMessage(chatId, [
            '⏰ 待办提醒',
            `- ${item.text}`,
            `🕐 时间：${fmt}（约 ${leftMin} 分钟后）`,
            '可发送 /todo 查看全部待办事宜。'
          ].join('\n'));
        }
      }

      if (changed) await this.persistTodoState();
    } finally {
      this.reminderRunning = false;
    }
  }

  /** Persist the todo bridge state ({ sent, chats }) to disk. */
  async persistTodoState() {
    if (this.todoState === undefined) return;
    if (this.todoStateFile === undefined) {
      this.todoStateFile = join(this.resolveWorkspace('').usersRoot, '.wecom-todo-state.json');
    }
    this.todoState.chats = Object.fromEntries(this.userChats);
    pruneSent(this.todoState);
    await saveState(this.todoStateFile, this.todoState);
  }

  // ----------------------------------------------------------- workspaces

  /**
   * Resolve the role and session workspace for a WeCom user.
   * EVERY user — admins included — gets a dedicated private workspace
   * <usersRoot>/<userId> (default <agent.cwd>/users/<userId>) that is fully
   * separated from the public workspace (publicDir). Admins additionally get
   * the danger-full-access sandbox; non-admins keep workspace-write, so their
   * session cwd is a hard write boundary.
   * @returns {{ isAdmin: boolean, cwd: string, publicDir: string, usersRoot: string }}
   */
  resolveWorkspace(userId) {
    const security = this.config.security || {};
    const adminIds = security.adminIds || [];
    const isAdmin = adminIds.includes(String(userId));
    const baseCwd = resolve(this.config.agent.cwd || process.cwd());
    const publicDir = resolve(security.publicDir || join(baseCwd, 'public'));
    const usersRoot = resolve(security.usersRoot || join(baseCwd, 'users'));
    const userDir = sanitizeFileName(String(userId), 'user');
    return { isAdmin, cwd: join(usersRoot, userDir), publicDir, usersRoot };
  }

  /** Create the per-user workspace (host side, outside any sandbox). */
  async ensureWorkspace(cwd) {
    await mkdir(cwd, { recursive: true, mode: 0o700 });
  }

  // ----------------------------------------------------------------- chats

  async getOrCreateChat(key, userId, isGroupChat = false) {
    let chat = this.chats.get(key);
    if (chat === undefined) {
      chat = await this.createChat(key, userId, isGroupChat);
      this.chats.set(key, chat);
    }
    chat.lastUsed = Date.now();
    return chat;
  }

  async createChat(key, userId, isGroupChat = false) {
    const ctx = this.ctx;
    const defaultModel = ctx.get('agentDefaultModel');
    const selection = defaultModel?.currentSelection?.();
    if (selection === undefined) throw new Error('agentDefaultModel service is unavailable');
    const provider = this.config.agent.provider || selection.provider;
    const model = this.config.agent.model || selection.model;
    const chatId = key.slice('wecom:'.length);
    const security = this.config.security || {};
    // Group sessions run at a FIXED privilege level regardless of who speaks
    // first: workspace-write with no approvals. An admin saying the first
    // word in a group must never hand every member a full-access agent.
    const isAdmin = !isGroupChat && (security.adminIds || []).includes(String(userId));
    const baseCwd = resolve(this.config.agent.cwd || process.cwd());
    const publicDir = resolve(security.publicDir || join(baseCwd, 'public'));
    let cwd;
    let workspaceTitle;
    let boundaryText;
    // 部门文档目录：私聊按发送者的授权列表；群聊会话不授予（群成员身份混杂）。
    const departments = isGroupChat ? [] : this.userDepartments(userId);
    if (isGroupChat) {
      cwd = this.groupWorkspaceDir(chatId);
      workspaceTitle = `wecom-group/${chatId}`;
      boundaryText = groupBoundaryPrompt(cwd, publicDir);
    } else {
      cwd = this.resolveWorkspace(userId).cwd;
      workspaceTitle = `wecom/${userId}`;
      boundaryText = isAdmin
        ? adminBoundaryPrompt(cwd, this.allDepartments())
        : userBoundaryPrompt(cwd, publicDir, departments);
    }
    await this.ensureWorkspace(cwd);
    const presetId = this.config.agent.preset || undefined;

    // Resolve + mount the preset inside setup, exactly like the host api-proxy
    // does for browser-created sessions (`meta.agentPreset` alone is not
    // consumed; the caller must call presets.mount in setup).
    const presets = ctx.get('agentPresets');
    let resolvedPresetId;
    if (presets !== undefined && presetId) {
      resolvedPresetId = (await presets.resolve(presetId)).id;
    }

    const injectBoundary = security.boundaryPrompt !== false;

    const setup = async (agentCtx) => {
      installModelSelection(agentCtx, {
        current: { provider, model },
        assembled: undefined
      });
      if (presets !== undefined && resolvedPresetId) {
        await presets.mount(agentCtx, resolvedPresetId);
      }
      if (injectBoundary) {
        // Per-agent prompt section: scoped to this session's layer.
        const scope = agentCtx.agent?.ctx ?? agentCtx;
        scope.systemPrompt?.section?.({
          name: 'wecom:identity-boundary',
          order: 10,
          text: boundaryText
        });
      }
    };

    // Resume the chat's last session across restarts when its stored cwd
    // still matches this chat's workspace; otherwise start fresh.
    const stored = this.chatSessionMap.get(key);
    let handle;
    let resumed = false;
    if (stored !== undefined && stored.cwd === cwd) {
      try {
        handle = await ctx.agents.resume({
          resumeSessionId: SessionId(stored.id),
          agentOptions: { provider, model },
          setup
        });
        resumed = true;
      } catch (error) {
        console.error(`[dsh-wecom] resume stored session ${stored.id} failed, creating a new one: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    if (!resumed) {
      const sessionId = SessionId(`wecom-${randomUUID()}`);
      handle = await ctx.agents.create({
        sessionId,
        meta: { cwd, agentPreset: resolvedPresetId },
        agentOptions: { provider, model },
        setup
      });
    }
    await handle.agent.whenIdle();
    const liveSessionId = String(handle.agent.session.id);
    this.chatSessionMap.set(key, { id: liveSessionId, cwd });
    this.queuePersistStats();

    // Attach the new session to its wecom workspace (user or group) so it
    // shows up in the sidebar group, and count it in the status panel.
    try {
      const entity = isGroupChat
        ? await this.ensureGroupWorkspace(chatId, cwd, workspaceTitle)
        : await this.ensureUserWorkspace(userId);
      if (entity !== undefined) {
        await entity.attachSession(liveSessionId);
        this.wecomSessions.add(liveSessionId);
      }
    } catch (error) {
      console.error(`[dsh-wecom] session attach failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    if (isGroupChat || !isAdmin) {
      // Groups AND non-admin private sessions: close the escalation channel
      // entirely. The approval policy 'never' makes every sandbox-escalation
      // request auto-REJECT, so the model can never talk its way past the
      // workspace-write file sandbox (system changes, service restarts,
      // software installs are confined or refused; the boundary prompt
      // directs users to an admin).
      try {
        setApprovalPolicy(handle.agent.session, 'never');
      } catch (error) {
        console.error(`[dsh-wecom] setApprovalPolicy failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    } else {
      // Private admin session: full-access sandbox. The sandbox/mode event is
      // log-only and takes effect on the session's next confined call.
      try {
        setSandboxMode(handle.agent.session, 'danger-full-access');
      } catch (error) {
        console.error(`[dsh-wecom] setSandboxMode failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    return {
      key,
      chatId: key.slice('wecom:'.length),
      userId,
      isGroupChat,
      agent: handle.agent,
      dispose: handle.dispose,
      busy: Promise.resolve(),
      lastUsed: Date.now(),
      isAdmin,
      cwd,
      publicDir,
      /** Department dirs this chat may read (private: the user's; group: none). */
      deptDirs: departments.map((dept) => ({ name: dept.name, dir: dept.dir })),
      // Inbound-file uploads land under `<usersRoot>/.wecom-uploads/<sender>/`.
      // Group sessions keep that layout INSIDE the group dir so the files stay
      // readable by the group session's sandbox (its cwd is the group dir).
      usersRoot: isGroupChat ? cwd : this.resolveWorkspace(userId).usersRoot,
      /** ask_user_question prompt waiting for this chat's answer. */
      pendingQuestion: undefined,
      /** approval prompt waiting for this chat's decision. */
      pendingApproval: undefined,
      /** Whether a turn is currently executing (guards /switch). */
      turnActive: false,
      /** Session ids from the last /history listing (index 0 = entry 1). */
      historyCache: undefined
    };
  }

  // ------------------------------------------------------------ streaming

  /**
   * Create the live progress bubble for one turn: a WeCom stream message
   * created immediately (so the user sees action right away), refreshed on
   * tool activity, and sealed with the final answer at turn end.
   * Gateway rules: all frames pass through the inbound callback's headers,
   * one stream id per bubble, 10-minute max lifetime, 30 msgs/min per chat
   * (hence the 3s throttle). Returns undefined when streaming is off.
   */
  createStreamProgress(input) {
    const progressConfig = this.config.progress || {};
    if (progressConfig.enabled === false) return undefined;
    if (input.headers === undefined || typeof input.headers !== 'object') return undefined;
    const progress = {
      headers: input.headers,
      streamId: `stream-${randomUUID()}`,
      startedAt: Date.now(),
      lines: [],
      /** Tail of the model's visible text output (typewriter preview). */
      draft: '',
      lastPush: 0,
      finished: false,
      broken: false
    };
    this.streamPush(progress, true);
    return progress;
  }

  /** Compose the visible content of the progress bubble. */
  buildProgressContent(progress) {
    const elapsed = Math.max(0, Math.round((Date.now() - progress.startedAt) / 1000));
    const lines = [`🤔 正在处理…（${elapsed} 秒）`];
    for (const line of progress.lines.slice(-5)) lines.push(line);
    if (progress.draft !== undefined && progress.draft !== '') {
      // Live typewriter preview of the answer being written (tail only).
      const tail = progress.draft.slice(-300).replace(/\n{3,}/g, '\n\n');
      lines.push('', `✍️ ${tail}`);
    }
    return lines.join('\n');
  }

  /**
   * Throttled refresh of the progress bubble (force bypasses the throttle).
   * Past 9.5 minutes the stream is sealed with a handoff note — the gateway
   * kills streams at 10 minutes — and the final answer goes out as normal
   * proactive messages.
   */
  streamPush(progress, force = false) {
    if (progress === undefined || progress.finished || progress.broken) return;
    const now = Date.now();
    if (!force && now - progress.lastPush < 3_000) return;
    if (now - progress.startedAt > 9.5 * 60_000) {
      progress.finished = true;
      const ok = this.adapter?.replyStreamFrame(
        progress.headers,
        progress.streamId,
        `${this.buildProgressContent(progress)}\n⏳ 任务仍在进行，完成后将单独发送结果。`,
        true
      );
      if (!ok) progress.broken = true;
      return;
    }
    progress.lastPush = now;
    const ok = this.adapter?.replyStreamFrame(progress.headers, progress.streamId, this.buildProgressContent(progress), false);
    if (!ok) progress.broken = true;
  }

  /**
   * Seal the stream bubble with the final content.
   * @returns {boolean} true when the bubble was delivered (caller can skip
   *   the proactive reply), false when streaming was off/broken/dead.
   */
  finishStream(progress, content) {
    if (progress === undefined || progress.finished || progress.broken) return false;
    progress.finished = true;
    return this.adapter?.replyStreamFrame(progress.headers, progress.streamId, content, true) === true;
  }

  async runTurn(chat, input) {
    const { text, reply, file, userId } = input;
    const hasText = typeof text === 'string' && text.trim() !== '';
    const sessionId = chat.agent.session.id;
    // Live progress bubble: one WeCom stream message created up-front,
    // refreshed on tool activity, sealed with the final answer.
    const progress = this.createStreamProgress(input);
    chat.progress = progress;
    chat.turnActive = true;
    const collector = { parts: [], reason: undefined, progress };
    this.pending.set(sessionId, collector);
    try {
      const blocks = [];
      const imageMentions = [];
      let fileWarning = '';
      if (file) {
        try {
          const saved = await this.saveInboundFile(chat.usersRoot, userId, file);
          blocks.push({ type: 'text', text: saved.mention });
          // 文件保存成功后，把存储路径直接作为回答发回企业微信。
          await reply(`✅ 文件已上传到：${saved.path}`);
        } catch (error) {
          const why = error instanceof Error ? error.message : String(error);
          if (hasText) {
            fileWarning = `⚠️ 文件${file.name ? ` ${file.name}` : ''}接收失败（${why}），仅处理文字部分。\n\n`;
          } else {
            await reply(`❌ 文件接收失败: ${why}`);
            return;
          }
        }
      }
      let textBlock = `${fileWarning}${hasText ? text.trim() : ''}`.trim();
      // Images: save to disk (path mention) and attach as durable vision
      // blocks via the standard attachments seam — capped per message.
      const images = Array.isArray(input.images) ? input.images.slice(0, 6) : [];
      let droppedImages = 0;
      for (const [index, image] of images.entries()) {
        try {
          const saved = await this.saveInboundImage(chat.usersRoot, userId, image, index);
          const ref = (await admitEncodedImages(this.ctx.attachments, [{
            type: 'image',
            mediaType: saved.mediaType,
            data: saved.data,
            name: saved.name
          }]))[0];
          blocks.unshift({ type: 'image', attachment: ref });
          imageMentions.push(`🖼️ 收到图片：${saved.path}`);
        } catch (error) {
          droppedImages += 1;
          console.error(`[dsh-wecom] image ${index + 1} handling failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      if (images.length > 6) droppedImages += images.length - 6;
      const imageWarning = droppedImages > 0 ? `⚠️ 有 ${droppedImages} 张图片未能处理。\n\n` : '';
      const mentionBlock = imageMentions.length > 0 ? `${imageMentions.join('\n')}\n\n` : '';
      // Bare image (no caption): still open a turn so the vision model sees
      // the picture instead of just archiving it.
      if (textBlock === '' && images.length > 0) {
        textBlock = '（用户发来了图片，未附文字。请查看图片并简要描述你看到的内容。）';
      }
      const finalText = `${imageWarning}${mentionBlock}${textBlock}`.trim();
      if (finalText !== '') blocks.push({ type: 'text', text: finalText });
      if (blocks.length === 0) return;

      chat.agent.followup(
        createUserMessage({
          content: blocks,
          // kind 'user' (not a plugin/relay source) so the message surfaces
          // as a first-class user row in the web transcript — it IS user
          // input, just arriving through WeCom.
          source: { kind: 'user' }
        })
      );
      await chat.agent.whenIdle();
      await this.ctx.sessions.flush(chat.agent.session);
      const answer = collector.parts.join('\n\n').trim();
      const reason = collector.reason;
      if (reason?.kind === 'error') {
        const err = reason.error;
        const msg = `⚠️ 出错了: ${err.code}: ${err.message}`;
        // Stream still alive → seal the bubble with the error (one message).
        if (this.finishStream(progress, msg)) return;
        await reply(msg);
        return;
      }
      if (answer === '') {
        if (this.finishStream(progress, '✅ 已完成。（无文本回复）')) return;
        await reply('(无文本回复)');
        return;
      }
      const chunks = splitText(answer, this.config.agent.maxMessageLength);
      if (chunks.length === 1) {
        // Single bubble: seal the live stream with the final answer.
        if (this.finishStream(progress, chunks[0])) return;
        this.countOutbound();
        await reply(chunks[0]);
        return;
      }
      this.finishStream(progress, '✅ 回复较长，分条发送如下：');
      for (const chunk of chunks) {
        this.countOutbound();
        await reply(chunk);
      }
    } catch (error) {
      const msg = `❌ 执行失败: ${error instanceof Error ? error.message : String(error)}`;
      // Seal the live progress bubble with the error when streaming is up;
      // otherwise fall back to a proactive message.
      try {
        if (!this.finishStream(collector.progress, msg)) await reply(msg);
      } catch {
        /* containment */
      }
    } finally {
      this.pending.delete(sessionId);
      chat.progress = undefined;
      chat.turnActive = false;
      // The turn ended; fail any interactive prompt still waiting on the user
      // (normal flow settles them earlier, this only covers aborted turns).
      this.abandonPendingInteraction(chat);
    }
  }

  // ------------------------------------------------------- file send tool

  /**
   * Execute the wecom_send_file tool: validate the requested path against
   * the chatting user's allowed roots (own workspace + public workspace,
   * resolved through realpath so traversal cannot escape), then upload to
   * the WeCom gateway and push it to the chat.
   * @returns {Promise<{ ok: boolean, detail: string }>} model-facing result.
   */
  async handleSendFileRequest(agent, args, signal) {
    const deny = (detail) => ({ ok: false, detail });
    try {
      const chat = this.chatForAgent(agent);
      if (chat === undefined) return deny('当前会话不是企业微信会话，无法发送文件。');
      const filesConfig = this.config.files || {};
      if (filesConfig.sendEnabled === false) return deny('文件发送功能已禁用。');
      const rawPath = typeof args.path === 'string' ? args.path.trim() : '';
      if (rawPath === '') return deny('缺少参数 path（要发送的文件的绝对路径）。');
      const maxBytes = Number(filesConfig.maxSendBytes) || 48 * 1024 * 1024;

      // Path policy: the file must live under the session's workspace —
      // the user's private dir for 1:1 chats, the shared group dir for
      // group chats — or the public workspace or one of the user's
      // authorized department directories. realpath first, so symlink
      // and `..` traversal cannot escape the allow-list.
      const roots = [
        String(chat.cwd).replace(/\/+$/, ''),
        String(chat.publicDir).replace(/\/+$/, ''),
        ...(chat.deptDirs ?? []).map((dept) => String(dept.dir).replace(/\/+$/, ''))
      ];
      let real;
      try {
        real = await realpath(rawPath);
      } catch {
        return deny(`文件不存在或不可访问：${rawPath}`);
      }
      const inside = roots.some((root) => real === root || real.startsWith(`${root}/`));
      if (!inside) {
        return deny('仅允许发送你自己工作区目录或公共工作区目录内的文件，其他路径一律拒绝。');
      }
      const stat = await fsStat(real).catch(() => undefined);
      if (stat === undefined || !stat.isFile()) return deny('目标路径不是普通文件。');
      if (stat.size > maxBytes) {
        return deny(`文件过大（${stat.size} 字节），发送上限为 ${maxBytes} 字节（企微网关单文件上限约 50MB）。`);
      }

      if (signal?.aborted) return deny('任务已取消，文件未发送。');

      // Outbound-file approval gate: only SENSITIVE files need an admin's
      // decision (code archives, source files, configs/secrets, anything
      // big). Plain documents/images pass through. The requester is told
      // where the approval is pending.
      if (!chat.isAdmin && this.isSendApprovalRequired() && this.isSensitiveOutboundFile(real, stat.size)) {
        const decision = await this.requestSendApproval(chat, real, stat.size, args, signal);
        if (!decision.allowed) return deny(decision.reason);
      }

      const buffer = await readFile(real);
      const name = basename(real);
      if (this.adapter === undefined) return deny('企业微信连接不可用，文件未发送。');
      const uploaded = await this.adapter.uploadMedia(buffer, { type: 'file', filename: name });
      this.countOutbound();
      await this.adapter.sendMediaMessage(chat.chatId, 'file', uploaded.media_id);
      const caption = typeof args.caption === 'string' ? args.caption.trim() : '';
      if (caption !== '') {
        this.countOutbound();
        await this.adapter.sendMessage(chat.chatId, caption);
      }
      return { ok: true, detail: `已把 ${name}（${stat.size} 字节）发送到企业微信当前聊天。` };
    } catch (error) {
      return deny(`发送失败：${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // ------------------------------------------------- outbound approval gate

  /** Whether outbound file sends from non-admins need admin approval. */
  isSendApprovalRequired() {
    const security = this.config.security || {};
    if (security.sendApproval === false) return false;
    return (security.adminIds || []).length > 0;
  }

  /** Primary admin chat key for approval requests. */
  adminChatKey() {
    const admins = (this.config.security || {}).adminIds || [];
    const adminId = admins[0];
    return adminId !== undefined ? `wecom:${adminId}` : undefined;
  }

  /**
   * Heuristic sensitivity check for outbound files — the filter keeps the
   * approval gate proportional: only likely-code/secret/large payloads
   * need an admin, everything else flows without friction.
   *
   * Sensitive when ANY of:
   *  - archive (code bundles travel packed: zip/gz/tgz/…)
   *  - known source/code extension (js/ts/py/java/go/rs/c/…)
   *  - config/secret profile (.env, *.config, *.conf, *.yaml, *.pem, *.key…)
   *  - database dump (*.sql, *.db, *.sqlite)
   *  - larger than sendApprovalMaxDirectBytes (default 5MB)
   *  - no recognizable extension at all (unknown binary)
   * NOT sensitive: documents (pdf/doc/docx/xls/xlsx/ppt/pptx/txt/md/csv),
   * images, audio/video.
   */
  isSensitiveOutboundFile(realPath, size) {
    const security = this.config.security || {};
    const maxDirect = Number(security.sendApprovalMaxDirectBytes) || 5 * 1024 * 1024;
    if (size > maxDirect) return true;
    const name = basename(realPath).toLowerCase();
    const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : '';
    if (ext === '') return true; // unknown payload: treat as sensitive
    const ARCHIVES = new Set(['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'jar', 'war']);
    const CODE = new Set(['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'java', 'go', 'rs', 'c', 'h', 'cpp', 'hpp', 'cc', 'cs', 'php', 'rb', 'swift', 'kt', 'scala', 'sh', 'bash', 'ps1', 'bat', 'cmd', 'vue', 'svelte', 'html', 'htm', 'css', 'scss', 'less', 'sql', 'pl', 'lua', 'r', 'm', 'dart', 'groovy']);
    const CONFIG = new Set(['env', 'ini', 'cfg', 'conf', 'config', 'yaml', 'yml', 'toml', 'properties', 'xml', 'json', 'pem', 'key', 'crt', 'csr', 'pfx', 'p12', 'htpasswd', 'npmrc', 'netrc']);
    const DB = new Set(['sql', 'db', 'sqlite', 'sqlite3', 'dump', 'bak']);
    const SAFE = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'txt', 'md', 'csv', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'mp3', 'wav', 'mp4', 'mov', 'avi', 'eml', 'msg']);
    if (ARCHIVES.has(ext) || CONFIG.has(ext) || DB.has(ext)) return true;
    if (CODE.has(ext) && !SAFE.has(ext)) return true;
    return false;
  }

  /**
   * Ask the admin (in the admin's own private chat) to approve one outbound
   * file. Waits until the admin replies 允许/拒绝 in that chat, the user's
   * turn aborts, or the timeout elapses (default 10 min → auto-reject).
   * Fail-closed: when the admin chat is inactive or busy the send is refused.
   */
  async requestSendApproval(chat, realPath, size, args, signal) {
    const security = this.config.security || {};
    const timeoutMs = Math.max(Number(security.sendApprovalTimeoutMs) || 10 * 60_000, 30_000);
    const adminKey = this.adminChatKey();
    if (adminKey === undefined) return { allowed: true, reason: '' };
    if (adminKey === chat.key) return { allowed: true, reason: '' }; // admin's own chat never gates itself

    const adminChat = this.chats.get(adminKey);
    if (adminChat === undefined || adminChat.pendingApproval !== undefined) {
      await this.deliverText(chat, '⚠️ 管理员暂不在线（无法发起审批），文件未发送。请稍后再试或联系管理员。').catch(() => {});
      return { allowed: false, reason: '管理员暂不在线或正在处理其他审批，文件未发送。' };
    }

    const name = basename(realPath);
    const caption = typeof args.caption === 'string' ? args.caption.trim() : '';
    const requester = String(chat.userId ?? '');
    const requestText = [
      '🔐 文件外发审批',
      `- 申请人：${requester}`,
      `- 文件：${realPath}`,
      `- 大小：${size} 字节`,
      ...(caption !== '' ? [`- 说明：${caption.slice(0, 120)}`] : []),
      '',
      `回复「允许」放行，「拒绝」阻止；${Math.round(timeoutMs / 60_000)} 分钟内未回复视为拒绝。`
    ].join('\n');

    const decision = await new Promise((resolve) => {
      const settle = (allowed, reason) => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        if (adminChat.pendingApproval?.resolve === settleProxy) adminChat.pendingApproval = undefined;
        resolve({ allowed, reason });
      };
      const settleProxy = (outcome) => {
        if (outcome === 'allowed-once') settle(true, '');
        else if (outcome === 'rejected') settle(false, '管理员拒绝了本次文件发送。');
        else settle(false, '审批被取消，文件未发送。');
      };
      const timer = setTimeout(() => settle(false, '管理员未在时限内审批，文件未发送。'), timeoutMs);
      timer.unref?.();
      const onAbort = () => settle(false, '任务已取消，文件未发送。');
      signal?.addEventListener('abort', onAbort, { once: true });
      adminChat.pendingApproval = { resolve: settleProxy };
      this.deliverText(adminChat, requestText).catch(() => {});
      // Tell the requester who is reviewing and where things stand, so the
      // wait is not a black box (fire-and-forget: the executor is sync).
      void this.deliverText(chat, `🕐 该文件包含代码/敏感内容，已提交给管理员（${(this.config.security || {}).adminIds?.[0] ?? 'admin'}）审批，批准后将自动发送。`).catch(() => {});
    });
    if (decision.allowed) {
      await this.deliverText(chat, '✅ 管理员已批准，文件发送中…').catch(() => {});
    }
    return decision;
  }

  // ----------------------------------------------------------- file uploads

  /**
   * Download, decrypt and durably store a WeCom file message, then build the
   * user-facing mention that references the saved path.
   * @param usersRoot - root of all private user workspaces; uploads are stored
   *   under `<usersRoot>/.wecom-uploads/<userId>/` (`files.dir` overrides the
   *   `.wecom-uploads` root but the per-user sub-directory is kept).
   * @param userId - WeCom user id; owns the per-user upload sub-directory.
   * @param file - { url, aeskey, name?, size? } from the adapter.
   * @returns {Promise<{ path: string, name: string, size: number, mention: string }>}
   */
  async saveInboundFile(usersRoot, userId, file) {
    const filesConfig = this.config.files || {};
    if (filesConfig.enabled === false) {
      throw new Error('文件接收已禁用 (files.enabled=false)');
    }
    const root = resolve(filesConfig.dir || join(usersRoot, '.wecom-uploads'));
    const userDir = sanitizeFileName(String(userId), 'user');
    const dir = join(root, userDir);

    const { buffer, filename } = await downloadFile(file.url, {
      timeoutMs: Number(filesConfig.timeoutMs) || 30_000,
      maxBytes: Number(filesConfig.maxBytes) || 100 * 1024 * 1024
    });
    const decrypted = file.aeskey ? decryptFile(buffer, file.aeskey) : buffer;
    const name = sanitizeFileName(file.name || filename || 'wecom-file.bin', 'wecom-file.bin');
    const path = await saveUnique(dir, name, decrypted);
    return {
      path,
      name,
      size: decrypted.length,
      mention: [
        `📎 收到文件：${name}（${sizeText(decrypted.length)}）`,
        `已保存到：@${path}`
      ].join('\n')
    };
  }

  reapIdle() {
    const now = Date.now();
    const timeout = this.config.agent.idleTimeoutMs;
    for (const [key, chat] of this.chats) {
      // Never reap a chat that is waiting for the user to answer a prompt;
      // disposing it would orphan the suspended ask/approval.
      if (chat.pendingQuestion !== undefined || chat.pendingApproval !== undefined) continue;
      if (now - chat.lastUsed > timeout) {
        this.chats.delete(key);
        void Promise.resolve(chat.dispose?.()).catch(() => {});
      }
    }
  }
}
