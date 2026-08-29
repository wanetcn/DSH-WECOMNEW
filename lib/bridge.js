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
import { basename, join, resolve } from 'node:path';
import { installModelSelection } from '@deepseek-ai/dsh-agent';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { SessionId } from '@deepseek-ai/dsh-session';
import { setSandboxMode } from '@deepseek-ai/dsh-sandbox-policy';
import { setApprovalPolicy } from '@deepseek-ai/dsh-user-approval';
import { WeComAdapter } from './wecom-adapter.js';
import { registerSendFileTool } from './sendfile.js';
import { decryptFile, downloadFile, sanitizeFileName, saveUnique, sizeText } from './media.js';
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

/** Per-session prompt section for non-admin users: what they may/may not touch. */
function userBoundaryPrompt(cwd, publicDir) {
  return [
    '【企业微信普通用户权限边界】',
    `- 你的用户工作区（可读写）：${cwd}`,
    `- 公共工作区（所有人只读，你不可修改）：${publicDir}`,
    '- 禁止读取或查看其他用户的工作区、上传目录、会话记录（包括 $DSH_HOME/sessions 下的会话文件）以及 dsh 配置、系统配置。',
    '- 你无权对操作系统做任何修改：不得安装/卸载软件、不得运行影响系统的脚本、不得修改系统或服务配置、不得重启/停止系统或任何服务（对工作区和 /tmp 之外的写入，文件沙箱也会强制拒绝）。',
    '- 任务确实需要上述操作时，不要尝试绕过或变通执行，直接告知用户：「该操作需要管理员权限，请联系管理员处理。」'
  ].join('\n');
}

/** Per-session prompt section for admins: full access + caution. */
function adminBoundaryPrompt(cwd) {
  return [
    '【企业微信管理员权限】',
    '你是管理员（超级用户），拥有完整访问权限。',
    `- 管理会话工作区：${cwd}`,
    '- 可以查看所有用户的工作区、上传目录与会话信息（包括 $DSH_HOME/sessions 下的会话文件）。',
    '- 可以修改 dsh 配置与系统配置、管理服务。',
    '- 破坏性或影响面大的操作（如重启服务、改动生产配置）前应先向用户确认。'
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
    /** Session ids attached to a wecom workspace (status panel 总会话数). */
    this.wecomSessions = new Set();
    /** Process start time + web route disposer for the status endpoint. */
    this.startedAt = Date.now();
    this.disposeWebRoute = undefined;
    /** wecom_send_file tool registration disposer. */
    this.disposeSendTool = undefined;
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
        const input = typeof data.input === 'string' ? data.input : '';
        progress.lines.push(`🔧 ${name}${input ? `：${input.slice(0, 60)}` : ''}`);
        this.streamPush(progress);
      }
    });

    this.adapter = new WeComAdapter({
      botId: this.config.botId,
      secret: this.config.secret,
      websocketUrl: this.config.websocketUrl,
      onMessage: (input) => this.handleMessage(input),
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
      }
    } catch {
      /* first run or unreadable file: start from zero */
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
      chat.dispose().catch(() => {});
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
    const { chatId, userId, text, file, reply } = input;
    const hasText = typeof text === 'string' && text.trim() !== '';
    if (!hasText && !file) return;

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

    // Track the user (panel 总用户数) and make sure their sessions group
    // under a "wecom" workspace in the web sidebar.
    const uid = String(userId || '');
    if (uid !== '') {
      if (!this.stats.userIds.includes(uid)) {
        this.stats.userIds.push(uid);
        this.queuePersistStats();
      }
      this.ensureUserWorkspace(uid).catch((error) => {
        console.error(`[dsh-wecom] workspace setup failed for ${uid}: ${error instanceof Error ? error.message : String(error)}`);
      });
    }

    if (hasText && text.startsWith('/')) {
      await this.handleCommand(chatId, text, input);
      return;
    }

    // A pending interactive prompt (approval / ask_user_question) in this
    // chat consumes the next text message as its answer instead of starting
    // a new agent turn.
    const liveChat = this.chats.get(`wecom:${chatId}`);
    if (liveChat !== undefined && hasText) {
      if (await this.deliverPendingAnswer(liveChat, text, reply)) return;
    }

    // 纯文件消息（无文字）：保存后直接把存储路径作为回答，不额外开 agent 会话，
    // 方便用户把路径复述给智能体做后续对话。
    if (file && !hasText) {
      await this.receiveFileOnly(userId, file, reply);
      return;
    }

    const key = `wecom:${chatId}`;
    const chat = await this.getOrCreateChat(key, userId);
    const run = chat.busy.then(() => this.runTurn(chat, input));
    chat.busy = run.catch(() => {});
    await run;
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
    for (const header of headers) {
      const uid = this.wecomUserForCwd(header.cwd);
      if (uid === undefined) continue;
      const id = String(header.id);
      if (this.wecomSessions.has(id)) continue;
      const entity = await this.ensureUserWorkspace(uid);
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

  /** Write the lifetime counters to disk. */
  async persistStats() {
    if (this.statsFile === undefined) return;
    await writeFile(this.statsFile, `${JSON.stringify(this.stats, null, 2)}\n`);
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
    const [cmd, ...rest] = text.split(/\s+/);
    switch (cmd) {
      case '/help':
        await input.reply(
          [
            '📖 可用命令:',
            '  /help   - 显示帮助',
            '  /todo   - 查看你的待办事宜',
            '  /reset  - 清空当前会话上下文，重新开始',
            '  /status - 显示运行状态',
            '直接发送消息即可与助手对话。'
          ].join('\n')
        );
        break;
      case '/todo':
        await this.showTodos(input.userId, input.reply);
        break;
      case '/reset': {
        const key = `wecom:${chatId}`;
        const chat = this.chats.get(key);
        if (chat !== undefined) {
          this.chats.delete(key);
          this.abandonPendingInteraction(chat);
          await chat.dispose();
          await input.reply('🔄 已清空上下文，开始新的会话。');
        } else {
          await input.reply('当前没有活跃会话。');
        }
        break;
      }
      case '/status': {
        const agents = this.ctx.get('agents');
        const { isAdmin } = this.resolveWorkspace(input.userId);
        await input.reply(
          [
            '📊 状态:',
            `  当前身份: ${isAdmin ? '👑 管理员' : '普通用户'}`,
            `  活跃 IM 会话: ${this.chats.size}`,
            `  活跃 dsh 智能体: ${agents?.list?.().length ?? '未知'}`,
            '  通道: 企业微信 (WebSocket)'
          ].join('\n')
        );
        break;
      }
      default:
        await input.reply(`未知命令: ${cmd} (输入 /help 查看可用命令)`);
    }
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

  async getOrCreateChat(key, userId) {
    let chat = this.chats.get(key);
    if (chat === undefined) {
      chat = await this.createChat(key, userId);
      this.chats.set(key, chat);
    }
    chat.lastUsed = Date.now();
    return chat;
  }

  async createChat(key, userId) {
    const ctx = this.ctx;
    const defaultModel = ctx.get('agentDefaultModel');
    const selection = defaultModel?.currentSelection?.();
    if (selection === undefined) throw new Error('agentDefaultModel service is unavailable');
    const provider = this.config.agent.provider || selection.provider;
    const model = this.config.agent.model || selection.model;
    const { isAdmin, cwd, publicDir, usersRoot } = this.resolveWorkspace(userId);
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

    const security = this.config.security || {};
    const injectBoundary = security.boundaryPrompt !== false;

    const sessionId = SessionId(`wecom-${randomUUID()}`);
    const handle = await ctx.agents.create({
      sessionId,
      meta: { cwd, agentPreset: resolvedPresetId },
      agentOptions: { provider, model },
      setup: async (agentCtx) => {
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
            text: isAdmin ? adminBoundaryPrompt(cwd) : userBoundaryPrompt(cwd, publicDir)
          });
        }
      }
    });
    await handle.agent.whenIdle();

    // Attach the new session to the user's wecom workspace so it shows up in
    // the sidebar's wecom group, and count it in the status panel.
    try {
      const entity = await this.ensureUserWorkspace(userId);
      if (entity !== undefined) {
        await entity.attachSession(sessionId);
        this.wecomSessions.add(String(sessionId));
      }
    } catch (error) {
      console.error(`[dsh-wecom] session attach failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Admins get the full-access sandbox: can modify dsh/system configs and
    // read every session. Appending the sandbox/mode event is log-only and
    // takes effect on the session's next confined call.
    if (isAdmin) {
      try {
        setSandboxMode(handle.agent.session, 'danger-full-access');
      } catch (error) {
        console.error(`[dsh-wecom] setSandboxMode failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    } else {
      // Non-admins: close the escalation channel entirely. The approval
      // policy 'never' makes every sandbox-escalation request auto-REJECT,
      // so the model can never talk its way past the workspace-write file
      // sandbox (system changes, service restarts, software installs are
      // confined or refused; the boundary prompt directs users to an admin).
      try {
        setApprovalPolicy(handle.agent.session, 'never');
      } catch (error) {
        console.error(`[dsh-wecom] setApprovalPolicy failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    return {
      key,
      chatId: key.slice('wecom:'.length),
      userId,
      agent: handle.agent,
      dispose: handle.dispose,
      busy: Promise.resolve(),
      lastUsed: Date.now(),
      isAdmin,
      cwd,
      usersRoot,
      /** ask_user_question prompt waiting for this chat's answer. */
      pendingQuestion: undefined,
      /** approval prompt waiting for this chat's decision. */
      pendingApproval: undefined
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
    const collector = { parts: [], reason: undefined, progress };
    this.pending.set(sessionId, collector);
    try {
      const blocks = [];
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
      const textBlock = `${fileWarning}${hasText ? text.trim() : ''}`.trim();
      if (textBlock !== '') blocks.push({ type: 'text', text: textBlock });
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
      try {
        await reply(`❌ 执行失败: ${error instanceof Error ? error.message : String(error)}`);
      } catch {
        /* containment */
      }
    } finally {
      this.pending.delete(sessionId);
      chat.progress = undefined;
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

      // Path policy: the file must live under the chatting user's own
      // workspace or the public workspace. realpath first, so symlink and
      // `..` traversal cannot escape the allow-list.
      const { cwd, publicDir } = this.resolveWorkspace(chat.userId);
      const roots = [cwd.replace(/\/+$/, ''), publicDir.replace(/\/+$/, '')];
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
        chat.dispose().catch(() => {});
      }
    }
  }
}
