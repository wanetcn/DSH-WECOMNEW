import z from '@deepseek-ai/schemastery';
import { Bridge } from './bridge.js';

/** Stable Cordis plugin name (row id in the bundle patch). */
export const name = 'dsh-wecom';

/**
 * Core services the bridge needs before it can drive turns. `loader` is
 * awaited at start so the whole tree is mounted before the first message.
 */
export const inject = ['agentDefaultModel', 'agents', 'sessions', 'loader'];

/** Configuration schema (validated by the Cordis loader). */
export const Config = z.object({
  /** Master switch: when false the whole gateway stays dormant. */
  enabled: z.boolean().default(true),

  /** WeCom Smart Robot bot ID (企业微信智能机器人 ID). */
  botId: z.string().default(''),
  /** WeCom Smart Robot secret (企业微信智能机器人密钥). */
  secret: z.string().role('secret').default(''),
  /** WebSocket gateway URL. */
  websocketUrl: z.string().default('wss://openws.work.weixin.qq.com'),
  /** WeCom userids allowed to talk to the bot; empty = everyone. */
  allowedUserIds: z.array(z.string()).default([]),

  /** File upload handling for inbound WeCom file messages. */
  files: z
    .object({
      /** Master switch for receiving files from WeCom. */
      enabled: z.boolean().default(true),
      /**
       * Directory for received files. Defaults to
       * `<agent.cwd>/.wecom-uploads/<chatId>/` so the files land inside the
       * agent's workspace and its sandboxed file tools can read them.
       */
      dir: z.string().default(''),
      /** Max accepted file bytes (after decryption). */
      maxBytes: z.number().default(100 * 1024 * 1024),
      /** Download timeout in ms (the WeCom URL is only valid ~5 minutes). */
      timeoutMs: z.number().default(30_000)
    })
    .default({}),

  /**
   * Todo list support: `/todo` command + proactive WeCom reminders.
   * Todos live in `<usersRoot>/<userId>/<file>`; item lines with a datetime
   * like `2026-09-05 20:00` get a reminder pushed `defaultRemindMinutes`
   * before (or an explicit `提前N分钟/提前N小时` on the line wins).
   */
  todo: z
    .object({
      /** Todo file name inside each user's private workspace. */
      file: z.string().default('待办事宜文件.md'),
      /** Default reminder lead in minutes when no `提前N` is set. */
      defaultRemindMinutes: z.number().default(30),
      /** How often the reminder scanner runs (ms). */
      checkIntervalMs: z.number().default(300_000),
      /**
       * Fire the reminder as soon as we are within this many minutes of the
       * reminder point (early is fine, late is not). Also the lower bound of
       * the reminder window: reminders are sent in
       * [when − lead − grace, when), never after the event.
       */
      graceMinutes: z.number().default(5)
    })
    .default({}),

  /**
   * User isolation: admins (superusers) get the full sandbox and may modify
   * dsh/system configs and inspect every session; everyone else gets a
   * dedicated per-user workspace as their session cwd (writes restricted to
   * it, public workspace read-only) plus a prompt boundary forbidding
   * cross-user reads.
   */
  security: z
    .object({
      /** WeCom userids granted admin rights (e.g. ['alice']). */
      adminIds: z.array(z.string()).default([]),
      /**
       * Root directory holding per-user workspaces. Defaults to
       * `<agent.cwd>/users/<userId>`; each non-admin user's session cwd.
       */
      usersRoot: z.string().default(''),
      /**
       * Public workspace shared by non-admin users (read-only for them).
       * Defaults to `<agent.cwd>/public`.
       */
      publicDir: z.string().default(''),
      /** Inject the per-user permission-boundary prompt into agent sessions. */
      boundaryPrompt: z.boolean().default(true)
    })
    .default({}),

  agent: z.object({
    /** Agent preset to mount (defaults to the deployment's standard preset). */
    preset: z.string().default('standard'),
    /** Working directory for agent sessions (defaults to the dsh process cwd). */
    cwd: z.string().default(''),
    /** Override provider/model; empty = use the deployment default selection. */
    provider: z.string().default(''),
    model: z.string().default(''),
    /** Maximum chars per outbound message; longer replies are split. */
    maxMessageLength: z.number().default(4000),
    /** Idle ms before a chat's agent is disposed (memory reclamation). 0 = never. */
    idleTimeoutMs: z.number().default(30 * 60 * 1000)
  }).default({})
});

let activeBridge;

/** Mount the WeCom gateway: start the bridge, own its lifecycle. */
export function apply(ctx, config) {
  if (!config.enabled) return;
  const bridge = new Bridge(ctx, config);
  activeBridge = bridge;
  bridge.start().catch((error) => {
    console.error('[dsh-wecom] start failed: ' + (error instanceof Error ? error.message : String(error)));
    ctx.logger?.warn?.(`dsh-wecom: failed to start: ${error instanceof Error ? error.message : String(error)}`);
  });
  return () => {
    bridge.stop();
    if (activeBridge === bridge) activeBridge = undefined;
  };
}
