// WeCom Smart Robot (企业微信智能机器人) WebSocket adapter.
//
// Ports the protocol from Hermes Agent's `plugins/platforms/wecom/adapter.py`:
// a persistent WebSocket to wss://openws.work.weixin.qq.com authenticated with
// `aibot_subscribe` (bot_id + secret), receiving `aibot_msg_callback` events
// and replying via `aibot_respond_msg` / `aibot_send_msg`. No public endpoint
// or AES callback is needed — it is a long-lived client connection.
//
// File messages: msgtype "file" carries body.file.{url, aeskey, name?, size?}.
// The url points to encrypted bytes (valid ~5 min) and aeskey is the base64
// AES-256 key needed to decrypt them (see media.js). The adapter only extracts
// the metadata; downloading/decrypting/storing is the Bridge's job.

import { createHash, randomUUID } from 'node:crypto';
import WebSocket from 'ws';

const DEFAULT_WS_URL = 'wss://openws.work.weixin.qq.com';

const APP_CMD_SUBSCRIBE = 'aibot_subscribe';
const APP_CMD_CALLBACK = 'aibot_msg_callback';
const APP_CMD_LEGACY_CALLBACK = 'aibot_callback';
const APP_CMD_EVENT_CALLBACK = 'aibot_event_callback';
const APP_CMD_SEND = 'aibot_send_msg';
const APP_CMD_RESPONSE = 'aibot_respond_msg';
const APP_CMD_PING = 'ping';
const APP_CMD_UPLOAD_INIT = 'aibot_upload_media_init';
const APP_CMD_UPLOAD_CHUNK = 'aibot_upload_media_chunk';
const APP_CMD_UPLOAD_FINISH = 'aibot_upload_media_finish';

const CONNECT_TIMEOUT_SECONDS = 20;
const HEARTBEAT_INTERVAL_SECONDS = 30;
const RECONNECT_BACKOFF = [2, 5, 10, 30, 60];
const DEDUP_MAX_SIZE = 1000;
/**
 * WeCom only accepts `aibot_respond_msg` (passive reply bound to the inbound
 * req_id) within a few seconds of the message; after that the respond is
 * rejected server-side. Later answers must degrade to a proactive
 * `aibot_send_msg`, so remember when each chat's req_id was captured.
 */
const PASSIVE_REPLY_WINDOW_MS = 4_500;
/** Media upload framing: chunk bytes (before base64), max chunks, retries. */
const UPLOAD_CHUNK_BYTES = 512 * 1024;
const UPLOAD_MAX_CHUNKS = 100;
const UPLOAD_CHUNK_RETRIES = 2;
const UPLOAD_ACK_TIMEOUT_MS = 20_000;

function shortId() {
  return randomUUID().replace(/-/g, '');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class WeComAdapter {
  /**
   * @param opts - { botId, secret, websocketUrl, onMessage, logger }
   *   onMessage({ chatId, userId, text, file, reply }) where reply(content) sends
   *   a markdown reply back to that chat and file is
   *   { url, aeskey, name?, size? } | undefined.
   */
  constructor({ botId, secret, websocketUrl, onMessage, logger }) {
    this.botId = String(botId || '');
    this.secret = String(secret || '');
    this.wsUrl = String(websocketUrl || DEFAULT_WS_URL);
    this.onMessage = onMessage;
    this.logger = logger;
    this.running = false;
    this.ws = undefined;
    this.heartbeatTimer = undefined;
    this.deviceId = shortId();
    this.dedup = new Set();
    this.lastReqId = new Map(); // chatId -> last inbound req_id
    this.lastReqAt = new Map(); // chatId -> when that req_id was captured
    this.authed = false;
    this.authedAt = 0;
  }

  /**
   * Whether the gateway websocket is open AND authenticated.
   * Used by the bridge's status endpoint.
   */
  isConnected() {
    return this.authed && this.ws !== undefined && this.ws.readyState === WebSocket.OPEN;
  }

  /** Seconds since authentication succeeded (0 while disconnected). */
  connectedSec() {
    return this.authed ? Math.round((Date.now() - this.authedAt) / 1000) : 0;
  }

  async start() {
    if (!this.botId || !this.secret) {
      throw new Error('dsh-wecom: botId and secret are required');
    }
    this.running = true;
    this.connectLoop().catch((error) => {
      console.error(`[dsh-wecom] connect loop failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  }

  stop() {
    this.running = false;
    this.authed = false;
    if (this.heartbeatTimer !== undefined) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = undefined;
    if (this.ws !== undefined) {
      try {
        this.ws.terminate();
      } catch {
        /* containment */
      }
      this.ws = undefined;
    }
    this.dedup.clear();
    this.lastReqId.clear();
    this.lastReqAt.clear();
  }

  // ---------------------------------------------------------- connect loop

  async connectLoop() {
    let backoffIdx = 0;
    while (this.running) {
      try {
        await this.openAndSubscribe();
        backoffIdx = 0;
        await this.untilClosed();
      } catch (error) {
        if (!this.running) return;
        console.error(`[dsh-wecom] connect error: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (!this.running) return;
      const delay = RECONNECT_BACKOFF[Math.min(backoffIdx, RECONNECT_BACKOFF.length - 1)];
      backoffIdx += 1;
      console.error(`[dsh-wecom] reconnecting in ${delay}s`);
      await sleep(delay * 1000);
    }
  }

  /** Open a WebSocket, subscribe, and install listeners. */
  async openAndSubscribe() {
    const ws = new WebSocket(this.wsUrl);
    this.ws = ws;
    this.authed = false;
    this.closedPromise = new Promise((resolve) => {
      ws.on('close', () => {
        this.authed = false;
        resolve();
      });
      ws.on('error', () => resolve());
    });

    await new Promise((resolve, reject) => {
      ws.on('open', () => {
        resolve();
      });
      ws.on('error', (err) => {
        console.error(`[dsh-wecom] websocket error: ${err && err.message ? err.message : String(err)}`);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
    });

    // Authenticate.
    const reqId = `subscribe-${shortId()}`;
    const ack = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.off('message', onMessage);
        reject(new Error('dsh-wecom: subscribe acknowledgement timed out'));
      }, CONNECT_TIMEOUT_SECONDS * 1000);
      const onMessage = (data) => {
        let payload;
        try {
          payload = JSON.parse(data.toString());
        } catch {
          return;
        }
        if (payload?.cmd === APP_CMD_PING) return;
        if (payload?.headers?.req_id === reqId) {
          clearTimeout(timer);
          ws.off('message', onMessage);
          resolve(payload);
        }
      };
      ws.on('message', onMessage);
      ws.send(
        JSON.stringify({
          cmd: APP_CMD_SUBSCRIBE,
          headers: { req_id: reqId },
          body: { bot_id: this.botId, secret: this.secret, device_id: this.deviceId }
        })
      );
    });

    const errcode = ack?.errcode ?? ack?.body?.errcode ?? 0;
    if (errcode !== 0) {
      const errmsg = ack?.errmsg || ack?.body?.errmsg || 'authentication failed';
      console.error(`[dsh-wecom] auth FAILED: ${errmsg} (errcode=${errcode})`);
      throw new Error(`dsh-wecom: WeCom auth failed: ${errmsg} (errcode=${errcode})`);
    }
    console.error(`[dsh-wecom] authenticated OK, connected to ${this.wsUrl}`);
    this.authed = true;
    this.authedAt = Date.now();

    // Install the steady-state listeners.
    ws.on('message', (data) => this.handleFrame(data));
    this.heartbeatTimer = setInterval(() => this.sendPing(), HEARTBEAT_INTERVAL_SECONDS * 1000);
    this.heartbeatTimer.unref?.();
  }

  untilClosed() {
    return this.closedPromise;
  }

  // -------------------------------------------------------------- inbound

  handleFrame(data) {
    let payload;
    try {
      payload = JSON.parse(data.toString());
    } catch {
      return;
    }
    if (typeof payload !== 'object' || payload === null) return;
    const cmd = String(payload.cmd || '');
    if (cmd === APP_CMD_CALLBACK || cmd === APP_CMD_LEGACY_CALLBACK) {
      this.onInboundMessage(payload);
    } else if (cmd === APP_CMD_EVENT_CALLBACK) {
      // Event frames (enter chat, mention-only notices, ...) are not turned
      // into conversations; log the interesting ones so nothing arrives
      // invisibly while we debug a channel.
      const bodyKeys = typeof payload.body === 'object' && payload.body !== null ? Object.keys(payload.body).join(',') : '';
      console.error(`[dsh-wecom] event callback ignored: ${JSON.stringify(payload.body ?? {}).slice(0, 400)} (keys: ${bodyKeys})`);
    }
    // ping is ignored.
  }

  onInboundMessage(payload) {
    const body = payload.body;
    if (typeof body !== 'object' || body === null) return;

    const msgid = String(body.msgid || payload.headers?.req_id || shortId());
    if (this.dedup.has(msgid)) return;
    this.dedup.add(msgid);
    if (this.dedup.size > DEDUP_MAX_SIZE) {
      const entries = [...this.dedup];
      for (const id of entries.slice(0, Math.floor(DEDUP_MAX_SIZE / 2))) this.dedup.delete(id);
    }

    const sender = typeof body.from === 'object' && body.from !== null ? body.from : {};
    const userId = String(sender.userid || '').trim();
    const chatId = String(body.chatid || userId).trim();
    if (!chatId) return;
    // Group message when the callback carries an explicit chatid that is not
    // the sender's own userid (single chats either omit chatid or echo it).
    const isGroup = Boolean(body.chatid) && chatId !== userId;

    const replyReqId = String(payload.headers?.req_id || '').trim();
    if (replyReqId) {
      this.lastReqId.set(chatId, replyReqId);
      this.lastReqAt.set(chatId, Date.now());
    }

    const text = this.extractText(body);
    const file = this.extractFile(body);
    const images = this.extractImages(body);
    let unsupportedType;
    if (!text && !file && images.length === 0) {
      // Unknown/out-of-spec payload (e.g. 合并转发): log the shape so new
      // types can be supported, and let the bridge tell the user instead of
      // silently ignoring the message.
      const msgtype = String(body.msgtype || '').trim();
      unsupportedType = msgtype !== '' ? msgtype : '(消息体无 msgtype 字段)';
      console.error(`[dsh-wecom] unhandled inbound msgtype "${unsupportedType}": ${JSON.stringify(body).slice(0, 800)}`);
    }

    this.onMessage({
      chatId,
      userId,
      isGroup,
      text,
      file,
      images,
      unsupportedType,
      headers: payload.headers,
      reply: async (content) => this.sendReply(chatId, content, replyReqId)
    });
  }

  /**
   * Extract encrypted image payloads: a bare image message and image items
   * inside a mixed (图文混排) message. Same shape as files — an encrypted
   * download url (~5 min validity) plus the per-image AES key.
   * @returns {Array<{ url: string, aeskey: string }>}
   */
  extractImages(body) {
    const images = [];
    const push = (source) => {
      if (typeof source !== 'object' || source === null || !source.url) return;
      images.push({ url: String(source.url), aeskey: String(source.aeskey || '') });
    };
    const msgtype = String(body.msgtype || '').toLowerCase();
    if (msgtype === 'image') push(body.image);
    if (msgtype === 'mixed') {
      const items = body.mixed?.msg_item;
      if (Array.isArray(items)) {
        for (const item of items) {
          if (typeof item !== 'object' || item === null) continue;
          if (String(item.msgtype || '').toLowerCase() === 'image') push(item.image);
        }
      }
    }
    return images;
  }

  extractText(body) {
    const parts = [];
    const msgtype = String(body.msgtype || '').toLowerCase();

    if (msgtype === 'mixed') {
      const items = body.mixed?.msg_item;
      if (Array.isArray(items)) {
        for (const item of items) {
          if (typeof item !== 'object' || item === null) continue;
          if (String(item.msgtype || '').toLowerCase() === 'text') {
            const content = String(item.text?.content || '').trim();
            if (content) parts.push(content);
          }
        }
      }
    } else {
      const content = String(body.text?.content || '').trim();
      if (content) parts.push(content);
      if (msgtype === 'voice') {
        const voice = String(body.voice?.content || '').trim();
        if (voice) parts.push(voice);
      }
      if (msgtype === 'appmsg') {
        const title = String(body.appmsg?.title || '').trim();
        if (title) parts.push(title);
      }
    }

    // 合并转发/聊天记录不是智能机器人官方支持的接收类型，但实际会以带
    // item 数组的载荷到达。尽力抽取其中的文本项，合并成一段文字：
    // 「发言者: 内容」逐行，保留对话结构。
    if (parts.length === 0) {
      const record = (typeof body.chatrecord === 'object' && body.chatrecord !== null)
        ? body.chatrecord
        : (Array.isArray(body.item) ? body : undefined);
      const items = record?.item;
      if (Array.isArray(items)) {
        for (const item of items) {
          if (typeof item !== 'object' || item === null) continue;
          const content = String(item.text?.content || '').trim();
          if (content === '') continue;
          const sender = String(item.from?.nickname || item.from?.userid || '').trim();
          parts.push(sender ? `${sender}: ${content}` : content);
        }
      }
    }

    return parts.filter(Boolean).join('\n').trim();
  }

  /**
   * Extract the download metadata of a file message.
   * @returns {{ url: string, aeskey: string, name: string, size?: number } | undefined}
   */
  extractFile(body) {
    const msgtype = String(body.msgtype || '').toLowerCase();
    if (msgtype !== 'file') return undefined;
    const source = body.file;
    if (typeof source !== 'object' || source === null || !source.url) return undefined;
    const size = Number(source.size);
    return {
      url: String(source.url),
      aeskey: String(source.aeskey || ''),
      name: String(source.name || ''),
      size: Number.isFinite(size) && size > 0 ? size : undefined
    };
  }

  // ------------------------------------------------------------- outbound

  sendPing() {
    if (this.ws === undefined || this.ws.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(
        JSON.stringify({
          cmd: APP_CMD_PING,
          headers: { req_id: `ping-${shortId()}` },
          body: {}
        })
      );
    } catch {
      /* containment */
    }
  }

  async sendReply(chatId, content, replyReqId) {
    if (this.ws === undefined || this.ws.readyState !== WebSocket.OPEN) return;
    const reqId = replyReqId || this.lastReqId.get(chatId);
    // Only try the passive respond while the inbound message is still inside
    // WeCom's reply window; a stale req_id would be rejected and the reply
    // silently lost (e.g. the model's answer after a long ask_user pause).
    const withinWindow = Date.now() - (this.lastReqAt.get(chatId) ?? 0) < PASSIVE_REPLY_WINDOW_MS;
    const frame = reqId && withinWindow
      ? {
          cmd: APP_CMD_RESPONSE,
          headers: { req_id: reqId },
          body: { msgtype: 'markdown', markdown: { content } }
        }
      : {
          cmd: APP_CMD_SEND,
          headers: { req_id: `send-${shortId()}` },
          body: { chatid: chatId, msgtype: 'markdown', markdown: { content } }
        };
    try {
      this.ws.send(JSON.stringify(frame));
    } catch {
      /* containment */
    }
  }

  /**
   * Send a proactive (server-initiated) message to a chat — used for todo
   * reminders. Unlike sendReply this never tries to attach to an inbound
   * req_id; it always uses a fresh `aibot_send_msg`.
   * @param {string} chatId - WeCom chatid to deliver to.
   * @param {string} content - Markdown content.
   */
  async sendMessage(chatId, content) {
    if (this.ws === undefined || this.ws.readyState !== WebSocket.OPEN) return;
    if (!chatId) return;
    const frame = {
      cmd: APP_CMD_SEND,
      headers: { req_id: `send-${shortId()}` },
      body: { chatid: chatId, msgtype: 'markdown', markdown: { content } }
    };
    try {
      this.ws.send(JSON.stringify(frame));
    } catch {
      /* containment */
    }
  }

  // -------------------------------------------------------- media upload

  /**
   * Send one gateway command and await the ack frame carrying the same
   * req_id. Shared by the media-upload handshake steps.
   * @returns the ack payload; rejects on timeout / send failure.
   */
  request(cmd, body, timeoutMs = UPLOAD_ACK_TIMEOUT_MS) {
    if (this.ws === undefined || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error(`dsh-wecom: ${cmd} skipped, websocket not open`));
    }
    const reqId = `${cmd}-${shortId()}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.off('message', onMessage);
        reject(new Error(`dsh-wecom: ${cmd} acknowledgement timed out`));
      }, timeoutMs);
      const ws = this.ws;
      const onMessage = (data) => {
        let payload;
        try {
          payload = JSON.parse(data.toString());
        } catch {
          return;
        }
        if (payload?.headers?.req_id !== reqId) return;
        clearTimeout(timer);
        ws.off('message', onMessage);
        resolve(payload);
      };
      ws.on('message', onMessage);
      try {
        this.ws.send(JSON.stringify({ cmd, headers: { req_id: reqId }, body }));
      } catch (error) {
        clearTimeout(timer);
        ws.off('message', onMessage);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  /**
   * Upload one media file via the chunked gateway handshake
   * (init → chunk × N → finish) and return its media_id.
   * @param {Buffer} buffer - file bytes.
   * @param {{ type?: string, filename?: string }} options - media type
   *   ('file'|'image'|'voice'|'video') and display filename.
   * @returns {{ type: string, media_id: string }}
   */
  async uploadMedia(buffer, { type = 'file', filename = 'file' } = {}) {
    if (!Buffer.isBuffer(buffer)) throw new Error('dsh-wecom: uploadMedia needs a Buffer');
    const totalChunks = Math.ceil(buffer.length / UPLOAD_CHUNK_BYTES);
    if (totalChunks > UPLOAD_MAX_CHUNKS) {
      throw new Error(`dsh-wecom: file too large (${buffer.length} bytes = ${totalChunks} chunks; max ${UPLOAD_MAX_CHUNKS} chunks ≈ ${Math.floor((UPLOAD_MAX_CHUNKS * UPLOAD_CHUNK_BYTES) / 1024 / 1024)}MB)`);
    }
    const md5 = createHash('md5').update(buffer).digest('hex');

    const init = await this.request(APP_CMD_UPLOAD_INIT, {
      type,
      filename,
      total_size: buffer.length,
      total_chunks: totalChunks,
      md5
    });
    const uploadId = init?.body?.upload_id;
    if (!uploadId) {
      throw new Error(`dsh-wecom: upload init failed: ${JSON.stringify(init?.body ?? init?.errmsg ?? init)?.slice(0, 300)}`);
    }

    for (let index = 0; index < totalChunks; index += 1) {
      const start = index * UPLOAD_CHUNK_BYTES;
      const chunk = buffer.subarray(start, Math.min(start + UPLOAD_CHUNK_BYTES, buffer.length));
      const payload = { upload_id: uploadId, chunk_index: index, base64_data: chunk.toString('base64') };
      let lastError;
      for (let attempt = 0; attempt <= UPLOAD_CHUNK_RETRIES; attempt += 1) {
        try {
          await this.request(APP_CMD_UPLOAD_CHUNK, payload);
          lastError = undefined;
          break;
        } catch (error) {
          lastError = error;
          if (attempt < UPLOAD_CHUNK_RETRIES) await sleep(500 * (attempt + 1));
        }
      }
      if (lastError !== undefined) {
        throw new Error(`dsh-wecom: upload chunk ${index + 1}/${totalChunks} failed: ${lastError.message}`);
      }
    }

    const finish = await this.request(APP_CMD_UPLOAD_FINISH, { upload_id: uploadId });
    const mediaId = finish?.body?.media_id;
    if (!mediaId) {
      throw new Error(`dsh-wecom: upload finish failed: ${JSON.stringify(finish?.body ?? finish?.errmsg ?? finish)?.slice(0, 300)}`);
    }
    return { type: finish?.body?.type ?? type, media_id: mediaId };
  }

  /**
   * Push a media message (file/image/voice/video) to a chat by media_id.
   * @param {string} chatId - WeCom chatid (single chat = userid).
   * @param {string} mediaType - one of 'file'|'image'|'voice'|'video'.
   * @param {string} mediaId - id returned by uploadMedia().
   */
  async sendMediaMessage(chatId, mediaType, mediaId) {
    if (this.ws === undefined || this.ws.readyState !== WebSocket.OPEN) return;
    if (!chatId || !mediaId) return;
    const frame = {
      cmd: APP_CMD_SEND,
      headers: { req_id: `send-${shortId()}` },
      body: { chatid: chatId, msgtype: mediaType, [mediaType]: { media_id: mediaId } }
    };
    try {
      this.ws.send(JSON.stringify(frame));
    } catch {
      /* containment */
    }
  }

  /**
   * Send one streaming-reply frame (passive channel). The FIRST call with a
   * stream id creates the message; further calls with the same id refresh its
   * content; `finish: true` seals it. The inbound callback's headers (same
   * req_id) must be passed through unchanged per the WeCom gateway rules.
   * @param {object|undefined} headers - headers of the originating callback frame.
   * @param {string} streamId - stable id of this stream message.
   * @param {string} content - full replacement content of the bubble.
   * @param {boolean} finish - seal the stream when true.
   * @returns {boolean} whether the frame was handed to the socket.
   */
  replyStreamFrame(headers, streamId, content, finish = false) {
    if (this.ws === undefined || this.ws.readyState !== WebSocket.OPEN) return false;
    if (headers === undefined || typeof headers !== 'object' || !streamId) return false;
    const frame = {
      cmd: APP_CMD_RESPONSE,
      headers: { ...headers },
      body: { msgtype: 'stream', stream: { id: streamId, finish: !!finish, content } }
    };
    try {
      this.ws.send(JSON.stringify(frame));
      return true;
    } catch {
      return false;
    }
  }
}
