// Todo list helpers: parse a per-user Markdown todo file and keep track of
// which reminders have already been pushed, so we never nag twice.
//
// File format (per user, `<usersRoot>/<userId>/待办事宜文件.md`):
//   - [ ] 跟进行方升级 2026-09-05 20:00 提前1小时
//   - [x] 已完成的事项 2026-08-31 09:00   (done items are skipped)
//
// Recognised on an item line:
//   - datetime: `YYYY-MM-DD HH:mm` / `YYYY/MM/DD HH:mm` / `YYYY年M月D日 HH:mm`
//   - remind offset: `提前N分钟` / `提前N小时` / `提前半小时` (default 30 minutes)

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';

export const DEFAULT_TODO_FILE = '待办事宜文件.md';

/** Regexes: full datetime (year must be 4 digits, so dates in prose don't match). */
const DT_RE = /(\d{4})[-/年](\d{1,2})[-/月](\d{1,2})[日号]?\s+(\d{1,2})[:：](\d{2})/;
/** Remind offset: `提前30分钟`, `提前1小时`, `提前半小时`. */
const REMIND_RE = /提前\s*(?:(\d+(?:\.\d+)?)\s*(小时|分钟)|半小时)/;

/** Parse a remind-offset expression, returning minutes (or fallback). */
function parseRemindMinutes(text, fallback) {
  const m = REMIND_RE.exec(text);
  if (!m) return fallback;
  if (m[0].includes('半小时')) return 30;
  const value = Number(m[1]);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.round(m[2] === '小时' ? value * 60 : value);
}

/** Parse a datetime expression into a local-time Date (or null). */
function parseWhen(text) {
  const m = DT_RE.exec(text);
  if (!m) return null;
  const [, y, mo, d, h, mi] = m;
  const date = new Date(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), 0, 0);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Read a user's todo file and extract schedulable items.
 * @param {string} file - absolute path of the todo Markdown file.
 * @param {number} defaultRemindMinutes - reminder lead when no `提前N` is set.
 * @returns {Promise<Array<{ text: string, when: Date, remindBeforeMin: number, line: string }>>}
 */
export async function loadTodoItems(file, defaultRemindMinutes = 30) {
  let raw;
  try {
    raw = await readFile(file, 'utf8');
  } catch {
    return []; // no todo file yet -> nothing to schedule
  }
  const items = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith('#')) continue; // section headings
    if (trimmed.startsWith('- [x]') || trimmed.startsWith('- [X]')) continue; // done
    const when = parseWhen(trimmed);
    if (!when) continue; // no datetime -> nothing to schedule
    const text = trimmed
      .replace(/^[-*]\s*\[[ xX]\]\s*/, '')
      .replace(REMIND_RE, '')
      .trim();
    items.push({
      text: text || trimmed,
      when,
      remindBeforeMin: parseRemindMinutes(trimmed, defaultRemindMinutes),
      line: trimmed
    });
  }
  return items;
}

/** Stable key identifying a single reminder delivery (user + item + when). */
export function reminderKey(userId, item) {
  const hash = createHash('sha1').update(item.line).digest('hex').slice(0, 12);
  return `${userId}|${item.when.toISOString()}|${hash}`;
}

/**
 * Load the persisted bridge state:
 *   { sent: { [reminderKey]: epochMs }, chats: { [userId]: chatId } }
 * `sent` prevents duplicate reminders; `chats` lets proactive reminders keep
 * working across bridge restarts without waiting for the user to write again.
 */
export async function loadState(file) {
  try {
    const parsed = JSON.parse(await readFile(file, 'utf8'));
    return {
      sent: parsed && typeof parsed.sent === 'object' && parsed.sent !== null ? parsed.sent : {},
      chats: parsed && typeof parsed.chats === 'object' && parsed.chats !== null ? parsed.chats : {}
    };
  } catch {
    return { sent: {}, chats: {} };
  }
}

/** Persist the bridge state (see loadState). */
export async function saveState(file, state) {
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  await writeFile(file, JSON.stringify(state, null, 2), { mode: 0o600 });
}

/** Drop sent-state entries older than `maxAgeMs` so the file stays small. */
export function pruneSent(state, maxAgeMs = 7 * 24 * 3600 * 1000) {
  const now = Date.now();
  const sent = state.sent || {};
  for (const key of Object.keys(sent)) {
    if (now - Number(sent[key]) > maxAgeMs) delete sent[key];
  }
  state.sent = sent;
  return state;
}
