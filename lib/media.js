// WeCom aibot media helpers: download the encrypted file URL, decrypt it with
// the per-message aeskey, and store it durably under the chat workspace.
//
// Protocol facts (confirmed against the official @wecom/aibot-node-sdk and the
// 企业微信智能机器人 long-connection docs):
//   - Inbound `aibot_msg_callback` with msgtype "file" carries
//       body.file.url    -> encrypted download URL, valid ~5 minutes
//       body.file.aeskey -> base64 AES-256 key, unique per URL
//       body.file.name / body.file.size -> optional metadata
//   - The URL returns raw encrypted bytes; filename may come from the
//     Content-Disposition header (RFC 5987 filename*=UTF-8'' or filename="...").
//   - Decryption is AES-256-CBC with key = base64(aeskey), IV = key[0..16),
//     and PKCS#7 padding on a 32-byte block (Node's default 16-byte block
//     must be disabled and the padding stripped manually).

import { createDecipheriv } from 'node:crypto';
import { open, mkdir } from 'node:fs/promises';
import { basename, extname, join } from 'node:path';

/** WeCom pads media to a 32-byte block boundary (PKCS#7), not Node's 16. */
const PKCS7_BLOCK_SIZE = 32;

/** RFC 5987 + plain fallback filename extraction from Content-Disposition. */
export function parseContentDispositionFilename(contentDisposition) {
  if (typeof contentDisposition !== 'string' || contentDisposition === '') {
    return undefined;
  }
  const rfc5987 = /filename\*=UTF-8''([^;\s]+)/i.exec(contentDisposition);
  if (rfc5987) {
    try {
      return decodeURIComponent(rfc5987[1]);
    } catch {
      /* fall through to plain form */
    }
  }
  const plain = /filename="?([^";\s]+)"?/i.exec(contentDisposition);
  if (plain) {
    try {
      return decodeURIComponent(plain[1]);
    } catch {
      return plain[1];
    }
  }
  return undefined;
}

/**
 * Decrypt bytes returned by the WeCom media URL.
 * @param {Buffer} encryptedBuffer - raw bytes from the download URL
 * @param {string} aesKey - base64 AES-256 key from body.file.aeskey
 * @returns {Buffer} decrypted file bytes
 */
export function decryptFile(encryptedBuffer, aesKey) {
  if (!encryptedBuffer || encryptedBuffer.length === 0) {
    throw new Error('decryptFile: empty payload');
  }
  if (typeof aesKey !== 'string' || aesKey === '') {
    throw new Error('decryptFile: aeskey is missing');
  }
  // Buffer.from(base64) is lenient about padding; pad explicitly first so the
  // decoded key is always the full 32 bytes (mirrors the official SDK).
  const padded = aesKey + '='.repeat((4 - (aesKey.length % 4)) % 4);
  const key = Buffer.from(padded, 'base64');
  if (key.length !== 32) {
    throw new Error(`decryptFile: invalid aeskey (expected 32-byte key, got ${key.length})`);
  }
  const iv = key.subarray(0, 16);
  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
  const padLen = decrypted[decrypted.length - 1];
  if (padLen < 1 || padLen > PKCS7_BLOCK_SIZE || padLen > decrypted.length) {
    throw new Error(`decryptFile: invalid PKCS#7 padding value ${padLen}`);
  }
  for (let i = decrypted.length - padLen; i < decrypted.length; i += 1) {
    if (decrypted[i] !== padLen) {
      throw new Error('decryptFile: padding bytes mismatch');
    }
  }
  return decrypted.subarray(0, decrypted.length - padLen);
}

/** Make a downloaded name safe to store as a single file basename. */
export function sanitizeFileName(value, fallback = 'wecom-file.bin') {
  let name = String(value || '').normalize('NFC');
  name = basename(name)
    .replace(/[\\/\u0000-\u001f\u007f]/g, '_')
    .replace(/^\.+/, '')
    .trim();
  if (!name) name = fallback;
  if (name.length > 180) {
    const extension = extname(name).slice(0, 24);
    const stem = name.slice(0, Math.max(1, 180 - extension.length));
    name = `${stem}${extension}`;
  }
  return name;
}

/**
 * Download the WeCom media URL with a size cap and timeout.
 * @returns {Promise<{ buffer: Buffer, filename?: string }>}
 */
export async function downloadFile(url, { timeoutMs = 30_000, maxBytes = 100 * 1024 * 1024 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, { signal: controller.signal });
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error);
    throw new Error(`download failed: ${why}`);
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    throw new Error(`download failed: HTTP ${response.status} ${response.statusText}`);
  }
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`file too large: ${declared} bytes (limit ${maxBytes})`);
  }
  const data = await response.arrayBuffer();
  const buffer = Buffer.from(data);
  if (buffer.length > maxBytes) {
    throw new Error(`file too large: ${buffer.length} bytes (limit ${maxBytes})`);
  }
  return {
    buffer,
    filename: parseContentDispositionFilename(response.headers.get('content-disposition'))
  };
}

/** Persist `data` as `fileName` under `dir`, deduplicating with " (n)" suffixes. */
export async function saveUnique(dir, fileName, data) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const extension = extname(fileName).slice(0, 24);
  const stem = fileName.slice(0, fileName.length - extension.length);
  for (let index = 0; index < 10_000; index += 1) {
    const name = index === 0 ? fileName : `${stem} (${index})${extension}`;
    const target = join(dir, name);
    try {
      const handle = await open(target, 'wx', 0o600);
      try {
        await handle.writeFile(data);
        await handle.sync();
      } finally {
        await handle.close();
      }
      return target;
    } catch (error) {
      if (error?.code === 'EEXIST') continue;
      throw error;
    }
  }
  throw new Error('too many files share this name');
}

/** Human-readable byte size. */
export function sizeText(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/**
 * Detect the raster media type of decrypted image bytes by magic number.
 * WeCom does not declare the format, and the attachment admission verifies
 * the declared type against decoded bytes, so sniffing must be exact.
 * @param {Buffer} buffer - decrypted image bytes.
 * @returns {'image/png'|'image/jpeg'|'image/webp'|'image/gif'|undefined}
 */
export function sniffImageMediaType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return undefined;
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) return 'image/png';
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  if (buffer.subarray(0, 4).toString('ascii') === 'GIF8') return 'image/gif';
  return undefined;
}
