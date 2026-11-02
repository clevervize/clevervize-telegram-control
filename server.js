const http = require('node:http');
const crypto = require('node:crypto');

const port = Number(process.env.PORT || 3000);
const token = String(process.env.TELEGRAM_BOT_TOKEN || '').trim();
const webhookSecret = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const allowedChats = new Set(String(process.env.TELEGRAM_ALLOWED_CHAT_IDS || '')
  .split(',').map(value => value.trim()).filter(value => /^-?\d{5,20}$/.test(value)));

function send(res, status, body = '', headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 256 * 1024) reject(new Error('payload-too-large'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); } catch { reject(new Error('invalid-json')); }
    });
    req.on('error', reject);
  });
}

async function telegram(method, body) {
  if (!token) throw new Error('telegram-not-configured');
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.ok) throw new Error('telegram-request-failed');
  return payload.result;
}

function replyFor(text) {
  const command = String(text || '').trim().split(/\s+/, 1)[0].replace(/@[^\s]+$/, '').toLowerCase();
  if (command === '/start' || command === '/help') {
    return 'Clever Vize kontrol botu aktif. Komutlar: /status, /help. IMAP havuzu bağlandığında randevu ve OTP bildirimleri burada görünecek.';
  }
  if (command === '/status') return 'Bot aktif. IMAP havuzu henüz yapılandırılmadı.';
  return 'Bilinmeyen komut. /help yazabilirsiniz.';
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname === '/healthz' && ['GET', 'HEAD'].includes(req.method)) {
    return send(res, 200, req.method === 'HEAD' ? '' : JSON.stringify({ status: 'ok', telegramConfigured: Boolean(token && webhookSecret && allowedChats.size) }));
  }
  if (url.pathname !== '/telegram/webhook' || req.method !== 'POST') return send(res, 404, JSON.stringify({ error: 'not-found' }));
  const receivedSecret = Buffer.from(String(req.headers['x-telegram-bot-api-secret-token'] || ''));
  const expectedSecret = Buffer.from(webhookSecret);
  if (!webhookSecret || receivedSecret.length !== expectedSecret.length || !crypto.timingSafeEqual(receivedSecret, expectedSecret)) {
    return send(res, 403, JSON.stringify({ error: 'forbidden' }));
  }
  try {
    const update = await readJson(req);
    const message = update?.message;
    const chatId = String(message?.chat?.id || '');
    if (!allowedChats.has(chatId) || !message?.text) return send(res, 200, JSON.stringify({ ok: true }));
    await telegram('sendMessage', { chat_id: chatId, text: replyFor(message.text) });
    return send(res, 200, JSON.stringify({ ok: true }));
  } catch (error) {
    console.error('webhook failed', error.message);
    return send(res, 200, JSON.stringify({ ok: true }));
  }
}).listen(port, '0.0.0.0', () => console.log(`telegram control listening on ${port}`));
