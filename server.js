const http = require('node:http');
const crypto = require('node:crypto');

const port = Number(process.env.PORT || 3000);
const token = String(process.env.TELEGRAM_BOT_TOKEN || '').trim();
const webhookSecret = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const accessPassword = String(process.env.TELEGRAM_ACCESS_PASSWORD || '').trim();
// OpenInbox Worker posts only a compact, signed event here.  This is separate
// from Telegram's webhook secret so one integration cannot impersonate the other.
const inboxEventSecret = String(process.env.OPENINBOX_EVENT_SECRET || '').trim();
const publicUrl = String(process.env.RENDER_EXTERNAL_URL || process.env.PUBLIC_URL || '').replace(/\/$/, '');
const allowedChats = new Set(String(process.env.TELEGRAM_ALLOWED_CHAT_IDS || '')
  .split(',').map(value => value.trim()).filter(value => /^-?\d{5,20}$/.test(value)));
const temporaryAuthorizations = new Map();
const AUTH_TTL_MS = 12 * 60 * 60 * 1000;

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

async function registerWebhook() {
  if (!token || !webhookSecret || !publicUrl) return;
  try {
    await telegram('setWebhook', {
      url: `${publicUrl}/telegram/webhook`,
      secret_token: webhookSecret,
      allowed_updates: ['message', 'callback_query'],
      drop_pending_updates: true
    });
    console.log('telegram webhook registered');
  } catch (error) {
    console.error('telegram webhook registration failed', error.message);
  }
}

const persistentMenu = {
  keyboard: [[{ text: '📬 Menü' }]],
  resize_keyboard: true,
  is_persistent: true
};

const controlMenu = {
  inline_keyboard: [
    [{ text: '📊 Sistem durumu', callback_data: 'status' }, { text: '📥 Havuz durumu', callback_data: 'pool' }],
    [{ text: '🔑 Parola işlemleri', callback_data: 'password' }, { text: '🔄 Yenile', callback_data: 'menu' }],
    [{ text: '❓ Yardım', callback_data: 'help' }]
  ]
};

function menuText() {
  return 'Clever Vize kontrol merkezi. İşlemler bu menüdeki butonlardan yapılır. IMAP havuzu bağlandığında posta kutusu ve randevu bildirimleri burada açılacak.';
}

function responseFor(action) {
  if (action === 'status') return '🟢 Bot aktif. Render sağlık kontrolü çalışıyor.';
  if (action === 'pool') return '📥 Havuz yönlendirmesi etkin: havuz@clevervize.com gelen postaları Clever Gmail havuzuna iletir. Ajanda bu Gmail hesabını IMAP ile izleyerek bildirimi Telegram’a taşır.';
  if (action === 'password') return '🔑 Parola sıfırlama, gerçek IMAP kullanıcıları bağlandıktan sonra bu menüden yetki kontrolüyle açılacak.';
  if (action === 'help') return 'Alt kısımdaki 📬 Menü düğmesine dilediğiniz an basarak kontrol panelini açabilirsiniz.';
  return menuText();
}

function isAuthorized(chatId) {
  if (allowedChats.has(chatId)) return true;
  const expiresAt = temporaryAuthorizations.get(chatId);
  if (!expiresAt || expiresAt <= Date.now()) {
    temporaryAuthorizations.delete(chatId);
    return false;
  }
  return true;
}

function suppliedPassword(text) {
  const value = String(text || '').trim();
  return value.replace(/^\/giris\s+/i, '').trim();
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}

function inboxEventText(event) {
  const mailbox = String(event?.mailbox || '').trim();
  const from = String(event?.from || '').trim();
  const subject = String(event?.subject || '(konu yok)').trim();
  const snippet = String(event?.snippet || '').replace(/\s+/g, ' ').trim();
  if (!mailbox || !from) return null;
  return [
    '📬 Yeni Clever Vize e-postası',
    '',
    `Kutu: ${mailbox}`,
    `Kimden: ${from}`,
    `Konu: ${subject}`,
    snippet ? `Özet: ${snippet.slice(0, 700)}` : ''
  ].filter(Boolean).join('\n');
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname === '/healthz' && ['GET', 'HEAD'].includes(req.method)) {
    return send(res, 200, req.method === 'HEAD' ? '' : JSON.stringify({ status: 'ok', telegramConfigured: Boolean(token && webhookSecret && allowedChats.size) }));
  }
  if (url.pathname === '/openinbox/event' && req.method === 'POST') {
    if (!safeEqual(req.headers['x-openinbox-event-secret'], inboxEventSecret)) {
      return send(res, 403, JSON.stringify({ error: 'forbidden' }));
    }
    try {
      const event = await readJson(req);
      const text = inboxEventText(event);
      if (!text) return send(res, 400, JSON.stringify({ error: 'invalid-event' }));
      let delivered = 0;
      for (const chatId of allowedChats) {
        await telegram('sendMessage', { chat_id: chatId, text, reply_markup: persistentMenu });
        delivered += 1;
      }
      return send(res, 200, JSON.stringify({ ok: true, delivered }));
    } catch (error) {
      console.error('openinbox event failed', error.message);
      return send(res, 502, JSON.stringify({ error: 'delivery-failed' }));
    }
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
    const callback = update?.callback_query;
    const chatId = String(message?.chat?.id || callback?.message?.chat?.id || '');
    const text = String(message?.text || '');
    if (!isAuthorized(chatId)) {
      const candidate = suppliedPassword(text);
      if (!accessPassword || candidate.length !== accessPassword.length || !crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(accessPassword))) {
        await telegram('sendMessage', { chat_id: chatId, text: 'Erişim için /giris PAROLA yazın.' });
        return send(res, 200, JSON.stringify({ ok: true }));
      }
      temporaryAuthorizations.set(chatId, Date.now() + AUTH_TTL_MS);
      // Parola mümkün olduğunda sohbette kalmaması için giriş mesajını siler.
      if (message?.message_id) await telegram('deleteMessage', { chat_id: chatId, message_id: message.message_id }).catch(() => undefined);
      await telegram('sendMessage', { chat_id: chatId, text: '✅ Erişim verildi. 12 saat boyunca menüyü kullanabilirsiniz.', reply_markup: persistentMenu });
      await telegram('sendMessage', { chat_id: chatId, text: menuText(), reply_markup: controlMenu });
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (callback?.id) await telegram('answerCallbackQuery', { callback_query_id: callback.id });
    const action = callback?.data || (text === '📬 Menü' ? 'menu' : (/^\/(start|help)/i.test(text) ? 'menu' : 'help'));
    if (action === 'menu') {
      await telegram('sendMessage', { chat_id: chatId, text: '📬 Menü sabitlendi.', reply_markup: persistentMenu });
      await telegram('sendMessage', { chat_id: chatId, text: responseFor(action), reply_markup: controlMenu });
    } else {
      await telegram('sendMessage', { chat_id: chatId, text: responseFor(action), reply_markup: persistentMenu });
    }
    return send(res, 200, JSON.stringify({ ok: true }));
  } catch (error) {
    console.error('webhook failed', error.message);
    return send(res, 200, JSON.stringify({ ok: true }));
  }
}).listen(port, '0.0.0.0', () => {
  console.log(`telegram control listening on ${port}`);
  void registerWebhook();
});
