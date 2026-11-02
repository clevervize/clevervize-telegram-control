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
  if (action === 'pool') return '📥 IMAP havuzu henüz bağlanmadı. Havuz bilgileri Randevu Ajanda servisine eklendiğinde burada posta sayısı ve son bildirimler görünür.';
  if (action === 'password') return '🔑 Parola sıfırlama, gerçek IMAP kullanıcıları bağlandıktan sonra bu menüden yetki kontrolüyle açılacak.';
  if (action === 'help') return 'Alt kısımdaki 📬 Menü düğmesine dilediğiniz an basarak kontrol panelini açabilirsiniz.';
  return menuText();
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
    const callback = update?.callback_query;
    const chatId = String(message?.chat?.id || callback?.message?.chat?.id || '');
    if (!allowedChats.has(chatId)) return send(res, 200, JSON.stringify({ ok: true }));
    if (callback?.id) await telegram('answerCallbackQuery', { callback_query_id: callback.id });
    const text = String(message?.text || '');
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
}).listen(port, '0.0.0.0', () => console.log(`telegram control listening on ${port}`));
