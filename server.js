const http = require('node:http');
const crypto = require('node:crypto');

const port = Number(process.env.PORT || 3000);
const token = String(process.env.TELEGRAM_BOT_TOKEN || '').trim();
const webhookSecret = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const accessPassword = String(process.env.TELEGRAM_ACCESS_PASSWORD || '').trim();
// OpenInbox Worker posts only a compact, signed event here.  This is separate
// from Telegram's webhook secret so one integration cannot impersonate the other.
const inboxEventSecret = String(process.env.OPENINBOX_EVENT_SECRET || '').trim();
const openInboxUrl = String(process.env.OPENINBOX_URL || '').trim().replace(/\/$/, '');
const openInboxAdminEmail = String(process.env.OPENINBOX_ADMIN_EMAIL || '').trim().toLowerCase();
const openInboxAdminPassword = String(process.env.OPENINBOX_ADMIN_PASSWORD || '');
const openInboxForwardDestination = String(process.env.OPENINBOX_FORWARD_DESTINATION || 'clevervize@gmail.com').trim().toLowerCase();
const corporateDomain = 'clevervize.com';
const publicUrl = String(process.env.RENDER_EXTERNAL_URL || process.env.PUBLIC_URL || '').replace(/\/$/, '');
const allowedChats = new Set(String(process.env.TELEGRAM_ALLOWED_CHAT_IDS || '')
  .split(',').map(value => value.trim()).filter(value => /^-?\d{5,20}$/.test(value)));
const temporaryAuthorizations = new Map();
const pendingMailboxNames = new Map();
const AUTH_TTL_MS = 12 * 60 * 60 * 1000;
let openInboxSession = { cookie: '', csrf: '', expiresAt: 0 };

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
    [{ text: '➕ Yeni e-posta kutusu', callback_data: 'mailbox_create' }, { text: '📋 Kutuları listele', callback_data: 'mailbox_list' }],
    [{ text: '📊 Sistem durumu', callback_data: 'status' }, { text: '📥 Havuz durumu', callback_data: 'pool' }],
    [{ text: '🔑 Parola işlemleri', callback_data: 'password' }, { text: '🔄 Yenile', callback_data: 'menu' }],
    [{ text: '❓ Yardım', callback_data: 'help' }]
  ]
};

function menuText() {
  return 'Clever Vize e-posta kontrol merkezi. Yeni kutu açıldığında adres otomatik olarak Gmail havuzuna yönlendirilir; Ajanda buradan Telegram bildirimi üretir.';
}

function responseFor(action) {
  if (action === 'status') return `🟢 Bot aktif. OpenInbox bağlantısı: ${isOpenInboxConfigured() ? 'hazır' : 'Render değişkenleri eksik'}.`;
  if (action === 'pool') return '📥 Havuz yönlendirmesi etkin: havuz@clevervize.com gelen postaları Clever Gmail havuzuna iletir. Ajanda bu Gmail hesabını IMAP ile izleyerek bildirimi Telegram’a taşır.';
  if (action === 'password') return '🔑 Parola sıfırlama ve silme kontrolleri bir sonraki menü güncellemesinde her kutunun yanında yer alacak.';
  if (action === 'help') return 'Alt kısımdaki 📬 Menü düğmesine dilediğiniz an basarak kontrol panelini açabilirsiniz.';
  return menuText();
}

function isOpenInboxConfigured() {
  return Boolean(openInboxUrl && openInboxAdminEmail && openInboxAdminPassword);
}

function cookiePairs(response) {
  const values = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
  return values.filter(Boolean).map(value => String(value).split(';', 1)[0]).filter(Boolean);
}

function mergeCookies(current, incoming) {
  const jar = new Map(String(current || '').split(/;\s*/).filter(Boolean).map(pair => {
    const index = pair.indexOf('='); return index > 0 ? [pair.slice(0, index), pair] : [];
  }).filter(pair => pair.length));
  for (const pair of incoming) { const index = pair.indexOf('='); if (index > 0) jar.set(pair.slice(0, index), pair); }
  return [...jar.values()].join('; ');
}

function csrfFromCookies(cookie) {
  return String(cookie || '').split(/;\s*/).find(pair => pair.startsWith('oi_csrf='))?.slice('oi_csrf='.length) || '';
}

async function openInboxRequest(pathname, { method = 'GET', body, retry = true } = {}) {
  if (!isOpenInboxConfigured()) throw new Error('openinbox-not-configured');
  const now = Date.now();
  if (!openInboxSession.cookie || openInboxSession.expiresAt < now) {
    const session = await fetch(`${openInboxUrl}/api/auth/session`);
    if (!session.ok) throw new Error('openinbox-unavailable');
    openInboxSession.cookie = mergeCookies('', cookiePairs(session));
    openInboxSession.csrf = csrfFromCookies(openInboxSession.cookie);
    const login = await fetch(`${openInboxUrl}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: openInboxSession.cookie, 'X-CSRF-Token': openInboxSession.csrf }, body: JSON.stringify({ email: openInboxAdminEmail, password: openInboxAdminPassword }) });
    openInboxSession.cookie = mergeCookies(openInboxSession.cookie, cookiePairs(login));
    openInboxSession.csrf = csrfFromCookies(openInboxSession.cookie);
    if (!login.ok) { openInboxSession = { cookie: '', csrf: '', expiresAt: 0 }; throw new Error('openinbox-login-failed'); }
    openInboxSession.expiresAt = now + 20 * 60 * 1000;
  }
  const response = await fetch(`${openInboxUrl}/api${pathname}`, { method, headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), Cookie: openInboxSession.cookie, ...(method === 'GET' ? {} : { 'X-CSRF-Token': openInboxSession.csrf }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if ((response.status === 401 || response.status === 403) && retry) { openInboxSession = { cookie: '', csrf: '', expiresAt: 0 }; return openInboxRequest(pathname, { method, body, retry: false }); }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`openinbox-${response.status}`);
  return payload;
}

function mailboxLocalPart(name) {
  return String(name || '').toLocaleLowerCase('tr-TR').normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/ı/g, 'i').replace(/ş/g, 's').replace(/ğ/g, 'g').replace(/ü/g, 'u').replace(/ö/g, 'o').replace(/ç/g, 'c')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}

function generatedMailboxPassword() { return crypto.randomBytes(24).toString('base64url'); }

async function createMailbox(displayName) {
  const base = mailboxLocalPart(displayName);
  if (!base || String(displayName).trim().length < 2) throw new Error('invalid-mailbox-name');
  const [domains, users, mailboxes, destinations] = await Promise.all([
    openInboxRequest('/admin/domains'), openInboxRequest('/admin/users'), openInboxRequest('/admin/mailboxes'), openInboxRequest('/admin/forwarding')
  ]);
  const domain = domains.find(item => item.name === corporateDomain && item.status !== 'disabled');
  const verified = destinations.find(item => String(item?.address || '').toLowerCase() === openInboxForwardDestination && item?.verified);
  if (!domain) throw new Error('openinbox-domain-unavailable');
  if (!verified) throw new Error('openinbox-forward-destination-unverified');
  const used = new Set([...mailboxes.map(item => String(item?.address || '').toLowerCase()), ...users.map(item => String(item?.email || '').toLowerCase())]);
  let local = base;
  for (let suffix = 2; used.has(`${local}@${corporateDomain}`) && suffix <= 99; suffix += 1) local = `${base.slice(0, Math.max(1, 61 - String(suffix).length))}-${suffix}`;
  if (used.has(`${local}@${corporateDomain}`)) throw new Error('mailbox-name-exhausted');
  await openInboxRequest('/admin/users', { method: 'POST', body: { name: String(displayName).trim().slice(0, 100), role: 'member', email: `${local}@${corporateDomain}`, password: generatedMailboxPassword(), newMailbox: { localPart: local, domainId: domain.id }, mailboxIds: [] } });
  const createdBoxes = await openInboxRequest('/admin/mailboxes');
  const mailbox = createdBoxes.find(item => String(item?.address || '').toLowerCase() === `${local}@${corporateDomain}`);
  if (!mailbox?.id) throw new Error('openinbox-mailbox-not-created');
  await openInboxRequest(`/mailboxes/${mailbox.id}/settings`, { method: 'PATCH', body: { forwardTo: [openInboxForwardDestination] } });
  return mailbox.address;
}

async function listMailboxes() {
  const mailboxes = await openInboxRequest('/admin/mailboxes');
  return Array.isArray(mailboxes) ? mailboxes : [];
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
    if (pendingMailboxNames.has(chatId) && message && text && text !== '📬 Menü') {
      pendingMailboxNames.delete(chatId);
      try {
        const address = await createMailbox(text);
        await telegram('sendMessage', { chat_id: chatId, text: `✅ ${address} oluşturuldu. Gelen tüm postalar ${openInboxForwardDestination} havuzuna yönlendirilir.`, reply_markup: controlMenu });
      } catch (error) {
        console.error('mailbox create failed', error.message);
        const messageText = error.message === 'openinbox-not-configured' ? '❌ OpenInbox gizli Render değişkenleri henüz girilmemiş.'
          : error.message === 'openinbox-forward-destination-unverified' ? '❌ Gmail havuz yönlendirme adresi OpenInbox’ta doğrulanmamış.'
          : '❌ Kutu oluşturulamadı. OpenInbox bağlantısını kontrol edin.';
        await telegram('sendMessage', { chat_id: chatId, text: messageText, reply_markup: controlMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    const action = callback?.data || (text === '📬 Menü' ? 'menu' : (/^\/(start|help)/i.test(text) ? 'menu' : 'help'));
    if (action === 'mailbox_create') {
      if (!isOpenInboxConfigured()) {
        await telegram('sendMessage', { chat_id: chatId, text: '❌ OpenInbox bağlantısı Render’da yapılandırılmamış. Yönetici gizli değerleri eklediğinde tekrar deneyin.', reply_markup: controlMenu });
      } else {
        pendingMailboxNames.set(chatId, Date.now());
        await telegram('sendMessage', { chat_id: chatId, text: 'Yeni kutu için sadece isim yazın. Örnek: VFS Fransa → vfs-fransa@clevervize.com', reply_markup: persistentMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (action === 'mailbox_list') {
      try {
        const mailboxes = await listMailboxes();
        const lines = mailboxes.slice(0, 60).map(box => `• ${box.address}`);
        await telegram('sendMessage', { chat_id: chatId, text: lines.length ? `📋 Posta kutuları (${mailboxes.length})\n${lines.join('\n')}` : 'Henüz posta kutusu yok.', reply_markup: controlMenu });
      } catch (error) {
        console.error('mailbox list failed', error.message);
        await telegram('sendMessage', { chat_id: chatId, text: '❌ Posta kutuları alınamadı. OpenInbox Render bağlantısını kontrol edin.', reply_markup: controlMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
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
