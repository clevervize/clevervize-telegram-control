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
const founderMailApiKey = String(process.env.FOUNDERMAIL_API_KEY || '').trim();
const founderMailApiBase = 'https://api.foundermail.mx';
const brevoApiKey = String(process.env.BREVO_API_KEY || '').trim();
const outboundSender = 'info@clevervize.com';
const corporateDomain = 'clevervize.com';
const publicUrl = String(process.env.RENDER_EXTERNAL_URL || process.env.PUBLIC_URL || '').replace(/\/$/, '');
const allowedChats = new Set(String(process.env.TELEGRAM_ALLOWED_CHAT_IDS || '')
  .split(',').map(value => value.trim()).filter(value => /^-?\d{5,20}$/.test(value)));
const temporaryAuthorizations = new Map();
const pendingMailboxNames = new Map();
const pendingOutgoingEmails = new Map();
const protectedMailboxAddresses = new Set(['havuz@clevervize.com', 'info@clevervize.com', 'admin@clevervize.com']);
const AUTH_TTL_MS = 12 * 60 * 60 * 1000;
let openInboxSession = { cookie: '', csrf: '', expiresAt: 0 };
const founderSeenMessages = new Set();
let founderPollingStarted = false;
let founderPollingInitialized = false;

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
    [{ text: '📤 info@ ile mail gönder', callback_data: 'send_email' }],
    [{ text: '❓ Yardım', callback_data: 'help' }]
  ]
};

function menuText() {
  return "Clever Vize e-posta yönetim merkezi. Yeni gerçek posta kutuları FounderMail üzerinde açılır; gelen posta bildirimleri ayrı Clever Vize Ajanda botuna gönderilir.";
}

function responseFor(action) {
  if (action === 'status') return `🟢 Bot aktif. Posta servisi: ${isFounderMailConfigured() ? 'FounderMail hazır' : 'Render değişkenleri eksik'}.`;
  if (action === 'pool') return '📥 Havuz durumu: havuz@clevervize.com korunan ana kutudur. Gelen posta bildirimleri Clever Vize Ajanda botu tarafından izlenir.';
  if (action === 'password') return '🔑 Parola işlemleri için aşağıdan bir posta kutusu seçin.';
  if (action === 'help') return 'Alt kısımdaki 📬 Menü düğmesine dilediğiniz an basarak kontrol panelini açabilirsiniz.';
  return menuText();
}

function isOpenInboxConfigured() {
  return Boolean(openInboxUrl && openInboxAdminEmail && openInboxAdminPassword);
}

function isFounderMailConfigured() { return Boolean(founderMailApiKey); }

async function founderMailRequest(pathname, { method = 'GET', body } = {}) {
  if (!isFounderMailConfigured()) throw new Error('foundermail-not-configured');
  const response = await fetch(`${founderMailApiBase}${pathname}`, {
    method,
    headers: { 'X-Api-Key': founderMailApiKey, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(`foundermail-${response.status}`);
  return payload;
}

async function founderMailboxes() {
  const data = await founderMailRequest('/mailboxes');
  return (Array.isArray(data) ? data : (data?.mailboxes || data?.data || []))
    .filter(box => String(box?.address || '').toLowerCase().endsWith(`@${corporateDomain}`));
}

async function sendInfoEmail({ to, subject, message }) {
  // Gönderimler itibar/teslimat için doğrulanmış Brevo altyapısından çıkar.
  if (!brevoApiKey) throw new Error('brevo-not-configured');
  const response = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'Content-Type': 'application/json', 'api-key': brevoApiKey }, body: JSON.stringify({ sender: { name: 'Clever Vize & Danışmanlık', email: outboundSender }, to: [{ email: to }], replyTo: { email: outboundSender }, subject, textContent: message }) });
  if (!response.ok) throw new Error(`brevo-${response.status}`);
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
    .replace(/[^a-z0-9]+/g, '.').replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.').slice(0, 60);
}

function generatedMailboxPassword() { return crypto.randomBytes(24).toString('base64url'); }

async function createMailbox(displayName) {
  const base = mailboxLocalPart(displayName);
  if (!base || String(displayName).trim().length < 2) throw new Error('invalid-mailbox-name');
  if (isFounderMailConfigured()) {
    const boxes = await founderMailboxes();
    const used = new Set(boxes.map(box => String(box.address || '').toLowerCase()));
    let local = base;
    for (let suffix = 2; used.has(`${local}@${corporateDomain}`) && suffix <= 99; suffix += 1) local = `${base.slice(0, Math.max(1, 61 - String(suffix).length))}.${suffix}`;
    if (used.has(`${local}@${corporateDomain}`)) throw new Error('mailbox-name-exhausted');
    const created = await founderMailRequest('/mailboxes', { method: 'POST', body: { name: local, domain: corporateDomain } });
    const mailbox = created?.mailbox || created;
    return { address: String(mailbox?.address || `${local}@${corporateDomain}`).toLowerCase(), password: typeof mailbox?.password === 'string' ? mailbox.password : '' };
  }
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
  // Yönetici, yeni kişisel kutunun üyesi değildir. Kullanıcıya ait ayar
  // uç noktası bu nedenle 404 verir; yönetici uç noktası üyelik istemez.
  await openInboxRequest(`/admin/mailboxes/${mailbox.id}`, { method: 'PATCH', body: { forwardTo: [openInboxForwardDestination] } });
  return { address: mailbox.address, password: '' };
}

async function listMailboxes() {
  if (isFounderMailConfigured()) return founderMailboxes();
  const mailboxes = await openInboxRequest('/admin/mailboxes');
  return Array.isArray(mailboxes) ? mailboxes : [];
}

async function listMailboxUsers() {
  if (isFounderMailConfigured()) return [];
  const users = await openInboxRequest('/admin/users');
  return Array.isArray(users) ? users : [];
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

function founderMessageText(mailbox, message) {
  const from = Array.isArray(message?.from) ? message.from.join(', ') : String(message?.from || 'Bilinmeyen gönderici');
  const folder = String(message?.folderRole || message?.folder || '').toLowerCase();
  const isJunk = folder === 'junk' || folder === 'spam';
  const plainBody = String(message?.body || '')
    .replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&')
    .replace(/\s+/g, ' ').trim();
  const otp = plainBody.match(/\b\d{4,8}\b/)?.[0] || '';
  return [
    isJunk ? '⚠️ Junk / spam klasörüne yeni e-posta' : '📬 Yeni Clever Vize e-postası',
    '', `Kutu: ${mailbox.address}`, `Kimden: ${from}`,
    `Konu: ${String(message?.subject || '(konu yok)').slice(0, 500)}`,
    `Klasör: ${message?.folder || (isJunk ? 'Junk' : 'INBOX')}`,
    otp ? `OTP: ${otp}` : '',
    plainBody ? `İçerik: ${plainBody.slice(0, 1200)}` : ''
  ].join('\n');
}

async function pollFounderMail() {
  if (!isFounderMailConfigured() || !token || !allowedChats.size) return;
  const mailboxes = await founderMailboxes();
  for (const mailbox of mailboxes) {
    const key = encodeURIComponent(mailbox.address || mailbox.key);
    const result = await founderMailRequest(`/messages/${key}/search?folder=all&take=25`);
    const messages = Array.isArray(result?.messages) ? result.messages : [];
    for (const message of messages) {
      const identity = `${mailbox.address || mailbox.key}:${message?.uniqueId || message?.id}`;
      if (!message?.id || founderSeenMessages.has(identity)) continue;
      founderSeenMessages.add(identity);
      if (!founderPollingInitialized) continue;
      for (const chatId of allowedChats) await telegram('sendMessage', { chat_id: chatId, text: founderMessageText(mailbox, message), reply_markup: persistentMenu });
    }
  }
  if (founderSeenMessages.size > 3000) {
    const keep = [...founderSeenMessages].slice(-1500);
    founderSeenMessages.clear(); for (const key of keep) founderSeenMessages.add(key);
  }
}

async function startFounderPolling() {
  if (founderPollingStarted || !isFounderMailConfigured()) return;
  founderPollingStarted = true;
  // İlk tur yalnızca başlangıç kaydını alır; ardından tüm kutular (Junk dahil)
  // yaklaşık yarım dakikada bir izlenir.
  try {
    const boxes = await founderMailboxes();
    for (const box of boxes) {
      const result = await founderMailRequest(`/messages/${encodeURIComponent(box.address || box.key)}/search?folder=all&take=25`);
      for (const message of (result?.messages || [])) founderSeenMessages.add(`${box.address || box.key}:${message?.uniqueId || message?.id}`);
    }
  } catch (error) { console.error('FounderMail initial scan failed', error.message); }
  founderPollingInitialized = true;
  setInterval(() => { void pollFounderMail().catch(error => console.error('FounderMail poll failed', error.message)); }, 30_000).unref();
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
        const created = await createMailbox(text);
        await telegram('sendMessage', { chat_id: chatId, text: `✅ ${created.address} oluşturuldu.${created.password ? `\n\n🔑 İlk parola:\n<code>${created.password}</code>\n\nBu parolayı hemen güvenli bir yere kaydedin.` : ''}\n\nYeni gelen ve Junk postalar Telegram bildirim akışında izlenir.`, parse_mode: created.password ? 'HTML' : undefined, reply_markup: controlMenu });
      } catch (error) {
        console.error('mailbox create failed', error.message);
        const messageText = error.message === 'foundermail-not-configured' ? '❌ FounderMail anahtarı Render’da henüz girilmemiş.'
          : '❌ Kutu oluşturulamadı. FounderMail bağlantısını kontrol edin.';
        await telegram('sendMessage', { chat_id: chatId, text: messageText, reply_markup: controlMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (pendingOutgoingEmails.has(chatId) && message && text && text !== '📬 Menü') {
      const draft = pendingOutgoingEmails.get(chatId);
      if (!draft.to) { draft.to = text.trim().toLowerCase(); await telegram('sendMessage', { chat_id: chatId, text: 'Konu yazın:', reply_markup: persistentMenu }); return send(res, 200, JSON.stringify({ ok: true })); }
      if (!draft.subject) { draft.subject = text.trim().slice(0, 180); await telegram('sendMessage', { chat_id: chatId, text: 'Mesajı yazın:', reply_markup: persistentMenu }); return send(res, 200, JSON.stringify({ ok: true })); }
      pendingOutgoingEmails.delete(chatId);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(draft.to) || !draft.subject || !text.trim()) { await telegram('sendMessage', { chat_id: chatId, text: '❌ Geçersiz alıcı, konu veya mesaj.', reply_markup: controlMenu }); return send(res, 200, JSON.stringify({ ok: true })); }
      try { await sendInfoEmail({ to: draft.to, subject: draft.subject, message: text.trim().slice(0, 20000) }); await telegram('sendMessage', { chat_id: chatId, text: `✅ E-posta ${outboundSender} adresinden gönderildi.`, reply_markup: controlMenu }); } catch { await telegram('sendMessage', { chat_id: chatId, text: '❌ Gönderim için Brevo API anahtarı veya domain doğrulaması eksik.', reply_markup: controlMenu }); }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    const action = callback?.data || (text === '📬 Menü' ? 'menu' : (/^\/(start|help)/i.test(text) ? 'menu' : 'help'));
    if (action === 'mailbox_create') {
      if (!isFounderMailConfigured()) {
        await telegram('sendMessage', { chat_id: chatId, text: '❌ FounderMail bağlantısı Render’da yapılandırılmamış.', reply_markup: controlMenu });
      } else {
        pendingMailboxNames.set(chatId, Date.now());
        await telegram('sendMessage', { chat_id: chatId, text: 'Adı yazın. Örnek: İsmail Işık → ismail.isik@clevervize.com. Tek ad yazarsanız isim@clevervize.com oluşur.', reply_markup: persistentMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (action === 'send_email') {
      if (!brevoApiKey) await telegram('sendMessage', { chat_id: chatId, text: '❌ Brevo gönderim anahtarı henüz Render’da yok.', reply_markup: controlMenu });
      else { pendingOutgoingEmails.set(chatId, {}); await telegram('sendMessage', { chat_id: chatId, text: 'Alıcı e-posta adresini yazın:', reply_markup: persistentMenu }); }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (action === 'mailbox_list') {
      try {
        const mailboxes = await listMailboxes();
        const lines = mailboxes.slice(0, 30).map(box => `• ${box.address}`);
        const deleteButtons = mailboxes.slice(0, 30)
          .filter(box => !protectedMailboxAddresses.has(String(box.address || '').toLowerCase()))
          .map(box => [{ text: `🗑 ${box.address}`, callback_data: `delete:${encodeURIComponent(box.address || box.key)}` }]);
        await telegram('sendMessage', { chat_id: chatId, text: lines.length ? `📋 Posta kutuları (${mailboxes.length})\nSilmek için aşağıdan bir adres seçin.` : 'Henüz posta kutusu yok.', reply_markup: deleteButtons.length ? { inline_keyboard: [...deleteButtons, [{ text: '↩ Menü', callback_data: 'menu' }]] } : controlMenu });
      } catch (error) {
        console.error('mailbox list failed', error.message);
        await telegram('sendMessage', { chat_id: chatId, text: '❌ Posta kutuları alınamadı. FounderMail Render bağlantısını kontrol edin.', reply_markup: controlMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (action === 'password') {
      if (isFounderMailConfigured()) {
        await telegram('sendMessage', { chat_id: chatId, text: '🔑 İlk parola kutu oluşturulduğunda güvenli biçimde yalnızca bir kez verilir. FounderMail API parola sıfırlama uç noktası sunmadığı için daha sonraki sıfırlama FounderMail kontrol panelinden yapılır.', reply_markup: controlMenu });
        return send(res, 200, JSON.stringify({ ok: true }));
      }
      try {
        const [mailboxes, users] = await Promise.all([listMailboxes(), listMailboxUsers()]);
        const buttons = mailboxes.slice(0, 30).flatMap(box => {
          const member = (box.members || [])[0];
          const user = users.find(item => item.id === member?.userId || String(item.email || '').toLowerCase() === String(box.address || '').toLowerCase());
          return user?.id ? [[{ text: `🔑 ${box.address}`, callback_data: `passwordreset:${user.id}` }]] : [];
        });
        await telegram('sendMessage', {
          chat_id: chatId,
          text: buttons.length ? '🔑 Parolasını oluşturmak/değiştirmek istediğiniz kutuyu seçin. Eski parola geçersiz olur.' : 'Parolası yönetilebilen posta kutusu bulunamadı.',
          reply_markup: buttons.length ? { inline_keyboard: [...buttons, [{ text: '↩ Menü', callback_data: 'menu' }]] } : controlMenu
        });
      } catch (error) {
        console.error('password list failed', error.message);
        await telegram('sendMessage', { chat_id: chatId, text: '❌ Posta kutuları alınamadı. OpenInbox bağlantısını kontrol edin.', reply_markup: controlMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (action.startsWith('passwordreset:')) {
      const userId = action.slice('passwordreset:'.length);
      try {
        const users = await listMailboxUsers();
        const user = users.find(item => String(item.id) === userId);
        if (!user) throw new Error('mailbox-user-not-found');
        const result = await openInboxRequest(`/admin/users/${userId}/reset-password`, { method: 'POST', body: {} });
        if (!result?.password) throw new Error('password-not-returned');
        await telegram('sendMessage', {
          chat_id: chatId,
          text: `✅ ${user.email} için yeni parola oluşturuldu:\n\n<code>${result.password}</code>\n\nBu mesajı kimseyle paylaşmayın; eski parola artık geçersizdir.`,
          parse_mode: 'HTML',
          reply_markup: controlMenu
        });
      } catch (error) {
        console.error('password reset failed', error.message);
        await telegram('sendMessage', { chat_id: chatId, text: '❌ Parola oluşturulamadı. OpenInbox bağlantısını kontrol edin.', reply_markup: controlMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (action.startsWith('delete:')) {
      const mailboxId = decodeURIComponent(action.slice('delete:'.length));
      try {
        const mailbox = (await listMailboxes()).find(item => String(item.id || item.address || item.key) === mailboxId);
        if (!mailbox) throw new Error('mailbox-not-found');
        if (protectedMailboxAddresses.has(String(mailbox.address || '').toLowerCase())) throw new Error('protected-mailbox');
        await telegram('sendMessage', {
          chat_id: chatId,
          text: `⚠️ ${mailbox.address} kutusu ve içindeki postalar kalıcı olarak silinecek.`,
          reply_markup: { inline_keyboard: [[{ text: '🗑 Evet, kalıcı sil', callback_data: `confirmdelete:${encodeURIComponent(mailbox.address || mailbox.key)}` }, { text: 'Vazgeç', callback_data: 'mailbox_list' }]] }
        });
      } catch {
        await telegram('sendMessage', { chat_id: chatId, text: '❌ Kutu bulunamadı.', reply_markup: controlMenu });
      }
      return send(res, 200, JSON.stringify({ ok: true }));
    }
    if (action.startsWith('confirmdelete:')) {
      const mailboxId = decodeURIComponent(action.slice('confirmdelete:'.length));
      try {
        const mailbox = (await listMailboxes()).find(item => String(item.id || item.address || item.key) === mailboxId);
        if (!mailbox) throw new Error('mailbox-not-found');
        if (protectedMailboxAddresses.has(String(mailbox.address || '').toLowerCase())) throw new Error('protected-mailbox');
        if (isFounderMailConfigured()) await founderMailRequest(`/mailboxes/${encodeURIComponent(mailbox.address || mailbox.key)}`, { method: 'DELETE' });
        else await openInboxRequest(`/admin/mailboxes/${mailbox.id}?confirm=${encodeURIComponent(mailbox.address)}`, { method: 'DELETE' });
        await telegram('sendMessage', { chat_id: chatId, text: `✅ ${mailbox.address} kalıcı olarak silindi.`, reply_markup: controlMenu });
      } catch (error) {
        console.error('mailbox delete failed', error.message);
        await telegram('sendMessage', { chat_id: chatId, text: '❌ Kutu silinemedi.', reply_markup: controlMenu });
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
