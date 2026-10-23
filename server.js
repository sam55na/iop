/* =========================================================
   WORLD WAR - Server (النسخة النهائية الكاملة)
   يشمل: المصادقة، السحب، الإدارة، الدعم الفني، الإشعارات الجماعية
   ========================================================= */

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'worldwar_super_secret_change_me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.db');
const IS_PROD = process.env.NODE_ENV === 'production';
const ADMIN_NAME = 'sam55namsam55namsam55nam';
const WITHDRAW_COOLDOWN_MS = 10 * 60 * 1000;

// ⚠️ كلمة مرور الوصول للإدارة (إلزامية من متغيرات البيئة)
const ADMIN_ACCESS_PASSWORD = process.env.ADMIN_ACCESS_PASSWORD;
if (!ADMIN_ACCESS_PASSWORD || ADMIN_ACCESS_PASSWORD.length < 8) {
  console.error('❌ [CRITICAL] ADMIN_ACCESS_PASSWORD غير معرف أو أقل من 8 أحرف!');
  console.error('   عيّن متغير البيئة ADMIN_ACCESS_PASSWORD بقيمة قوية قبل التشغيل.');
  process.exit(1);
}
const ADMIN_ACCESS_HASH = bcrypt.hashSync(ADMIN_ACCESS_PASSWORD, 10);
console.log('✅ [Security] تم تحميل كلمة مرور الإدارة وتشفيرها في الذاكرة.');

// --- تهيئة قاعدة البيانات ---
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) { try { fs.mkdirSync(dbDir, { recursive: true }); } catch (err) {} }
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0, role TEXT NOT NULL DEFAULT 'user',
    last_withdraw_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT,
    action TEXT NOT NULL, details TEXT, ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS withdraw_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    min_amount REAL NOT NULL DEFAULT 0, fee_percent REAL NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS withdraw_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, user_name TEXT NOT NULL,
    method_id INTEGER NOT NULL, method_name TEXT NOT NULL,
    amount REAL NOT NULL, fee_percent REAL NOT NULL, fee_amount REAL NOT NULL,
    net_amount REAL NOT NULL, address TEXT NOT NULL,
    balance_before REAL NOT NULL, balance_after REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    processed_by TEXT, processed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS admin_access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT,
    success INTEGER NOT NULL, ip TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS support_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, user_name TEXT NOT NULL,
    subject TEXT, status TEXT NOT NULL DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_by TEXT, closed_at DATETIME
  );
  CREATE TABLE IF NOT EXISTS support_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    sender_role TEXT NOT NULL,
    sender_name TEXT NOT NULL,
    body TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS user_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec(`ALTER TABLE users ADD COLUMN last_withdraw_at DATETIME;`); } catch (e) {}

// =========================================================
// 🌐 Middleware
// =========================================================
app.set('trust proxy', 1);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

function logActivity(userId, userName, action, details, req) {
  try {
    const ip = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '') : '';
    db.prepare('INSERT INTO activity_logs (user_id, user_name, action, details, ip) VALUES (?, ?, ?, ?, ?)')
      .run(userId || null, userName || 'زائر', action, details || '', String(ip).split(',')[0].trim());
  } catch (e) {}
}

function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, name, balance, role FROM users WHERE id = ?').get(payload.id);
    if (!user) return res.status(401).json({ error: 'المستخدم غير موجود' });
    req.user = user; next();
  } catch { res.status(401).json({ error: 'توكن غير صالح' }); }
}

function isAdmin(req, res, next) {
  if (req.user.role === 'admin' && req.user.name === ADMIN_NAME) return next();
  return res.status(403).json({ error: 'مخصص للإدارة' });
}

const adminAttempts = new Map();
function checkAdminRateLimit(userId) {
  const now = Date.now();
  const rec = adminAttempts.get(userId);
  if (!rec || now > rec.resetAt) {
    adminAttempts.set(userId, { count: 0, resetAt: now + 15 * 60 * 1000 });
    return { ok: true };
  }
  if (rec.count >= 5) {
    return { ok: false, retryAfter: Math.ceil((rec.resetAt - now) / 1000) };
  }
  return { ok: true };
}
function bumpAdminAttempt(userId) {
  const now = Date.now();
  const rec = adminAttempts.get(userId);
  if (!rec || now > rec.resetAt) adminAttempts.set(userId, { count: 1, resetAt: now + 15 * 60 * 1000 });
  else rec.count += 1;
}
function clearAdminAttempts(userId) { adminAttempts.delete(userId); }

function adminAuth(req, res, next) {
  const t = req.headers['x-admin-token'];
  if (!t) return res.status(401).json({ error: 'انتهت جلسة الإدارة، أعد إدخال كلمة المرور' });
  try {
    const p = jwt.verify(t, JWT_SECRET);
    if (p.scope !== 'admin' || p.id !== req.user.id) {
      return res.status(401).json({ error: 'توكن إدارة غير صالح' });
    }
    next();
  } catch { return res.status(401).json({ error: 'انتهت جلسة الإدارة، أعد إدخال كلمة المرور' }); }
}

// =========================================================
// 🔑 المصادقة
// =========================================================
app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const password = String(req.body.password || '');
    if (!name || !password) return res.status(400).json({ error: 'الاسم وكلمة المرور مطلوبان' });
    const exists = db.prepare('SELECT id FROM users WHERE name = ?').get(name);
    if (exists) return res.status(409).json({ error: 'هذا الاسم مستخدم مسبقاً' });

    const hash = await bcrypt.hash(password, 10);
    const role = (name === ADMIN_NAME) ? 'admin' : 'user';
    const info = db.prepare('INSERT INTO users (name, password, role) VALUES (?, ?, ?)').run(name, hash, role);
    logActivity(info.lastInsertRowid, name, 'register', 'إنشاء حساب جديد', req);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      logActivity(user ? user.id : null, name, 'login_fail', 'محاولة دخول فاشلة', req);
      return res.status(401).json({ error: 'البيانات خاطئة' });
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, maxAge: 7 * 24 * 60 * 60 * 1000 });
    logActivity(user.id, user.name, 'login', 'تسجيل دخول ناجح', req);
    res.json({ ok: true, user: { id: user.id, name: user.name, balance: user.balance, role: user.role } });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/logout', auth, (req, res) => {
  logActivity(req.user.id, req.user.name, 'logout', 'تسجيل خروج', req);
  res.clearCookie('token').json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

// =========================================================
// 🛡️ التحقق من كلمة مرور الإدارة
// =========================================================
app.get('/api/admin/check', auth, (req, res) => {
  res.json({ isAdminCandidate: req.user.role === 'admin' && req.user.name === ADMIN_NAME });
});

app.post('/api/admin/unlock', auth, async (req, res) => {
  try {
    if (!(req.user.role === 'admin' && req.user.name === ADMIN_NAME)) {
      logActivity(req.user.id, req.user.name, 'admin_unlock_forbidden', 'محاولة وصول إدارة غير مصرح بها', req);
      return res.status(403).json({ error: 'غير مصرح' });
    }
    const rl = checkAdminRateLimit(req.user.id);
    if (!rl.ok) {
      db.prepare('INSERT INTO admin_access_log (user_id, user_name, success, ip) VALUES (?, ?, 0, ?)')
        .run(req.user.id, req.user.name, String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim());
      return res.status(429).json({ error: `محاولات كثيرة، انتظر ${Math.ceil(rl.retryAfter/60)} دقيقة` });
    }
    const pwd = String(req.body.password || '');
    if (!pwd) return res.status(400).json({ error: 'أدخل كلمة المرور' });
    const ok = await bcrypt.compare(pwd, ADMIN_ACCESS_HASH);
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (!ok) {
      bumpAdminAttempt(req.user.id);
      db.prepare('INSERT INTO admin_access_log (user_id, user_name, success, ip) VALUES (?, ?, 0, ?)')
        .run(req.user.id, req.user.name, ip);
      logActivity(req.user.id, req.user.name, 'admin_unlock_fail', 'كلمة مرور إدارة خاطئة', req);
      return res.status(401).json({ error: 'كلمة المرور خاطئة' });
    }
    clearAdminAttempts(req.user.id);
    db.prepare('INSERT INTO admin_access_log (user_id, user_name, success, ip) VALUES (?, ?, 1, ?)')
      .run(req.user.id, req.user.name, ip);
    logActivity(req.user.id, req.user.name, 'admin_unlock_ok', 'فتح لوحة الإدارة', req);
    const adminToken = jwt.sign({ id: req.user.id, scope: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ ok: true, adminToken });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

// =========================================================
// 💸 المستخدم - طرق السحب
// =========================================================
app.get('/api/withdraw-methods', auth, (req, res) => {
  const list = db.prepare('SELECT id, name, min_amount, fee_percent FROM withdraw_methods ORDER BY id DESC').all();
  res.json({ methods: list });
});

app.get('/api/withdraw/status', auth, (req, res) => {
  const u = db.prepare('SELECT last_withdraw_at FROM users WHERE id = ?').get(req.user.id);
  const last = u.last_withdraw_at ? new Date(u.last_withdraw_at).getTime() : 0;
  const remaining = Math.max(0, WITHDRAW_COOLDOWN_MS - (Date.now() - last));
  res.json({ cooldownRemaining: remaining, lastWithdrawAt: u.last_withdraw_at });
});

app.post('/api/withdraw/request', auth, (req, res) => {
  try {
    const { method_id, amount, address } = req.body;
    const amt = Number(amount);
    if (!method_id || !amt || amt <= 0 || !address || !String(address).trim()) {
      return res.status(400).json({ error: 'يرجى تعبئة جميع الحقول بشكل صحيح' });
    }
    const method = db.prepare('SELECT * FROM withdraw_methods WHERE id = ?').get(method_id);
    if (!method) return res.status(400).json({ error: 'طريقة السحب غير موجودة' });

    const u = db.prepare('SELECT last_withdraw_at, balance FROM users WHERE id = ?').get(req.user.id);
    if (u.last_withdraw_at) {
      const elapsed = Date.now() - new Date(u.last_withdraw_at).getTime();
      if (elapsed < WITHDRAW_COOLDOWN_MS) {
        const rem = Math.ceil((WITHDRAW_COOLDOWN_MS - elapsed) / 1000);
        return res.status(429).json({ error: `يرجى الانتظار ${Math.ceil(rem/60)} دقيقة قبل طلب سحب جديد` });
      }
    }
    if (amt < method.min_amount) return res.status(400).json({ error: `الحد الأدنى للسحب بهذه الطريقة ${method.min_amount}` });
    if (amt > u.balance) return res.status(400).json({ error: 'رصيدك غير كافٍ' });

    const feeAmount = +(amt * method.fee_percent / 100).toFixed(2);
    const netAmount = +(amt - feeAmount).toFixed(2);
    const balanceBefore = u.balance;
    const balanceAfter = +(u.balance - amt).toFixed(2);

    db.prepare('UPDATE users SET balance = ?, last_withdraw_at = CURRENT_TIMESTAMP WHERE id = ?').run(balanceAfter, req.user.id);

    const info = db.prepare(`INSERT INTO withdraw_requests
      (user_id, user_name, method_id, method_name, amount, fee_percent, fee_amount, net_amount, address, balance_before, balance_after, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`)
      .run(req.user.id, req.user.name, method.id, method.name, amt, method.fee_percent, feeAmount, netAmount, String(address).trim(), balanceBefore, balanceAfter);

    logActivity(req.user.id, req.user.name, 'withdraw_request', `طلب سحب #${info.lastInsertRowid} - ${amt} - ${method.name}`, req);
    res.json({ ok: true, message: 'تم إرسال طلب السحب بنجاح', requestId: info.lastInsertRowid });
  } catch (err) { res.status(500).json({ error: 'خطأ في معالجة الطلب' }); }
});

// =========================================================
// 💬 الدعم الفني - المستخدم
// =========================================================
app.get('/api/support/ticket', auth, (req, res) => {
  let ticket = db.prepare("SELECT * FROM support_tickets WHERE user_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1").get(req.user.id);
  if (!ticket) {
    const info = db.prepare("INSERT INTO support_tickets (user_id, user_name, subject, status) VALUES (?, ?, ?, 'open')")
      .run(req.user.id, req.user.name, 'استفسار جديد');
    ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(info.lastInsertRowid);
  }
  const messages = db.prepare('SELECT * FROM support_messages WHERE ticket_id = ? ORDER BY id ASC').all(ticket.id);
  db.prepare("UPDATE support_messages SET is_read = 1 WHERE ticket_id = ? AND sender_role = 'admin' AND is_read = 0").run(ticket.id);
  res.json({ ticket, messages });
});

app.post('/api/support/message', auth, (req, res) => {
  try {
    const body = String(req.body.body || '').trim();
    if (!body) return res.status(400).json({ error: 'الرسالة فارغة' });
    if (body.length > 2000) return res.status(400).json({ error: 'الرسالة طويلة جداً' });

    let ticket = db.prepare("SELECT * FROM support_tickets WHERE user_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1").get(req.user.id);
    if (!ticket) {
      const info = db.prepare("INSERT INTO support_tickets (user_id, user_name, subject, status) VALUES (?, ?, ?, 'open')")
        .run(req.user.id, req.user.name, 'استفسار جديد');
      ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(info.lastInsertRowid);
    }
    const info = db.prepare("INSERT INTO support_messages (ticket_id, sender_role, sender_name, body) VALUES (?, 'user', ?, ?)")
      .run(ticket.id, req.user.name, body);
    db.prepare('UPDATE support_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(ticket.id);
    logActivity(req.user.id, req.user.name, 'support_message', `رسالة دعم في التذكرة #${ticket.id}`, req);
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.get('/api/support/unread-count', auth, (req, res) => {
  const row = db.prepare(`
    SELECT COUNT(*) as c FROM support_messages m
    JOIN support_tickets t ON t.id = m.ticket_id
    WHERE t.user_id = ? AND m.sender_role = 'admin' AND m.is_read = 0
  `).get(req.user.id);
  res.json({ unread: row.c });
});

// =========================================================
// 🔔 إشعارات المستخدم
// =========================================================
app.get('/api/notifications', auth, (req, res) => {
  const list = db.prepare('SELECT * FROM user_notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(req.user.id);
  const unread = list.filter(n => !n.is_read).length;
  res.json({ notifications: list, unread });
});
app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare('UPDATE user_notifications SET is_read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

// =========================================================
// 🛡️ APIs الإدارة
// =========================================================
app.get('/api/admin/overview', auth, isAdmin, adminAuth, (req, res) => {
  const stats = {
    users: db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    totalBalance: db.prepare('SELECT COALESCE(SUM(balance),0) as s FROM users').get().s,
    pendingWithdraws: db.prepare("SELECT COUNT(*) as c FROM withdraw_requests WHERE status='pending'").get().c,
    methods: db.prepare('SELECT COUNT(*) as c FROM withdraw_methods').get().c,
    openTickets: db.prepare("SELECT COUNT(*) as c FROM support_tickets WHERE status='open'").get().c,
  };
  res.json(stats);
});

app.get('/api/admin/logs', auth, isAdmin, adminAuth, (req, res) => {
  const limit = Math.min(200, Number(req.query.limit) || 100);
  const logs = db.prepare('SELECT * FROM activity_logs ORDER BY id DESC LIMIT ?').all(limit);
  res.json({ logs });
});

app.get('/api/admin/logs/:id', auth, isAdmin, adminAuth, (req, res) => {
  const log = db.prepare('SELECT * FROM activity_logs WHERE id = ?').get(req.params.id);
  if (!log) return res.status(404).json({ error: 'غير موجود' });
  let user = null;
  if (log.user_id) user = db.prepare('SELECT id, name, balance, role, created_at FROM users WHERE id = ?').get(log.user_id);
  res.json({ log, user });
});

// طرق السحب
app.get('/api/admin/withdraw-methods', auth, isAdmin, adminAuth, (req, res) => {
  res.json({ methods: db.prepare('SELECT * FROM withdraw_methods ORDER BY id DESC').all() });
});
app.post('/api/admin/withdraw-methods', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const { name, min_amount, fee_percent } = req.body;
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'اسم الطريقة مطلوب' });
    const minAmt = Number(min_amount) || 0;
    const fee = Number(fee_percent) || 0;
    if (minAmt < 0 || fee < 0 || fee > 100) return res.status(400).json({ error: 'قيم غير صالحة' });
    const info = db.prepare('INSERT INTO withdraw_methods (name, min_amount, fee_percent) VALUES (?, ?, ?)')
      .run(String(name).trim(), minAmt, fee);
    logActivity(req.user.id, req.user.name, 'admin_add_method', `إضافة طريقة سحب: ${name}`, req);
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});
app.delete('/api/admin/withdraw-methods/:id', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const m = db.prepare('SELECT * FROM withdraw_methods WHERE id = ?').get(req.params.id);
    if (!m) return res.status(404).json({ error: 'غير موجود' });
    db.prepare('DELETE FROM withdraw_methods WHERE id = ?').run(req.params.id);
    logActivity(req.user.id, req.user.name, 'admin_del_method', `حذف طريقة سحب: ${m.name}`, req);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

// طلبات السحب
app.get('/api/admin/withdraw-requests', auth, isAdmin, adminAuth, (req, res) => {
  const status = req.query.status || 'pending';
  let list;
  if (status === 'all') list = db.prepare('SELECT * FROM withdraw_requests ORDER BY id DESC LIMIT 200').all();
  else list = db.prepare('SELECT * FROM withdraw_requests WHERE status = ? ORDER BY id DESC LIMIT 200').all(status);
  res.json({ requests: list });
});

app.get('/api/admin/withdraw-requests/:id', auth, isAdmin, adminAuth, (req, res) => {
  const r = db.prepare('SELECT * FROM withdraw_requests WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ error: 'غير موجود' });
  const user = db.prepare('SELECT id, name, balance, role, created_at FROM users WHERE id = ?').get(r.user_id);
  res.json({ request: r, user });
});

app.post('/api/admin/withdraw-requests/:id/approve', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const r = db.prepare('SELECT * FROM withdraw_requests WHERE id = ?').get(req.params.id);
    if (!r) return res.status(404).json({ error: 'غير موجود' });
    if (r.status !== 'pending') return res.status(400).json({ error: 'تمت معالجته مسبقاً' });
    db.prepare("UPDATE withdraw_requests SET status='approved', processed_by=?, processed_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(req.user.name, r.id);
    db.prepare('INSERT INTO user_notifications (user_id, title, body) VALUES (?, ?, ?)')
      .run(r.user_id, 'تم تنفيذ طلب السحب', `تمت الموافقة على طلب سحبك #${r.id} بمبلغ ${r.amount}. المبلغ الصافي المرسل: ${r.net_amount}.`);
    logActivity(req.user.id, req.user.name, 'admin_approve_withdraw', `موافقة على طلب سحب #${r.id}`, req);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/admin/withdraw-requests/:id/reject', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const r = db.prepare('SELECT * FROM withdraw_requests WHERE id = ?').get(req.params.id);
    if (!r) return res.status(404).json({ error: 'غير موجود' });
    if (r.status !== 'pending') return res.status(400).json({ error: 'تمت معالجته مسبقاً' });
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(r.amount, r.user_id);
    db.prepare("UPDATE withdraw_requests SET status='rejected', processed_by=?, processed_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(req.user.name, r.id);
    db.prepare('INSERT INTO user_notifications (user_id, title, body) VALUES (?, ?, ?)')
      .run(r.user_id, 'تم رفض طلب السحب', `تم رفض طلب سحبك #${r.id} وإعادة المبلغ (${r.amount}) إلى محفظتك.`);
    logActivity(req.user.id, req.user.name, 'admin_reject_withdraw', `رفض طلب سحب #${r.id} وإعادة ${r.amount}`, req);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

// المستخدمون
app.get('/api/admin/users', auth, isAdmin, adminAuth, (req, res) => {
  const q = String(req.query.q || '').trim();
  let list;
  if (q) list = db.prepare('SELECT id, name, balance, role, created_at, last_withdraw_at FROM users WHERE name LIKE ? ORDER BY id DESC LIMIT 200').all(`%${q}%`);
  else list = db.prepare('SELECT id, name, balance, role, created_at, last_withdraw_at FROM users ORDER BY id DESC LIMIT 200').all();
  res.json({ users: list });
});

app.get('/api/admin/users/:id', auth, isAdmin, adminAuth, (req, res) => {
  const u = db.prepare('SELECT id, name, balance, role, created_at, last_withdraw_at FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'غير موجود' });
  const withdraws = db.prepare('SELECT * FROM withdraw_requests WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(u.id);
  const logs = db.prepare('SELECT * FROM activity_logs WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(u.id);
  res.json({ user: u, withdraws, logs });
});

app.post('/api/admin/users/:id/balance', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const delta = Number(req.body.delta);
    if (!Number.isFinite(delta)) return res.status(400).json({ error: 'قيمة غير صالحة' });
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!u) return res.status(404).json({ error: 'المستخدم غير موجود' });
    const newBalance = +(u.balance + delta).toFixed(2);
    if (newBalance < 0) return res.status(400).json({ error: 'لا يمكن أن يكون الرصيد سالباً' });
    db.prepare('UPDATE users SET balance = ? WHERE id = ?').run(newBalance, u.id);
    logActivity(req.user.id, req.user.name, 'admin_edit_balance',
      `تعديل رصيد ${u.name}: ${delta > 0 ? '+' : ''}${delta} (من ${u.balance} إلى ${newBalance})`, req);
    res.json({ ok: true, newBalance });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

// =========================================================
// 💬 الدعم - الإدارة
// =========================================================
app.get('/api/admin/support/tickets', auth, isAdmin, adminAuth, (req, res) => {
  const status = req.query.status || 'open';
  let list;
  if (status === 'all') {
    list = db.prepare('SELECT * FROM support_tickets ORDER BY updated_at DESC LIMIT 200').all();
  } else {
    list = db.prepare('SELECT * FROM support_tickets WHERE status = ? ORDER BY updated_at DESC LIMIT 200').all(status);
  }
  const enriched = list.map(t => {
    const lastMsg = db.prepare('SELECT body, sender_role, created_at FROM support_messages WHERE ticket_id = ? ORDER BY id DESC LIMIT 1').get(t.id);
    const unread = db.prepare("SELECT COUNT(*) as c FROM support_messages WHERE ticket_id = ? AND sender_role = 'user' AND is_read = 0").get(t.id).c;
    return { ...t, last_message: lastMsg || null, unread_count: unread };
  });
  res.json({ tickets: enriched });
});

app.get('/api/admin/support/tickets/:id', auth, isAdmin, adminAuth, (req, res) => {
  const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'غير موجود' });
  const messages = db.prepare('SELECT * FROM support_messages WHERE ticket_id = ? ORDER BY id ASC').all(ticket.id);
  db.prepare("UPDATE support_messages SET is_read = 1 WHERE ticket_id = ? AND sender_role = 'user' AND is_read = 0").run(ticket.id);
  res.json({ ticket, messages });
});

app.post('/api/admin/support/tickets/:id/reply', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const body = String(req.body.body || '').trim();
    if (!body) return res.status(400).json({ error: 'الرسالة فارغة' });
    if (body.length > 2000) return res.status(400).json({ error: 'الرسالة طويلة جداً' });
    const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(req.params.id);
    if (!ticket) return res.status(404).json({ error: 'غير موجود' });
    if (ticket.status !== 'open') return res.status(400).json({ error: 'التذكرة مغلقة' });
    db.prepare("INSERT INTO support_messages (ticket_id, sender_role, sender_name, body) VALUES (?, 'admin', ?, ?)")
      .run(ticket.id, req.user.name, body);
    db.prepare('UPDATE support_tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(ticket.id);
    logActivity(req.user.id, req.user.name, 'admin_support_reply', `رد على تذكرة #${ticket.id}`, req);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/admin/support/tickets/:id/close', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(req.params.id);
    if (!ticket) return res.status(404).json({ error: 'غير موجود' });
    if (ticket.status !== 'open') return res.status(400).json({ error: 'مغلقة مسبقاً' });
    db.prepare("UPDATE support_tickets SET status='closed', closed_by=?, closed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(req.user.name, ticket.id);
    db.prepare('INSERT INTO user_notifications (user_id, title, body) VALUES (?, ?, ?)')
      .run(ticket.user_id, 'تم إغلاق استفسارك', 'تم حل الاستفسار من قِبل الإدارة. يمكنك فتح تذكرة جديدة عند الحاجة.');
    logActivity(req.user.id, req.user.name, 'admin_support_close', `إغلاق تذكرة #${ticket.id}`, req);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.get('/api/admin/support/unread-count', auth, isAdmin, adminAuth, (req, res) => {
  const row = db.prepare("SELECT COUNT(*) as c FROM support_messages WHERE sender_role = 'user' AND is_read = 0").get();
  res.json({ unread: row.c });
});

// =========================================================
// 📢 إشعار جماعي
// =========================================================
app.post('/api/admin/broadcast', auth, isAdmin, adminAuth, (req, res) => {
  try {
    const title = String(req.body.title || '').trim();
    const body = String(req.body.body || '').trim();
    if (!title || !body) return res.status(400).json({ error: 'العنوان والنص مطلوبان' });
    if (title.length > 100 || body.length > 1000) return res.status(400).json({ error: 'النص طويل جداً' });
    const users = db.prepare('SELECT id FROM users').all();
    const ins = db.prepare('INSERT INTO user_notifications (user_id, title, body) VALUES (?, ?, ?)');
    const tx = db.transaction(() => { for (const u of users) ins.run(u.id, title, body); });
    tx();
    logActivity(req.user.id, req.user.name, 'admin_broadcast', `إشعار جماعي: ${title} (${users.length} مستخدم)`, req);
    res.json({ ok: true, sent: users.length });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

// =========================================================
app.get('*', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(__dirname, 'index.html')); });

const server = app.listen(PORT, '0.0.0.0', () => console.log(`🚀 World War running on port ${PORT}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
