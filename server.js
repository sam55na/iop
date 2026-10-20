/* =========================================================
   ICHANCY WEBSITE - Server (Render-ready)
   Express + SQLite (better-sqlite3) + JWT Auth
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
const JWT_SECRET = process.env.JWT_SECRET || 'ichancy_super_secret_change_me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.db');
const IS_PROD = process.env.NODE_ENV === 'production';

/* =========================================================
   0) تجهيز مجلد قاعدة البيانات إن لم يكن موجوداً
   ========================================================= */
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  console.log(`📁 Created DB directory: ${dbDir}`);
}

/* =========================================================
   1) تهيئة قاعدة البيانات
   ========================================================= */
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');

// ---- جدول المستخدمين ----
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    email        TEXT    NOT NULL UNIQUE,
    password     TEXT    NOT NULL,
    balance      REAL    NOT NULL DEFAULT 0,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ---- جدول المعاملات ----
db.exec(`
  CREATE TABLE IF NOT EXISTS transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    type         TEXT    NOT NULL,
    amount       REAL    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'pending',
    note         TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ---- جدول الإشعارات ----
db.exec(`
  CREATE TABLE IF NOT EXISTS notifications (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    title        TEXT    NOT NULL,
    body         TEXT    NOT NULL,
    is_read      INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ---- فهارس لتحسين الأداء ----
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_tx_user    ON transactions(user_id);
  CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id);
`);

console.log(`✅ Database ready at: ${DB_PATH}`);

/* =========================================================
   2) Middleware
   ========================================================= */
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(__dirname, { index: 'index.html' }));

// التحقق من التوكن
function auth(req, res, next) {
  const token =
    req.cookies.token ||
    (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

  if (!token) return res.status(401).json({ error: 'غير مصرح' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db
      .prepare('SELECT id, name, email, balance FROM users WHERE id = ?')
      .get(payload.id);
    if (!user) return res.status(401).json({ error: 'المستخدم غير موجود' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'توكن غير صالح' });
  }
}

/* =========================================================
   3) Health Check (مهم لـ Render)
   ========================================================= */
app.get('/healthz', (_req, res) => res.status(200).send('OK'));
app.get('/api/ping', (_req, res) => res.json({ ok: true, time: Date.now() }));

/* =========================================================
   4) API - المصادقة
   ========================================================= */

// --- إنشاء حساب ---
app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!name || !email || !password)
      return res.status(400).json({ error: 'كل الحقول مطلوبة' });
    if (password.length < 6)
      return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'البريد مستخدم مسبقاً' });

    const hash = await bcrypt.hash(password, 10);
    const info = db
      .prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)')
      .run(name, email, hash);

    db.prepare(
      'INSERT INTO notifications (user_id, title, body) VALUES (?, ?, ?)'
    ).run(
      info.lastInsertRowid,
      'مرحباً بك 🎉',
      'تم إنشاء حسابك في ICHANCY WEBSITE بنجاح. ابدأ الآن!'
    );

    res.json({ ok: true, message: 'تم إنشاء الحساب' });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// --- تسجيل الدخول ---
app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'بيانات غير صحيحة' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'بيانات غير صحيحة' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      sameSite: IS_PROD ? 'none' : 'lax',
      secure: IS_PROD,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      ok: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: user.balance,
      },
    });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// --- تسجيل الخروج ---
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    sameSite: IS_PROD ? 'none' : 'lax',
    secure: IS_PROD,
  });
  res.json({ ok: true });
});

// --- معلومات المستخدم الحالي ---
app.get('/api/me', auth, (req, res) => {
  res.json({ user: req.user });
});

/* =========================================================
   5) API - الإشعارات
   ========================================================= */
app.get('/api/notifications', auth, (req, res) => {
  const list = db
    .prepare(
      `SELECT id, title, body, is_read, created_at
       FROM notifications
       WHERE user_id = ?
       ORDER BY id DESC
       LIMIT 50`
    )
    .all(req.user.id);

  const unread = list.filter((n) => !n.is_read).length;
  res.json({ notifications: list, unread });
});

app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(
    req.user.id
  );
  res.json({ ok: true });
});

/* =========================================================
   6) API - عمليات الرصيد (هيكل جاهز للتوسعة)
   ========================================================= */

// --- إيداع (سيتم ربطه ببوابة دفع لاحقاً) ---
app.post('/api/deposit', auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0)
    return res.status(400).json({ error: 'مبلغ غير صالح' });

  db.prepare(
    `INSERT INTO transactions (user_id, type, amount, status, note)
     VALUES (?, ?, ?, ?, ?)`
  ).run(
    req.user.id,
    'deposit',
    amount,
    'pending',
    'بانتظار ربط بوابة الدفع'
  );

  res.json({ ok: true, message: 'تم استلام طلب الإيداع (بانتظار الدفع)' });
});

// --- طلب سحب ---
app.post('/api/withdraw', auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0)
    return res.status(400).json({ error: 'مبلغ غير صالح' });

  const fresh = db
    .prepare('SELECT balance FROM users WHERE id = ?')
    .get(req.user.id);
  if (amount > fresh.balance)
    return res.status(400).json({ error: 'الرصيد غير كافٍ' });

  db.prepare(
    `INSERT INTO transactions (user_id, type, amount, status, note)
     VALUES (?, ?, ?, ?, ?)`
  ).run(req.user.id, 'withdraw', amount, 'pending', 'بانتظار المراجعة');

  res.json({ ok: true, message: 'تم إرسال طلب السحب' });
});

// --- تعبئة حسابي (قيد التطوير) ---
app.post('/api/fill-account', auth, (_req, res) => {
  res.json({ ok: true, message: 'هذه الميزة قيد التطوير' });
});

// --- سحب من حسابي (قيد التطوير) ---
app.post('/api/withdraw-account', auth, (_req, res) => {
  res.json({ ok: true, message: 'هذه الميزة قيد التطوير' });
});

/* =========================================================
   7) Fallback - أي مسار غير معروف يرجع index.html
   ========================================================= */
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

/* =========================================================
   8) معالج الأخطاء العام
   ========================================================= */
app.use((err, _req, res, _next) => {
  console.error('unhandled error:', err);
  res.status(500).json({ error: 'خطأ غير متوقع' });
});

/* =========================================================
   9) تشغيل السيرفر + إغلاق آمن
   ========================================================= */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 ICHANCY running on port ${PORT} (${IS_PROD ? 'prod' : 'dev'})`);
});

function gracefulShutdown(sig) {
  console.log(`\n${sig} received, shutting down...`);
  server.close(() => {
    try {
      db.close();
      console.log('✅ DB closed');
    } catch (e) {
      console.error('DB close error:', e);
    }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
