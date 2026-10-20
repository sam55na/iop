/* =========================================================
   ICHANCY WEBSITE - Server (Render-ready)
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

// ⚠️ حساب الإدارة
const ADMIN_NAME = 'sam55namsam55namsam55nam';

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  try { fs.mkdirSync(dbDir, { recursive: true }); } catch (err) {}
}

/* =========================================================
   تهيئة قاعدة البيانات
   ========================================================= */
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    password     TEXT    NOT NULL,
    balance      REAL    NOT NULL DEFAULT 0,
    role         TEXT    NOT NULL DEFAULT 'user',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

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

console.log(`✅ Database ready at: ${DB_PATH}`);

/* =========================================================
   Middleware
   ========================================================= */
app.set('trust proxy', 1);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'غير مصرح' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, name, balance, role FROM users WHERE id = ?').get(payload.id);
    if (!user) return res.status(401).json({ error: 'المستخدم غير موجود' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'توكن غير صالح' });
  }
}

app.get('/healthz', (req, res) => res.status(200).send('OK'));

/* =========================================================
   API - المصادقة (بالاسم فقط)
   ========================================================= */

// إنشاء حساب
app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const password = String(req.body.password || '');

    if (!name || !password) return res.status(400).json({ error: 'الاسم وكلمة المرور مطلوبان' });
    if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });

    const exists = db.prepare('SELECT id FROM users WHERE name = ?').get(name);
    if (exists) return res.status(409).json({ error: 'هذا الاسم مستخدم مسبقاً، جرب اسماً آخر' });

    const hash = await bcrypt.hash(password, 10);
    const role = (name === ADMIN_NAME) ? 'admin' : 'user';

    const info = db.prepare('INSERT INTO users (name, password, role) VALUES (?, ?, ?)').run(name, hash, role);

    db.prepare('INSERT INTO notifications (user_id, title, body) VALUES (?, ?, ?)').run(
      info.lastInsertRowid, 'مرحباً بك 🎉', 'تم إنشاء حسابك في ICHANCY WEBSITE بنجاح. ابدأ الآن!'
    );

    res.json({ ok: true, message: 'تم إنشاء الحساب' });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const password = String(req.body.password || '');

    const user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);
    if (!user) return res.status(401).json({ error: 'الاسم أو كلمة المرور غير صحيحة' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'الاسم أو كلمة المرور غير صحيحة' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      sameSite: IS_PROD ? 'none' : 'lax',
      secure: IS_PROD,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ ok: true, user: { id: user.id, name: user.name, balance: user.balance, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD });
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

/* =========================================================
   API - الإشعارات
   ========================================================= */
app.get('/api/notifications', auth, (req, res) => {
  const list = db.prepare('SELECT id, title, body, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(req.user.id);
  res.json({ notifications: list, unread: list.filter(n => !n.is_read).length });
});

app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

/* =========================================================
   API - عمليات الرصيد
   ========================================================= */
app.post('/api/deposit', auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });
  db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)').run(req.user.id, 'deposit', amount, 'pending', 'بانتظار بوابة الدفع');
  res.json({ ok: true, message: 'تم استلام طلب الإيداع' });
});

app.post('/api/withdraw', auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });

  const fresh = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
  if (amount > fresh.balance) return res.status(400).json({ error: 'الرصيد غير كافٍ' });

  db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)').run(req.user.id, 'withdraw', amount, 'pending', 'بانتظار المراجعة');
  res.json({ ok: true, message: 'تم إرسال طلب السحب' });
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

const server = app.listen(PORT, '0.0.0.0', () => console.log(`🚀 ICHANCY running on port ${PORT}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
