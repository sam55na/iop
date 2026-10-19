/* =========================================================
   ICHANCY WEBSITE - Server
   Express + SQLite + JWT Auth
   ========================================================= */

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ichancy_super_secret_change_me';

/* =========================================================
   1) تهيئة قاعدة البيانات
   ========================================================= */
const db = new Database(path.join(__dirname, 'database.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

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

// ---- جدول المعاملات (للاستخدام لاحقاً في الإيداع/السحب) ----
db.exec(`
  CREATE TABLE IF NOT EXISTS transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    type         TEXT    NOT NULL,  -- deposit | withdraw | transfer_in | transfer_out
    amount       REAL    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'pending', -- pending | completed | rejected
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

console.log('✅ Database initialized');

/* =========================================================
   2) Middleware
   ========================================================= */
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname)); // نقدّم ملفات المشروع الثابتة (index.html)

// Middleware للتحقق من التوكن
function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'غير مصرح' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, name, email, balance FROM users WHERE id = ?').get(payload.id);
    if (!user) return res.status(401).json({ error: 'المستخدم غير موجود' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'توكن غير صالح' });
  }
}

/* =========================================================
   3) API - المصادقة
   ========================================================= */

// --- إنشاء حساب ---
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'كل الحقول مطلوبة' });
    if (password.length < 6)
      return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(409).json({ error: 'البريد مستخدم مسبقاً' });

    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)'
    ).run(name, email, hash);

    // إشعار ترحيبي
    db.prepare(
      'INSERT INTO notifications (user_id, title, body) VALUES (?, ?, ?)'
    ).run(info.lastInsertRowid, 'مرحباً بك 🎉',
      'تم إنشاء حسابك في ICHANCY WEBSITE بنجاح. ابدأ الآن!');

    res.json({ ok: true, message: 'تم إنشاء الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// --- تسجيل الدخول ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'بيانات غير صحيحة' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'بيانات غير صحيحة' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      ok: true,
      user: { id: user.id, name: user.name, email: user.email, balance: user.balance }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// --- تسجيل الخروج ---
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// --- معلومات المستخدم الحالي ---
app.get('/api/me', auth, (req, res) => {
  res.json({ user: req.user });
});

/* =========================================================
   4) API - الإشعارات
   ========================================================= */
app.get('/api/notifications', auth, (req, res) => {
  const list = db.prepare(
    'SELECT id, title, body, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50'
  ).all(req.user.id);
  const unread = list.filter(n => !n.is_read).length;
  res.json({ notifications: list, unread });
});

app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

/* =========================================================
   5) API - عمليات الرصيد (الهيكل الأساسي جاهز للتوسعة)
   ========================================================= */

// --- إيداع (سيتم ربطه ببوابة دفع لاحقاً) ---
app.post('/api/deposit', auth, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });

  db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, 'deposit', amount, 'pending', 'بانتظار ربط بوابة الدفع');
  res.json({ ok: true, message: 'تم استلام طلب الإيداع (بانتظار الدفع)' });
});

// --- طلب سحب ---
app.post('/api/withdraw', auth, (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });
  if (amount > req.user.balance) return res.status(400).json({ error: 'الرصيد غير كافٍ' });

  db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, 'withdraw', amount, 'pending', 'بانتظار المراجعة');
  res.json({ ok: true, message: 'تم إرسال طلب السحب' });
});

// --- تعبئة حسابي (تحويل داخلي - واجهة فقط الآن) ---
app.post('/api/fill-account', auth, (req, res) => {
  res.json({ ok: true, message: 'هذه الميزة قيد التطوير' });
});

// --- سحب من حسابي ---
app.post('/api/withdraw-account', auth, (req, res) => {
  res.json({ ok: true, message: 'هذه الميزة قيد التطوير' });
});

/* =========================================================
   6) تشغيل السيرفر
   ========================================================= */
app.listen(PORT, () => {
  console.log(`🚀 ICHANCY running: http://localhost:${PORT}`);
});
