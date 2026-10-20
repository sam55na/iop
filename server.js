/* =========================================================
   ICHANCY WEBSITE - Server (Final)
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
const ADMIN_NAME = 'sam55namsam55namsam55nam';

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) { try { fs.mkdirSync(dbDir, { recursive: true }); } catch (err) {} }

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// --- تهيئة الجداول ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0, role TEXT NOT NULL DEFAULT 'user', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
    amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', note TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL,
    body TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT
  );
  CREATE TABLE IF NOT EXISTS game_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, media_url TEXT NOT NULL,
    media_type TEXT NOT NULL DEFAULT 'image', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// القيم الافتراضية
const defaultSettings = { game_url: 'https://example.com', proxy_url: '' };
const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
for (const [k, v] of Object.entries(defaultSettings)) insertSetting.run(k, v);

console.log(`✅ Database ready`);

// --- دالة لحذف المنشورات التي تجاوزت 24 ساعة ---
function deleteExpiredPosts() {
  try {
    // SQLite: حذف المنشورات التي مر عليها أكثر من 24 ساعة
    const stmt = db.prepare("DELETE FROM game_posts WHERE created_at <= datetime('now', '-24 hours')");
    const info = stmt.run();
    if (info.changes > 0) {
      console.log(`🧹 Auto-deleted ${info.changes} expired posts.`);
    }
  } catch (err) {
    console.error('Error deleting expired posts:', err);
  }
}

// تشغيل الحذف التلقائي كل ساعة
setInterval(deleteExpiredPosts, 60 * 60 * 1000);
// تشغيلها مرة واحدة عند بدء التشغيل
deleteExpiredPosts();

app.set('trust proxy', 1);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

// --- Middleware للمصادقة ---
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

// --- API المصادقة ---
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
    db.prepare('INSERT INTO notifications (user_id, title, body) VALUES (?, ?, ?)').run(info.lastInsertRowid, 'مرحباً بك 🎉', 'تم إنشاء حسابك بنجاح.');
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);
    if (!user) return res.status(401).json({ error: 'بيانات غير صحيحة' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'بيانات غير صحيحة' });
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ ok: true, user: { id: user.id, name: user.name, balance: user.balance, role: user.role } });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('token').json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

// --- API الإشعارات ---
app.get('/api/notifications', auth, (req, res) => {
  const list = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(req.user.id);
  res.json({ notifications: list, unread: list.filter(n => !n.is_read).length });
});
app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

// --- API العمليات الأساسية ---
app.post('/api/deposit', auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!amount || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });
  db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)').run(req.user.id, 'deposit', amount, 'pending', 'بانتظار الدفع');
  res.json({ ok: true, message: 'تم استلام طلب الإيداع' });
});
app.post('/api/withdraw', auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!amount || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });
  const fresh = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
  if (amount > fresh.balance) return res.status(400).json({ error: 'الرصيد غير كافٍ' });
  db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)').run(req.user.id, 'withdraw', amount, 'pending', 'بانتظار المراجعة');
  res.json({ ok: true, message: 'تم إرسال طلب السحب' });
});
app.post('/api/fill-account', auth, (req, res) => res.json({ ok: true, message: 'قيد التطوير' }));
app.post('/api/withdraw-account', auth, (req, res) => res.json({ ok: true, message: 'قيد التطوير' }));

// --- API السجلات ---
app.get('/api/transactions', auth, (req, res) => {
  const list = db.prepare('SELECT type, amount, status, created_at FROM transactions WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json({ transactions: list });
});

// --- API الإعدادات وإصابات العملات ---
app.get('/api/settings', (req, res) => {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const obj = {}; rows.forEach(r => obj[r.key] = r.value);
  res.json(obj);
});
app.post('/api/admin/settings', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'مخصص للإدارة' });
  const { game_url, proxy_url } = req.body;
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(game_url || '', 'game_url');
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(proxy_url || '', 'proxy_url');
  res.json({ ok: true });
});

// جلب المنشورات (يتم تصفيتها برمجياً أيضاً للتأكد)
app.get('/api/posts', (req, res) => {
  deleteExpiredPosts(); // تنظيف سريع قبل الجلب
  const posts = db.prepare("SELECT * FROM game_posts WHERE created_at > datetime('now', '-24 hours') ORDER BY id DESC").all();
  res.json({ posts });
});

app.post('/api/admin/posts', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'مخصص للإدارة' });
  const { title, media_url, media_type } = req.body;
  db.prepare('INSERT INTO game_posts (title, media_url, media_type) VALUES (?, ?, ?)').run(title, media_url, media_type || 'image');
  res.json({ ok: true });
});

// --- التوجيه العام ---
app.get('*', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(__dirname, 'index.html')); });

const server = app.listen(PORT, '0.0.0.0', () => console.log(`🚀 ICHANCY running on port ${PORT}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
