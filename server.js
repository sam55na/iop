/* =========================================================
   ICHANCY WEBSITE - Server (نسخة مبسطة)
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

// --- تهيئة قاعدة البيانات ---
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) { try { fs.mkdirSync(dbDir, { recursive: true }); } catch (err) {} }
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0, role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// =========================================================
// 🌐 Middleware
// =========================================================
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
    req.user = user; next();
  } catch { res.status(401).json({ error: 'توكن غير صالح' }); }
}

// =========================================================
// 🔑 APIs المصادقة
// =========================================================
app.post('/api/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const password = String(req.body.password || '');
    if (!name || !password) return res.status(400).json({ error: 'الاسم وكلمة المرور مطلوبان' });

    const exists = db.prepare('SELECT id FROM users WHERE name = ?').get(name);
    if (exists) return res.status(409).json({ error: 'هذا الاسم مستخدم مسبقاً' });

    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (name, password) VALUES (?, ?)').run(name, hash);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'بيانات غير صحيحة' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: IS_PROD ? 'none' : 'lax', secure: IS_PROD, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ ok: true, user: { id: user.id, name: user.name, balance: user.balance, role: user.role } });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('token').json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

app.get('*', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(__dirname, 'index.html')); });

const server = app.listen(PORT, '0.0.0.0', () => console.log(`🚀 ICHANCY running on port ${PORT}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
