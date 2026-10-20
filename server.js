/* =========================================================
   ICHANCY WEBSITE - Full Server & Agent Integration
   ========================================================= */

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ichancy_super_secret_change_me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.db');
const IS_PROD = process.env.NODE_ENV === 'production';
const ADMIN_NAME = 'sam55namsam55namsam55nam';

// ⚠️ إعدادات المنصة (يجب تعديلها حسب بياناتك)
const BASE_URL = process.env.ICHANCY_BASE_URL || 'https://example-platform.com';
const AGENT_USERNAME = process.env.ICHANCY_USER || 'your_agent_username';
const AGENT_PASSWORD = process.env.ICHANCY_PASS || 'your_agent_password';
const PARENT_ID = process.env.ICHANCY_PARENT_ID || '2699771';

// --- تهيئة قاعدة البيانات ---
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) { try { fs.mkdirSync(dbDir, { recursive: true }); } catch (err) {} }
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0, role TEXT NOT NULL DEFAULT 'user', 
    player_id TEXT, platform_username TEXT, platform_password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
    amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', note TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL,
    body TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
  CREATE TABLE IF NOT EXISTS game_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, media_url TEXT NOT NULL,
    media_type TEXT NOT NULL DEFAULT 'image', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// إضافة أعمدة جديدة في حال كان الجدول موجوداً (ترقية تلقائية)
try { db.exec(`ALTER TABLE users ADD COLUMN player_id TEXT;`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN platform_username TEXT;`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN platform_password TEXT;`); } catch (e) {}

const defaultSettings = { game_url: 'https://example.com', proxy_url: '' };
const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
for (const [k, v] of Object.entries(defaultSettings)) insertSetting.run(k, v);

// حذف المنشورات المنتهية (24 ساعة)
setInterval(() => {
  try { db.prepare("DELETE FROM game_posts WHERE created_at <= datetime('now', '-24 hours')").run(); } catch (e) {}
}, 60 * 60 * 1000);

// =========================================================
// 🤖 كلاس IChancyAgent (محول إلى Node.js بالكامل)
// =========================================================
class IChancyAgent {
  constructor() {
    this.BASE_URL = BASE_URL;
    this.USERNAME = AGENT_USERNAME;
    this.PASSWORD = AGENT_PASSWORD;
    this.loggedIn = false;
    this.authCache = { loggedIn: false, lastAuthTime: 0, cacheDuration: 1800 };
    this.minRequestInterval = 1000; // تقليل الوقت قليلاً ليكون مناسباً للويب
    this.lastRequestTime = 0;
    this.requestCounter = 0;

    // إعداد الجلسة والكوكيز
    this.jar = new CookieJar();
    this.client = wrapper(axios.create({ 
      jar: this.jar, 
      withCredentials: true,
      headers: {
        "Content-Type": "application/json",
        "Origin": this.BASE_URL,
        "Referer": `${this.BASE_URL}/`,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*"
      },
      timeout: 30000
    }));
  }

  rotateUserAgent() {
    const agents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
    ];
    this.client.defaults.headers.common['User-Agent'] = agents[Math.floor(Math.random() * agents.length)];
  }

  async ensureLogin() {
    const now = Date.now() / 1000;
    if (this.authCache.loggedIn && (now - this.authCache.lastAuthTime) < this.authCache.cacheDuration) {
      return true;
    }

    try {
      this.rotateUserAgent();
      const res = await this.client.post(`${this.BASE_URL}/global/api/User/signIn`, {
        username: this.USERNAME,
        password: this.PASSWORD
      });

      if (res.status === 200 && res.data?.status && res.data?.result?.message === 'dashboard') {
        this.loggedIn = true;
        this.authCache = { loggedIn: true, lastAuthTime: now, cacheDuration: 1800 };
        console.log('✅ [Agent] Logged in successfully');
        return true;
      }
    } catch (error) {
      console.error('❌ [Agent] Login Error:', error.message);
    }
    return false;
  }

  async makeRequest(endpoint, payload = null, method = "POST") {
    // إدارة الوقت بين الطلبات لمنع الحظر
    const now = Date.now();
    const timeSinceLast = now - this.lastRequestTime;
    if (timeSinceLast < this.minRequestInterval) {
      await new Promise(r => setTimeout(r, this.minRequestInterval - timeSinceLast));
    }

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        if (!await this.ensureLogin()) return { error: "Login failed", status: "error" };

        const url = `${this.BASE_URL}${endpoint}`;
        let res;
        
        if (method === "POST") {
          res = await this.client.post(url, payload);
        } else {
          res = await this.client.get(url);
        }

        this.lastRequestTime = Date.now();

        if (res.status === 200) {
          // التحقق من انتهاء الجلسة
          if (res.data?.result === "ex") {
            this.authCache.loggedIn = false;
            await new Promise(r => setTimeout(r, 2000));
            continue;
          }
          return res.data;
        }
      } catch (err) {
        if (err.response?.status === 401) {
          this.authCache.loggedIn = false;
        }
        await new Promise(r => setTimeout(r, 2000));
      }
    }
    return { error: "Request failed after retries", status: "error" };
  }

  async registerPlayer(username, password, email) {
    const payload = {
      player: { email, password, parentId: PARENT_ID, login: username }
    };
    return this.makeRequest("/global/api/Player/registerPlayer", payload);
  }

  async getPlayerBalance(playerId) {
    return this.makeRequest("/global/api/Player/getPlayerBalanceById", { playerId });
  }

  async depositToPlayer(playerId, amount) {
    const payload = {
      playerId: String(playerId), amount: amount, comment: null,
      currencyCode: "NSP", currency: "NSP", moneyStatus: 5
    };
    const result = await this.makeRequest("/global/api/Player/depositToPlayer", payload);
    return result?.status === true || result?.status === "true";
  }

  async withdrawFromPlayer(playerId, amount) {
    const payload = {
      playerId: String(playerId), amount: -amount, comment: null,
      currencyCode: "NSP", currency: "NSP", moneyStatus: 5
    };
    const result = await this.makeRequest("/global/api/Player/withdrawFromPlayer", payload);
    return result?.status === true || result?.status === "true";
  }
}

const agent = new IChancyAgent();

// =========================================================
// 🌐 إعدادات Express والمصادقة
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
    const user = db.prepare('SELECT id, name, balance, role, player_id, platform_username FROM users WHERE id = ?').get(payload.id);
    if (!user) return res.status(401).json({ error: 'المستخدم غير موجود' });
    req.user = user; next();
  } catch { res.status(401).json({ error: 'توكن غير صالح' }); }
}

const isAdmin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'مخصص للإدارة' });

// =========================================================
// 🔑 API المصادقة (الموقع)
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
    db.prepare('INSERT INTO users (name, password, role) VALUES (?, ?, ?)').run(name, hash, role);
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
    res.json({ ok: true, user: { id: user.id, name: user.name, balance: user.balance, role: user.role, hasAccount: !!user.player_id } });
  } catch (err) { res.status(500).json({ error: 'خطأ' }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('token').json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: { ...req.user, hasAccount: !!req.user.player_id } }));

// =========================================================
// 🤝 API المنصة (الحقيقية)
// =========================================================

// 1. إنشاء حساب في المنصة
app.post('/api/platform/create-account', auth, async (req, res) => {
  try {
    if (req.user.player_id) return res.status(400).json({ error: 'لديك حساب بالفعل' });

    const { username, password, email } = req.body;
    if (!username || !password || !email) return res.status(400).json({ error: 'جميع الحقول مطلوبة' });

    const result = await agent.registerPlayer(username, password, email);
    
    if (result && result.status) {
      // استخراج معرف اللاعب (بناءً على استجابة المنصة)
      const playerId = result.result?.playerId || result.result?.id || result.result?.player?.id || username;
      
      db.prepare('UPDATE users SET player_id = ?, platform_username = ?, platform_password = ? WHERE id = ?')
        .run(String(playerId), username, password, req.user.id);

      res.json({ ok: true, message: 'تم إنشاء الحساب في المنصة بنجاح' });
    } else {
      res.status(400).json({ error: result?.message || 'فشل إنشاء الحساب في المنصة' });
    }
  } catch (err) { res.status(500).json({ error: 'خطأ في الاتصال بالمنصة' }); }
});

// 2. تعبئة حسابي (إيداع)
app.post('/api/platform/deposit', auth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    if (!amount || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });
    if (!req.user.player_id) return res.status(400).json({ error: 'يجب إنشاء حساب في المنصة أولاً' });
    
    const fresh = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
    if (amount > fresh.balance) return res.status(400).json({ error: 'رصيدك في الموقع غير كافٍ' });

    const success = await agent.depositToPlayer(req.user.player_id, amount);
    
    if (success) {
      db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, req.user.id);
      db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)')
        .run(req.user.id, 'deposit', amount, 'completed', 'تعبئة حساب المنصة');
      res.json({ ok: true, message: 'تم تحويل المبلغ إلى حسابك في المنصة' });
    } else {
      res.status(400).json({ error: 'فشل الإيداع في المنصة' });
    }
  } catch (err) { res.status(500).json({ error: 'خطأ في الاتصال بالمنصة' }); }
});

// 3. سحب من حسابي (سحب)
app.post('/api/platform/withdraw', auth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    if (!amount || amount <= 0) return res.status(400).json({ error: 'مبلغ غير صالح' });
    if (!req.user.player_id) return res.status(400).json({ error: 'يجب إنشاء حساب في المنصة أولاً' });

    const balanceRes = await agent.getPlayerBalance(req.user.player_id);
    const platformBalance = balanceRes?.result?.balance || balanceRes?.balance || 0;

    if (amount > platformBalance) return res.status(400).json({ error: 'رصيدك في المنصة غير كافٍ' });

    const success = await agent.withdrawFromPlayer(req.user.player_id, amount);

    if (success) {
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, req.user.id);
      db.prepare('INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?, ?, ?, ?, ?)')
        .run(req.user.id, 'withdraw', amount, 'completed', 'سحب من حساب المنصة');
      res.json({ ok: true, message: 'تم سحب المبلغ من حسابك في المنصة' });
    } else {
      res.status(400).json({ error: 'فشل السحب من المنصة' });
    }
  } catch (err) { res.status(500).json({ error: 'خطأ في الاتصال بالمنصة' }); }
});

// =========================================================
// 📋 باقي الـ APIs (السجلات، الإشعارات، الإعدادات)
// =========================================================
app.get('/api/notifications', auth, (req, res) => {
  const list = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(req.user.id);
  res.json({ notifications: list, unread: list.filter(n => !n.is_read).length });
});
app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});
app.get('/api/transactions', auth, (req, res) => {
  res.json({ transactions: db.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC').all(req.user.id) });
});
app.get('/api/settings', (req, res) => {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const obj = {}; rows.forEach(r => obj[r.key] = r.value);
  res.json(obj);
});
app.post('/api/admin/settings', auth, isAdmin, (req, res) => {
  const { game_url, proxy_url } = req.body;
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(game_url || '', 'game_url');
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(proxy_url || '', 'proxy_url');
  res.json({ ok: true });
});
app.get('/api/posts', (req, res) => {
  res.json({ posts: db.prepare("SELECT * FROM game_posts WHERE created_at > datetime('now', '-24 hours') ORDER BY id DESC").all() });
});
app.post('/api/admin/posts', auth, isAdmin, (req, res) => {
  const { title, media_url, media_type } = req.body;
  db.prepare('INSERT INTO game_posts (title, media_url, media_type) VALUES (?, ?, ?)').run(title, media_url, media_type || 'image');
  res.json({ ok: true });
});

app.get('*', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(__dirname, 'index.html')); });

const server = app.listen(PORT, '0.0.0.0', () => console.log(`🚀 ICHANCY running on port ${PORT}`));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
