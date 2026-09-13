const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

/* ===== 数据 ===== */
let db = { users: [], tokens: {}, scores: {} };

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
      if (!db.users) db.users = [];
      if (!db.tokens) db.tokens = {};
      if (!db.scores) db.scores = {};
    }
  } catch (e) { console.error('读数据失败:', e.message); }
}
function saveDB() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
  catch (e) { console.error('存数据失败:', e.message); }
}
loadDB();

/* ===== 密码 ===== */
function hashPwd(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha256').toString('hex');
}
function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function publicUser(u) {
  return { username: u.username, nick: u.nick, avatar: u.avatar, bio: u.bio, created: u.created_at };
}

/* ===== 工具 ===== */
function sendJSON(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { resolve({}); }
    });
  });
}
function getAuthUser(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token || !db.tokens[token]) return null;
  return db.users.find(u => u.id === db.tokens[token]) || null;
}

/* ===== 静态文件 ===== */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon'
};
function serveStatic(req, res) {
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';
  const filePath = path.join(PUBLIC_DIR, urlPath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); return res.end('404 Not Found'); }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

/* ===== 服务器 ===== */
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const method = req.method;

  if (url.startsWith('/api/')) {
    try {
      /* 注册 */
      if (url === '/api/register' && method === 'POST') {
        const { username, password, nick } = await readBody(req);
        if (!username || username.length < 2 || username.length > 12)
          return sendJSON(res, 400, { error: '用户名需要 2-12 个字符' });
        if (!password || password.length < 4)
          return sendJSON(res, 400, { error: '密码至少 4 位' });
        if (db.users.find(u => u.username === username))
          return sendJSON(res, 400, { error: '这个用户名已经被注册了' });

        const salt = crypto.randomBytes(16).toString('hex');
        const user = {
          id: Date.now() + Math.floor(Math.random() * 1000),
          username,
          password_hash: hashPwd(password, salt),
          salt,
          nick: nick || username,
          avatar: '🐱',
          bio: '',
          created_at: Date.now()
        };
        db.users.push(user);
        const token = makeToken();
        db.tokens[token] = user.id;
        saveDB();
        return sendJSON(res, 200, { token, user: publicUser(user) });
      }

      /* 登录 */
      if (url === '/api/login' && method === 'POST') {
        const { username, password } = await readBody(req);
        const user = db.users.find(u => u.username === username);
        if (!user) return sendJSON(res, 400, { error: '用户不存在' });
        if (hashPwd(password, user.salt) !== user.password_hash)
          return sendJSON(res, 400, { error: '密码不对' });
        const token = makeToken();
        db.tokens[token] = user.id;
        saveDB();
        return sendJSON(res, 200, { token, user: publicUser(user) });
      }

      /* 以下需要登录 */
      const user = getAuthUser(req);
      if (!user) return sendJSON(res, 401, { error: '请先登录' });

      if (url === '/api/me' && method === 'GET')
        return sendJSON(res, 200, { user: publicUser(user) });

      if (url === '/api/profile' && method === 'PUT') {
        const { nick, avatar, bio } = await readBody(req);
        if (nick !== undefined) user.nick = String(nick).slice(0, 12);
        if (avatar !== undefined) user.avatar = String(avatar).slice(0, 8);
        if (bio !== undefined) user.bio = String(bio).slice(0, 200);
        saveDB();
        return sendJSON(res, 200, { user: publicUser(user) });
      }

      if (url === '/api/score' && method === 'POST') {
        const { game, score } = await readBody(req);
        if (!game || typeof score !== 'number' || !isFinite(score))
          return sendJSON(res, 400, { error: '参数不对' });
        if (!db.scores[user.id]) db.scores[user.id] = {};
        if (score > (db.scores[user.id][game] || 0))
          db.scores[user.id][game] = score;
        saveDB();
        return sendJSON(res, 200, { ok: true });
      }

      if (url === '/api/scores' && method === 'GET')
        return sendJSON(res, 200, { scores: db.scores[user.id] || {} });

      if (url === '/api/leaderboard' && method === 'GET') {
        const list = db.users.map(u => {
          const sc = db.scores[u.id] || {};
          const total = Object.values(sc).reduce((a, b) => a + b, 0);
          return {
            username: u.username,
            nick: u.nick,
            avatar: u.avatar,
            total,
            games: sc
          };
        }).sort((a, b) => b.total - a.total).slice(0, 20);
        return sendJSON(res, 200, { list });
      }

      if (url === '/api/logout' && method === 'POST') {
        const h = req.headers.authorization || '';
        const token = h.startsWith('Bearer ') ? h.slice(7) : null;
        if (token) delete db.tokens[token];
        saveDB();
        return sendJSON(res, 200, { ok: true });
      }

      return sendJSON(res, 404, { error: '接口不存在' });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { error: '服务器错误' });
    }
  }

  serveStatic(req, res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  🚀 服务器已启动');
  console.log('  👉 本机访问：http://localhost:' + PORT);
  console.log('  👉 手机访问：http://手机IP:' + PORT);
  console.log('');
});