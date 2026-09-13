export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 1. 处理 API 请求
    if (path.startsWith('/api/')) {
      try {
        // 统一处理请求体
        let body = {};
        if (method === 'POST' || method === 'PUT') {
          body = await request.json().catch(() => ({}));
        }

        // 获取当前用户逻辑
        const getAuthUser = async () => {
          const h = request.headers.get('Authorization') || '';
          const token = h.startsWith('Bearer ') ? h.slice(7) : null;
          if (!token) return null;
          const row = await env.DB.prepare(
            'SELECT u.* FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token = ?'
          ).bind(token).first();
          return row || null;
        };

        // 密码哈希（简单实现，无依赖）
        const hashPwd = async (pwd, salt) => {
          const data = new TextEncoder().encode(pwd + salt);
          const hashBuffer = await crypto.subtle.digest('SHA-256', data);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        };

        const makeToken = () => crypto.randomUUID().replace(/-/g, '');
        const publicUser = (u) => ({ username: u.username, nick: u.nick, avatar: u.avatar, bio: u.bio, created: u.created_at });

        // 注册
        if (path === '/api/register' && method === 'POST') {
          const { username, password, nick } = body;
          if (!username || username.length < 2 || username.length > 12) return Response.json({ error: '用户名需要 2-12 个字符' }, { status: 400 });
          if (!password || password.length < 4) return Response.json({ error: '密码至少 4 位' }, { status: 400 });
          
          const exist = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
          if (exist) return Response.json({ error: '这个用户名已经被注册了' }, { status: 400 });

          const salt = crypto.randomUUID().replace(/-/g, '');
          const hash = await hashPwd(password, salt);
          const now = Date.now();
          
          const info = await env.DB.prepare(
            'INSERT INTO users (username, password_hash, salt, nick, created_at) VALUES (?, ?, ?, ?, ?)'
          ).bind(username, hash, salt, nick || username, now).run();

          const userId = info.meta.last_row_id;
          const token = makeToken();
          await env.DB.prepare('INSERT INTO tokens (token, user_id) VALUES (?, ?)').bind(token, userId).run();
          
          const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
          return Response.json({ token, user: publicUser(user) });
        }

        // 登录
        if (path === '/api/login' && method === 'POST') {
          const { username, password } = body;
          const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
          if (!user) return Response.json({ error: '用户不存在' }, { status: 400 });
          
          const hash = await hashPwd(password, user.salt);
          if (hash !== user.password_hash) return Response.json({ error: '密码不对' }, { status: 400 });

          const token = makeToken();
          await env.DB.prepare('INSERT INTO tokens (token, user_id) VALUES (?, ?)').bind(token, user.id).run();
          return Response.json({ token, user: publicUser(user) });
        }

        // 以下需要登录
        const user = await getAuthUser();
        if (!user) return Response.json({ error: '请先登录' }, { status: 401 });

        if (path === '/api/me' && method === 'GET') return Response.json({ user: publicUser(user) });

        if (path === '/api/profile' && method === 'PUT') {
          const { nick, avatar, bio } = body;
          const newNick = nick !== undefined ? String(nick).slice(0, 12) : user.nick;
          const newAvatar = avatar !== undefined ? String(avatar).slice(0, 8) : user.avatar;
          const newBio = bio !== undefined ? String(bio).slice(0, 200) : user.bio;
          await env.DB.prepare('UPDATE users SET nick = ?, avatar = ?, bio = ? WHERE id = ?').bind(newNick, newAvatar, newBio, user.id).run();
          return Response.json({ user: { ...publicUser(user), nick: newNick, avatar: newAvatar, bio: newBio } });
        }

        if (path === '/api/score' && method === 'POST') {
          const { game, score } = body;
          if (!game || typeof score !== 'number') return Response.json({ error: '参数不对' }, { status: 400 });
          const existing = await env.DB.prepare('SELECT score FROM scores WHERE user_id = ? AND game = ?').bind(user.id, game).first();
          if (!existing || score > existing.score) {
            await env.DB.prepare('INSERT OR REPLACE INTO scores (user_id, game, score) VALUES (?, ?, ?)').bind(user.id, game, score).run();
          }
          return Response.json({ ok: true });
        }

        if (path === '/api/scores' && method === 'GET') {
          const rows = await env.DB.prepare('SELECT game, score FROM scores WHERE user_id = ?').bind(user.id).all();
          const scores = {};
          rows.results.forEach(r => { scores[r.game] = r.score; });
          return Response.json({ scores });
        }

        if (path === '/api/leaderboard' && method === 'GET') {
          const users = await env.DB.prepare('SELECT id, username, nick, avatar FROM users').all();
          const scores = await env.DB.prepare('SELECT user_id, game, score FROM scores').all();
          
          const scoreMap = {};
          scores.results.forEach(s => {
            if (!scoreMap[s.user_id]) scoreMap[s.user_id] = {};
            scoreMap[s.user_id][s.game] = s.score;
          });

          const list = users.results.map(u => {
            const sc = scoreMap[u.id] || {};
            const total = Object.values(sc).reduce((a, b) => a + b, 0);
            return { username: u.username, nick: u.nick, avatar: u.avatar, total, games: sc };
          }).sort((a, b) => b.total - a.total).slice(0, 20);

          return Response.json({ list });
        }

        if (path === '/api/logout' && method === 'POST') {
          const h = request.headers.get('Authorization') || '';
          const token = h.startsWith('Bearer ') ? h.slice(7) : null;
          if (token) await env.DB.prepare('DELETE FROM tokens WHERE token = ?').bind(token).run();
          return Response.json({ ok: true });
        }

        return Response.json({ error: '接口不存在' }, { status: 404 });
      } catch (e) {
        return Response.json({ error: '服务器错误: ' + e.message }, { status: 500 });
      }
    }

    // 2. 放行前端静态文件
    return env.ASSETS.fetch(request);
  }
};
