export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path.startsWith('/api/')) {
      try {
        let body = {};
        if (method === 'POST' || method === 'PUT') {
          body = await request.json().catch(() => ({}));
        }

        const getAuthUser = async () => {
          const h = request.headers.get('Authorization') || '';
          const token = h.startsWith('Bearer ') ? h.slice(7) : null;
          if (!token) return null;
          return await env.DB.prepare('SELECT u.* FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token = ?').bind(token).first();
        };

        const hashPwd = async (pwd, salt) => {
          const data = new TextEncoder().encode(pwd + salt);
          const hashBuffer = await crypto.subtle.digest('SHA-256', data);
          return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        };

        const makeToken = () => crypto.randomUUID().replace(/-/g, '');
        const publicUser = (u) => ({ username: u.username, nick: u.nick, avatar: u.avatar, bio: u.bio, created: u.created_at, visits: u.visits || 0 });

        // 注册
        if (path === '/api/register' && method === 'POST') {
          const { username, password, nick, securityQuestion, securityAnswer } = body;
          if (!username || username.length < 2 || username.length > 12) return Response.json({ error: '用户名需要 2-12 个字符' }, { status: 400 });
          if (!password || password.length < 4) return Response.json({ error: '密码至少 4 位' }, { status: 400 });
          if (!securityQuestion || !securityAnswer) return Response.json({ error: '请填写密保问题和答案' }, { status: 400 });
          if (await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()) return Response.json({ error: '用户名已存在' }, { status: 400 });

          const salt = crypto.randomUUID().replace(/-/g, '');
          const hash = await hashPwd(password, salt);
          const ansHash = await hashPwd(securityAnswer.toLowerCase().trim(), salt);
          
          const info = await env.DB.prepare('INSERT INTO users (username, password_hash, salt, nick, security_question, security_answer, created_at, visits) VALUES (?, ?, ?, ?, ?, ?, ?, 0)')
            .bind(username, hash, salt, nick || username, securityQuestion, ansHash, Date.now()).run();

          const userId = info.meta.last_row_id || info.last_row_id;
          const token = makeToken();
          await env.DB.prepare('INSERT INTO tokens (token, user_id) VALUES (?, ?)').bind(token, userId).run();
          const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
          return Response.json({ token, user: publicUser(user) });
        }

        // 登录
        if (path === '/api/login' && method === 'POST') {
          const { username, password } = body;
          const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
          if (!user || hashPwd(password, user.salt) !== user.password_hash) return Response.json({ error: '账号或密码不对' }, { status: 400 });
          const token = makeToken();
          await env.DB.prepare('INSERT INTO tokens (token, user_id) VALUES (?, ?)').bind(token, user.id).run();
          return Response.json({ token, user: publicUser(user) });
        }

        // 获取密保问题
        if (path === '/api/forgot/question' && method === 'GET') {
          const username = url.searchParams.get('username');
          if (!username) return Response.json({ error: '请输入用户名' }, { status: 400 });
          const user = await env.DB.prepare('SELECT security_question FROM users WHERE username = ?').bind(username).first();
          if (!user) return Response.json({ error: '用户不存在' }, { status: 404 });
          if (!user.security_question) return Response.json({ error: '该账号未设置密保问题，无法找回' }, { status: 400 });
          return Response.json({ question: user.security_question });
        }

        // 重置密码
        if (path === '/api/forgot/reset' && method === 'POST') {
          const { username, answer, newPassword } = body;
          if (!newPassword || newPassword.length < 4) return Response.json({ error: '新密码至少 4 位' }, { status: 400 });
          const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
          if (!user) return Response.json({ error: '用户不存在' }, { status: 404 });
          
          const ansHash = await hashPwd(answer.toLowerCase().trim(), user.salt);
          if (ansHash !== user.security_answer) return Response.json({ error: '密保答案不对' }, { status: 400 });
          
          const newSalt = crypto.randomUUID().replace(/-/g, '');
          const newHash = await hashPwd(newPassword, newSalt);
          await env.DB.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').bind(newHash, newSalt, user.id).run();
          
          await env.DB.prepare('DELETE FROM tokens WHERE user_id = ?').bind(user.id).run();
          
          return Response.json({ ok: true, message: '密码重置成功，请重新登录' });
        }

        // 需要登录的接口
        const user = await getAuthUser();
        if (!user) return Response.json({ error: '请先登录' }, { status: 401 });

        if (path === '/api/me' && method === 'GET') return Response.json({ user: publicUser(user) });

        if (path === '/api/profile' && method === 'PUT') {
          const { nick, avatar, bio } = body;
          await env.DB.prepare('UPDATE users SET nick = ?, avatar = ?, bio = ? WHERE id = ?')
            .bind(nick || user.nick, avatar || user.avatar, bio !== undefined ? bio : user.bio, user.id).run();
          const updated = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
          return Response.json({ user: publicUser(updated) });
        }

        // 查看别人的主页
        if (path.startsWith('/api/profile/') && method === 'GET') {
          const targetUsername = path.split('/')[3];
          const targetUser = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(targetUsername).first();
          if (!targetUser) return Response.json({ error: '用户不存在' }, { status: 404 });
          
          await env.DB.prepare('UPDATE users SET visits = COALESCE(visits, 0) + 1 WHERE id = ?').bind(targetUser.id).run();
          
          const msgs = await env.DB.prepare('SELECT * FROM messages WHERE receiver = ? ORDER BY created_at DESC LIMIT 50').bind(targetUsername).all();
          return Response.json({ 
            user: { ...publicUser(targetUser), visits: (targetUser.visits || 0) + 1 },
            messages: msgs.results 
          });
        }

        // 发送留言
        if (path === '/api/messages' && method === 'POST') {
          const { receiver, content } = body;
          if (!receiver || !content || !content.trim()) return Response.json({ error: '参数不对' }, { status: 400 });
          await env.DB.prepare('INSERT INTO messages (sender, receiver, content, created_at) VALUES (?, ?, ?, ?)')
            .bind(user.username, receiver, content.slice(0, 200), Date.now()).run();
          return Response.json({ ok: true });
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
          const users = await env.DB.prepare('SELECT id, username, nick, avatar, visits FROM users').all();
          const scores = await env.DB.prepare('SELECT user_id, game, score FROM scores').all();
          const scoreMap = {};
          scores.results.forEach(s => { if (!scoreMap[s.user_id]) scoreMap[s.user_id] = {}; scoreMap[s.user_id][s.game] = s.score; });
          const list = users.results.map(u => {
            const sc = scoreMap[u.id] || {};
            const total = Object.values(sc).reduce((a, b) => a + b, 0);
            return { username: u.username, nick: u.nick, avatar: u.avatar, visits: u.visits || 0, total, games: sc };
          }).sort((a, b) => b.total - a.total).slice(0, 20);
          return Response.json({ list });
        }

        // 注销账户
        if (path === '/api/delete-account' && method === 'POST') {
          // 删除用户
          await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
          // 删除该用户的 Token
          await env.DB.prepare('DELETE FROM tokens WHERE user_id = ?').bind(user.id).run();
          // 删除该用户的游戏分数
          await env.DB.prepare('DELETE FROM scores WHERE user_id = ?').bind(user.id).run();
          // 删除该用户发送和接收的所有留言
          await env.DB.prepare('DELETE FROM messages WHERE sender = ? OR receiver = ?').bind(user.username, user.username).run();
          
          return Response.json({ ok: true, message: '账户已成功注销' });
        }

                // 查询签到状态
        if (path === '/api/signin/status' && method === 'GET') {
          const today = new Date().toISOString().slice(0, 10);
          const todayRow = await env.DB.prepare(
            'SELECT 1 FROM signins WHERE user_id = ? AND date = ?'
          ).bind(user.id, today).first();
          const totalRow = await env.DB.prepare(
            'SELECT COUNT(*) as cnt FROM signins WHERE user_id = ?'
          ).bind(user.id).first();
          const total = totalRow?.cnt || 0;

          // 计算连续天数
          let streak = 0;
          if (total > 0) {
            const dates = await env.DB.prepare(
              'SELECT date FROM signins WHERE user_id = ? ORDER BY date DESC LIMIT 30'
            ).bind(user.id).all();
            const list = dates.results.map(r => r.date);
            let check = new Date();
            const todayStr = check.toISOString().slice(0, 10);
            if (!list.includes(todayStr)) {
              check.setDate(check.getDate() - 1);
            }
            for (let i = 0; i < 30; i++) {
              const d = check.toISOString().slice(0, 10);
              if (list.includes(d)) {
                streak++;
                check.setDate(check.getDate() - 1);
              } else {
                break;
              }
            }
          }

          return Response.json({ signed: !!todayRow, total, streak });
        }

        // 签到
        if (path === '/api/signin' && method === 'POST') {
          const today = new Date().toISOString().slice(0, 10);
          const exists = await env.DB.prepare(
            'SELECT 1 FROM signins WHERE user_id = ? AND date = ?'
          ).bind(user.id, today).first();

          if (exists) {
            return Response.json({ error: '今天已经签过啦！' }, { status: 400 });
          }

          await env.DB.prepare(
            'INSERT INTO signins (user_id, date, created_at) VALUES (?, ?, ?)'
          ).bind(user.id, today, Date.now()).run();

          // 把签到积分累加到 scores 表（每条签到 = 10 分）
          const totalRow = await env.DB.prepare(
            'SELECT COUNT(*) as cnt FROM signins WHERE user_id = ?'
          ).bind(user.id).first();
          const total = totalRow?.cnt || 0;
          const points = total * 10;

          await env.DB.prepare(`
            INSERT INTO scores (user_id, game, score) VALUES (?, 'signin', ?)
            ON CONFLICT(user_id, game) DO UPDATE SET score = excluded.score
          `).bind(user.id, points).run();

          return Response.json({ ok: true, points, total });
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

    return env.ASSETS.fetch(request);
  }
};