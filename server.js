const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_SALT = process.env.SECRET_SALT || 'gomkarat_super_secret_salt_2026_x86_x64';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const requestCounts = new Map();
app.use('/api/', (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const now = Date.now();
    const windowMs = 60 * 1000;
    const limit = 30;

    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, { count: 1, resetTime: now + windowMs });
    } else {
        const record = requestCounts.get(ip);
        if (now > record.resetTime) {
            record.count = 1;
            record.resetTime = now + windowMs;
        } else {
            record.count++;
            if (record.count > limit) {
                return res.status(429).json({ valid: false, message: 'Слишком много запросов. Подождите.' });
            }
        }
    }
    next();
});

// PostgreSQL Pool Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/gomkarat',
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Auto initialize PostgreSQL database table and default admin
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                hwid VARCHAR(100) DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT NULL
            );
        `);

        // Check if default Admin exists, create if missing
        const res = await pool.query('SELECT * FROM users WHERE LOWER(username) = $1', ['admin']);
        if (res.rows.length === 0) {
            await pool.query(
                'INSERT INTO users (username, password, is_admin, expires_at) VALUES ($1, $2, $3, $4)',
                ['Admin', 'qqbot2323', true, null]
            );
            console.log('[DB] Дефолтный админ Admin / qqbot2323 был успешно создан в БД!');
        }
        console.log('[DB] Подключение к PostgreSQL и таблица пользователей готовы.');
    } catch (err) {
        console.error('[DB Error] Ошибка инициализации PostgreSQL:', err);
    }
}
initDB();

// Random password generator
function generateRandomPassword(length = 12) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*';
    let pwd = '';
    const bytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
        pwd += chars[bytes[i] % chars.length];
    }
    return pwd;
}

// Timing attack safe comparison
function safeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

// HMAC session token generation
function generateSessionToken(username, hwid, timestamp) {
    return crypto
        .createHmac('sha256', SECRET_SALT)
        .update(`${username}:${hwid}:${timestamp}`)
        .digest('hex');
}

// HTML escape for XSS prevention
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Authenticate Admin from request
async function getAuthenticatedAdmin(req) {
    const authAdmin = req.query.adminUser || req.body.adminUser;
    const authPass = req.query.adminPass || req.body.adminPass;
    if (!authAdmin || !authPass) return null;

    try {
        const res = await pool.query('SELECT * FROM users WHERE LOWER(username) = $1', [authAdmin.toLowerCase()]);
        if (res.rows.length > 0) {
            const user = res.rows[0];
            if (user.is_admin && safeCompare(user.password, authPass)) {
                return user;
            }
        }
    } catch (e) {
        return null;
    }
    return null;
}

// Admin Panel Web Interface
app.get('/admin', async (req, res) => {
    const adminUser = await getAuthenticatedAdmin(req);

    if (!adminUser) {
        return res.send(`
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <title>Авторизация | Админ-панель</title>
                <style>
                    body { font-family: monospace; background: #121212; color: #00ff66; padding: 50px; display: flex; justify-content: center; align-items: center; height: 70vh; margin: 0; }
                    .login-card { border: 1px solid #00ff66; padding: 30px; border-radius: 8px; background: #181818; width: 350px; text-align: center; box-shadow: 0 0 15px rgba(0,255,102,0.2); }
                    input { width: 90%; padding: 10px; background: #222; color: #fff; border: 1px solid #00ff66; margin: 10px 0; font-family: monospace; }
                    button { width: 95%; padding: 10px; background: #00ff66; color: #000; font-weight: bold; border: none; cursor: pointer; font-family: monospace; }
                </style>
            </head>
            <body>
                <div class="login-card">
                    <h2>🔑 Вход в Админку</h2>
                    <form action="/admin" method="GET">
                        <input type="text" name="adminUser" required placeholder="Введите логин"><br/>
                        <input type="password" name="adminPass" required placeholder="Введите пароль"><br/>
                        <button type="submit">Войти</button>
                    </form>
                </div>
            </body>
            </html>
        `);
    }

    let users = [];
    try {
        const dbUsers = await pool.query('SELECT * FROM users ORDER BY id ASC');
        users = dbUsers.rows;
    } catch (e) {
        users = [];
    }

    const now = new Date();
    const generatedPwd = req.query.newPwd ? escapeHtml(req.query.newPwd) : null;
    const generatedUsername = req.query.newUsername ? escapeHtml(req.query.newUsername) : null;

    res.send(`
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>Управление пользователями и подписками</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; }
                input, select, button { padding: 8px; background: #222; color: #fff; border: 1px solid #00ff66; margin: 5px 0; font-family: monospace; }
                button { cursor: pointer; background: #00ff66; color: #000; font-weight: bold; border: none; padding: 8px 14px; }
                button.btn-danger { background: #ff3333; color: #fff; }
                button.btn-warn { background: #ffaa00; color: #000; }
                .card { border: 1px solid #333; padding: 20px; border-radius: 8px; max-width: 950px; margin-bottom: 20px; background: #181818; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                th, td { border: 1px solid #333; padding: 10px; text-align: left; }
                th { background: #222; color: #00ff66; }
                .expired { color: #ff5555; }
                .active { color: #00ff66; }
                .alert-success { background: #004411; border: 1px solid #00ff66; padding: 15px; border-radius: 5px; margin-bottom: 15px; color: #fff; }
            </style>
        </head>
        <body>
            <h2>🔑 Управление пользователями и подписками (PostgreSQL БД)</h2>
            <p>Вы вошли как: <b>${escapeHtml(adminUser.username)}</b></p>
            
            ${generatedPwd ? `
                <div class="alert-success">
                    <b>✅ Новый пользователь успешно создан!</b><br/>
                    Логин: <b>${generatedUsername}</b><br/>
                    Сгенерированный пароль: <b style="color:#00ff66; font-size:16px;">${generatedPwd}</b><br/>
                    <i>(Сохраните эти данные для передачи клиенту!)</i>
                </div>
            ` : ''}

            <div class="card">
                <h3>Создание нового пользователя</h3>
                <form action="/api/admin/create-user" method="POST">
                    <input type="hidden" name="adminUser" value="${escapeHtml(adminUser.username)}">
                    <input type="hidden" name="adminPass" value="${escapeHtml(adminUser.password)}">
                    
                    <label>Логин пользователя:</label><br/>
                    <input type="text" name="username" required placeholder="user123" style="width:250px;"><br/>
                    
                    <label>Пароль (оставьте пустым для авто-генерации):</label><br/>
                    <input type="text" name="customPassword" placeholder="Автоматический случайный пароль" style="width:250px;"><br/>

                    <label>Роль в системе (IsAdmin):</label><br/>
                    <select name="isAdmin">
                        <option value="false">Обычный пользователь (IsAdmin = false)</option>
                        <option value="true">Администратор (IsAdmin = true)</option>
                    </select><br/>
                    
                    <label>Срок подписки:</label><br/>
                    <select name="duration">
                        <option value="lifetime">Навсегда (Lifetime)</option>
                        <option value="1d">1 день</option>
                        <option value="7d">7 дней</option>
                        <option value="30d">30 дней</option>
                        <option value="90d">90 дней</option>
                        <option value="365d">365 дней (1 год)</option>
                    </select><br/><br/>
                    
                    <button type="submit">Создать пользователя</button>
                </form>
            </div>
            
            <div class="card">
                <h3>Пользователи в базе данных PostgreSQL (${users.length}):</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Логин</th>
                            <th>IsAdmin</th>
                            <th>HWID</th>
                            <th>Создан</th>
                            <th>Подписка до</th>
                            <th>Статус</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${users.map(u => {
                            const isExpired = u.expires_at && new Date(u.expires_at) < now;
                            const statusText = isExpired ? '<span class="expired">Подписка истёкла</span>' : '<span class="active">Активна</span>';
                            const expText = u.expires_at ? new Date(u.expires_at).toLocaleString() : 'Навсегда';
                            
                            return `
                                <tr>
                                    <td><b>${escapeHtml(u.username)}</b></td>
                                    <td>${u.is_admin ? '<b style="color:#00ff66;">True</b>' : 'False'}</td>
                                    <td>${escapeHtml(u.hwid || 'Не привязан')}</td>
                                    <td>${new Date(u.created_at).toLocaleString()}</td>
                                    <td>${expText}</td>
                                    <td>${statusText}</td>
                                    <td>
                                        <form style="display:inline;" action="/api/admin/reset-hwid" method="POST" onsubmit="return confirm('Сбросить HWID у пользователя ${escapeHtml(u.username)}?');">
                                            <input type="hidden" name="targetUser" value="${escapeHtml(u.username)}">
                                            <input type="hidden" name="adminUser" value="${escapeHtml(adminUser.username)}">
                                            <input type="hidden" name="adminPass" value="${escapeHtml(adminUser.password)}">
                                            <button type="submit" class="btn-warn">Сбросить HWID</button>
                                        </form>
                                        <form style="display:inline;" action="/api/admin/delete-user" method="POST" onsubmit="return confirm('Удалить пользователя ${escapeHtml(u.username)}?');">
                                            <input type="hidden" name="targetUser" value="${escapeHtml(u.username)}">
                                            <input type="hidden" name="adminUser" value="${escapeHtml(adminUser.username)}">
                                            <input type="hidden" name="adminPass" value="${escapeHtml(adminUser.password)}">
                                            <button type="submit" class="btn-danger">Удалить</button>
                                        </form>
                                    </td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
    `);
});

// Admin API: Create User
app.post('/api/admin/create-user', async (req, res) => {
    const adminUser = await getAuthenticatedAdmin(req);
    if (!adminUser) {
        return res.status(403).json({ success: false, message: 'Неверные данные администратора!' });
    }

    const { username, customPassword, isAdmin, duration } = req.body;
    if (!username || typeof username !== 'string' || username.trim() === '') {
        return res.status(400).json({ success: false, message: 'Укажите верное имя пользователя' });
    }

    const cleanUsername = username.trim();
    const pwd = (customPassword && customPassword.trim() !== '') ? customPassword.trim() : generateRandomPassword();

    let expiresAt = null;
    if (duration && duration !== 'lifetime') {
        const now = new Date();
        if (duration === '1d') now.setDate(now.getDate() + 1);
        else if (duration === '7d') now.setDate(now.getDate() + 7);
        else if (duration === '30d') now.setDate(now.getDate() + 30);
        else if (duration === '90d') now.setDate(now.getDate() + 90);
        else if (duration === '365d') now.setDate(now.getDate() + 365);
        expiresAt = now.toISOString();
    }

    try {
        await pool.query(
            'INSERT INTO users (username, password, is_admin, expires_at) VALUES ($1, $2, $3, $4)',
            [cleanUsername, pwd, isAdmin === 'true' || isAdmin === true, expiresAt]
        );
    } catch (e) {
        return res.status(400).json({ success: false, message: 'Пользователь с таким логином уже существует в БД!' });
    }

    if (req.headers['content-type'] === 'application/json') {
        return res.json({ success: true, username: cleanUsername, password: pwd, isAdmin, expiresAt });
    } else {
        return res.redirect(`/admin?adminUser=${encodeURIComponent(adminUser.username)}&adminPass=${encodeURIComponent(adminUser.password)}&newUsername=${encodeURIComponent(cleanUsername)}&newPwd=${encodeURIComponent(pwd)}`);
    }
});

// Admin API: Reset HWID
app.post('/api/admin/reset-hwid', async (req, res) => {
    const adminUser = await getAuthenticatedAdmin(req);
    if (!adminUser) {
        return res.status(403).json({ success: false, message: 'Неверные данные администратора!' });
    }

    const { targetUser } = req.body;
    if (targetUser) {
        await pool.query('UPDATE users SET hwid = NULL WHERE LOWER(username) = $1', [targetUser.trim().toLowerCase()]);
    }

    if (req.headers['content-type'] === 'application/json') {
        return res.json({ success: true, message: 'HWID пользователя сброшен' });
    } else {
        return res.redirect(`/admin?adminUser=${encodeURIComponent(adminUser.username)}&adminPass=${encodeURIComponent(adminUser.password)}`);
    }
});

// Admin API: Delete User
app.post('/api/admin/delete-user', async (req, res) => {
    const adminUser = await getAuthenticatedAdmin(req);
    if (!adminUser) {
        return res.status(403).json({ success: false, message: 'Неверные данные администратора!' });
    }

    const { targetUser } = req.body;
    const target = (targetUser || '').trim().toLowerCase();

    if (target === 'admin') {
        return res.status(400).json({ success: false, message: 'Нельзя удалить главного администратора!' });
    }

    await pool.query('DELETE FROM users WHERE LOWER(username) = $1', [target]);

    if (req.headers['content-type'] === 'application/json') {
        return res.json({ success: true, message: 'Пользователь удален' });
    } else {
        return res.redirect(`/admin?adminUser=${encodeURIComponent(adminUser.username)}&adminPass=${encodeURIComponent(adminUser.password)}`);
    }
});

// Endpoint to validate C# Client (User + Password + Subscription + HWID)
app.post('/api/validate', async (req, res) => {
    const { username, password, hwid } = req.body;

    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ valid: false, message: 'Логин и пароль обязательны' });
    }

    const cleanUsername = username.trim();
    let user = null;

    try {
        const dbRes = await pool.query('SELECT * FROM users WHERE LOWER(username) = $1', [cleanUsername.toLowerCase()]);
        if (dbRes.rows.length > 0) {
            user = dbRes.rows[0];
        }
    } catch (e) {
        return res.status(500).json({ valid: false, message: 'Ошибка базы данных' });
    }

    if (!user || !safeCompare(user.password, password)) {
        return res.status(401).json({ valid: false, message: 'Неверный логин или пароль!' });
    }

    // Check subscription expiration
    if (user.expires_at && new Date(user.expires_at) < new Date()) {
        return res.status(401).json({ valid: false, message: 'Срок подписки истёк!' });
    }

    // Check and bind HWID
    if (hwid && typeof hwid === 'string' && hwid.trim() !== '') {
        const cleanHwid = hwid.trim();
        if (!user.hwid) {
            await pool.query('UPDATE users SET hwid = $1 WHERE id = $2', [cleanHwid, user.id]);
            user.hwid = cleanHwid;
        } else if (!safeCompare(user.hwid, cleanHwid)) {
            return res.status(403).json({ valid: false, message: 'Аккаунт привязан к другому ПК (HWID mismatch)!' });
        }
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const token = generateSessionToken(user.username, user.hwid || hwid || 'nohwid', timestamp);

    return res.json({
        valid: true,
        message: 'Авторизация успешна!',
        username: user.username,
        isAdmin: user.is_admin,
        timestamp: timestamp,
        token: token
    });
});

app.listen(PORT, () => {
    console.log(`[Backend] Сервер запущен на http://localhost:${PORT}`);
});
