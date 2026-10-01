const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'qqbot2323';
const SECRET_SALT = process.env.SECRET_SALT || 'gomkarat_super_secret_salt_2026_x86_x64';
const KEYS_FILE = path.join(__dirname, 'keys.json');

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

// Load existing keys from file
let validKeys = [];
if (fs.existsSync(KEYS_FILE)) {
    try {
        validKeys = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
    } catch (e) {
        validKeys = [];
    }
}

function saveKeys() {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(validKeys, null, 2));
}

// Cryptographically secure key generation
function generateKeyFormat() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let key = '';
    const bytes = crypto.randomBytes(16);
    for (let i = 0; i < 16; i++) {
        key += chars[bytes[i] % chars.length];
    }
    return key.toUpperCase();
}

// Timing attack safe comparison
function safeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

// Generate HMAC session token
function generateSessionToken(key, hwid, timestamp) {
    return crypto
        .createHmac('sha256', SECRET_SALT)
        .update(`${key}:${hwid}:${timestamp}`)
        .digest('hex');
}

// Escape HTML for XSS prevention
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Admin Panel UI
app.get('/admin', (req, res) => {
    const now = new Date();
    res.send(`
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>Админ-панель ключей</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; }
                input, select, button { padding: 8px; background: #222; color: #fff; border: 1px solid #00ff66; margin: 5px 0; font-family: monospace; }
                button { cursor: pointer; background: #00ff66; color: #000; font-weight: bold; border: none; padding: 8px 14px; }
                button.btn-danger { background: #ff3333; color: #fff; }
                button.btn-warn { background: #ffaa00; color: #000; }
                .card { border: 1px solid #333; padding: 20px; border-radius: 8px; max-width: 800px; margin-bottom: 20px; background: #181818; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                th, td { border: 1px solid #333; padding: 10px; text-align: left; }
                th { background: #222; color: #00ff66; }
                .expired { color: #ff5555; }
                .active { color: #00ff66; }
            </style>
        </head>
        <body>
            <h2>🔑 Управление ключами доступа</h2>
            
            <div class="card">
                <h3>Генерация нового ключа</h3>
                <form action="/api/admin/generate" method="POST">
                    <label>Админ-ключ:</label><br/>
                    <input type="password" name="adminKey" required placeholder="Введите админ-ключ"><br/><br/>
                    
                    <label>Срок действия ключа:</label><br/>
                    <select name="duration">
                        <option value="lifetime">Навсегда (Lifetime)</option>
                        <option value="1d">1 день</option>
                        <option value="7d">7 дней</option>
                        <option value="30d">30 дней</option>
                        <option value="90d">90 дней</option>
                        <option value="365d">365 дней (1 год)</option>
                    </select><br/><br/>
                    
                    <button type="submit">Сгенерировать ключ</button>
                </form>
            </div>
            
            <div class="card">
                <h3>Активные и выданные ключи (${validKeys.length}):</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Ключ</th>
                            <th>HWID</th>
                            <th>Создан</th>
                            <th>Истекает</th>
                            <th>Статус</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${validKeys.map(k => {
                            const isExpired = k.expiresAt && new Date(k.expiresAt) < now;
                            const statusText = isExpired ? '<span class="expired">Истёк</span>' : '<span class="active">Активен</span>';
                            const expText = k.expiresAt ? new Date(k.expiresAt).toLocaleString() : 'Навсегда';
                            
                            return `
                                <tr>
                                    <td><b>${escapeHtml(k.key)}</b></td>
                                    <td>${escapeHtml(k.hwid || 'Не привязан')}</td>
                                    <td>${new Date(k.createdAt).toLocaleString()}</td>
                                    <td>${expText}</td>
                                    <td>${statusText}</td>
                                    <td>
                                        <form style="display:inline;" action="/api/admin/reset-hwid" method="POST" onsubmit="return confirm('Сбросить HWID у данного ключа?');">
                                            <input type="hidden" name="key" value="${escapeHtml(k.key)}">
                                            <input type="password" name="adminKey" required placeholder="Пароль" style="width:70px; padding:4px;">
                                            <button type="submit" class="btn-warn">Сбросить HWID</button>
                                        </form>
                                        <form style="display:inline;" action="/api/admin/delete-key" method="POST" onsubmit="return confirm('Удалить данный ключ?');">
                                            <input type="hidden" name="key" value="${escapeHtml(k.key)}">
                                            <input type="password" name="adminKey" required placeholder="Пароль" style="width:70px; padding:4px;">
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

// Admin API to generate key with duration
app.post('/api/admin/generate', (req, res) => {
    const { adminKey, duration } = req.body;
    if (!safeCompare(adminKey, ADMIN_KEY)) {
        return res.status(403).json({ success: false, message: 'Неверный админ-ключ!' });
    }

    const newKey = generateKeyFormat();
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

    const keyData = {
        key: newKey,
        hwid: null,
        createdAt: new Date().toISOString(),
        expiresAt: expiresAt
    };
    
    validKeys.push(keyData);
    saveKeys();

    if (req.headers['content-type'] === 'application/json') {
        return res.json({ success: true, key: newKey, expiresAt });
    } else {
        return res.redirect('/admin');
    }
});

// Admin API to reset HWID
app.post('/api/admin/reset-hwid', (req, res) => {
    const { adminKey, key } = req.body;
    if (!safeCompare(adminKey, ADMIN_KEY)) {
        return res.status(403).json({ success: false, message: 'Неверный админ-ключ!' });
    }

    const found = validKeys.find(k => k.key === (key || '').trim());
    if (found) {
        found.hwid = null;
        saveKeys();
    }

    if (req.headers['content-type'] === 'application/json') {
        return res.json({ success: true, message: 'HWID успешно сброшен' });
    } else {
        return res.redirect('/admin');
    }
});

// Admin API to delete key
app.post('/api/admin/delete-key', (req, res) => {
    const { adminKey, key } = req.body;
    if (!safeCompare(adminKey, ADMIN_KEY)) {
        return res.status(403).json({ success: false, message: 'Неверный админ-ключ!' });
    }

    const targetKey = (key || '').trim();
    validKeys = validKeys.filter(k => k.key !== targetKey);
    saveKeys();

    if (req.headers['content-type'] === 'application/json') {
        return res.json({ success: true, message: 'Ключ успешно удален' });
    } else {
        return res.redirect('/admin');
    }
});

// Endpoint to validate key from C# client
app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || typeof key !== 'string') {
        return res.status(400).json({ valid: false, message: 'Ключ не передан или имеет неверный формат' });
    }

    const cleanKey = key.trim();
    const found = validKeys.find(k => k.key === cleanKey);

    if (!found) {
        return res.status(401).json({ valid: false, message: 'Неверный или недействительный ключ!' });
    }

    // Проверка срока действия ключа
    if (found.expiresAt && new Date(found.expiresAt) < new Date()) {
        return res.status(401).json({ valid: false, message: 'Срок действия ключа истёк!' });
    }

    // Привязка и проверка HWID
    if (hwid && typeof hwid === 'string' && hwid.trim() !== '') {
        const cleanHwid = hwid.trim();
        if (!found.hwid) {
            found.hwid = cleanHwid;
            saveKeys();
        } else if (!safeCompare(found.hwid, cleanHwid)) {
            return res.status(403).json({ valid: false, message: 'Ключ привязан к другому ПК (HWID mismatch)!' });
        }
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const token = generateSessionToken(cleanKey, found.hwid || hwid || 'nohwid', timestamp);

    return res.json({
        valid: true,
        message: 'Авторизация успешна!',
        timestamp: timestamp,
        token: token
    });
});

app.listen(PORT, () => {
    console.log(`[Backend] Сервер запущен на http://localhost:${PORT}`);
    console.log(`[Backend] Админка доступна по http://localhost:${PORT}/admin`);
});
