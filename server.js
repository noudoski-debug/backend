const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = 'qqbot2323';
const KEYS_FILE = path.join(__dirname, 'keys.json');

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Generate key matching pattern: 123aaa567@#$2 (digits, letters, digits, symbols, digit)
function generateKeyFormat() {
    const chars = 'abcdefghijklmnopqrstuvwxyz';
    const symbols = '@#$%&*!';
    
    let part1 = Math.floor(100 + Math.random() * 900); // 3 digits
    let part2 = '';
    for (let i = 0; i < 3; i++) {
        part2 += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    let part3 = Math.floor(100 + Math.random() * 900); // 3 digits
    let part4 = '';
    for (let i = 0; i < 3; i++) {
        part4 += symbols.charAt(Math.floor(Math.random() * symbols.length));
    }
    let part5 = Math.floor(Math.random() * 10); // 1 digit

    return `${part1}${part2}${part3}${part4}${part5}`;
}

// Admin Panel UI
app.get('/admin', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>Админ-панель ключей</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 30px; }
                input, button { padding: 10px; background: #222; color: #fff; border: 1px solid #00ff66; margin: 5px 0; font-family: monospace; }
                button { cursor: pointer; background: #00ff66; color: #000; font-weight: bold; }
                .card { border: 1px solid #333; padding: 20px; border-radius: 8px; max-width: 500px; margin-bottom: 20px; }
                ul { list-style-type: square; }
            </style>
        </head>
        <body>
            <h2>🔑 Админка генерации ключей</h2>
            <div class="card">
                <form action="/api/admin/generate" method="POST">
                    <label>Админ-ключ:</label><br/>
                    <input type="password" name="adminKey" required placeholder="qqbot2323"><br/><br/>
                    <button type="submit">Сгенерировать новый ключ</button>
                </form>
            </div>
            
            <div class="card">
                <h3>Список активных ключей:</h3>
                <ul>
                    ${validKeys.map(k => `<li><b>${k.key}</b> (Создан: ${new Date(k.createdAt).toLocaleString()})</li>`).join('')}
                </ul>
            </div>
        </body>
        </html>
    `);
});

// Admin API to generate key
app.post('/api/admin/generate', (req, res) => {
    const { adminKey } = req.body;
    if (adminKey !== ADMIN_KEY) {
        return res.status(403).json({ success: false, message: 'Неверный админ-ключ!' });
    }

    const newKey = generateKeyFormat();
    const keyData = { key: newKey, createdAt: new Date().toISOString() };
    validKeys.push(keyData);
    saveKeys();

    if (req.headers['content-type'] === 'application/json') {
        return res.json({ success: true, key: newKey });
    } else {
        return res.redirect('/admin');
    }
});

// Endpoint to validate key from C# client
app.post('/api/validate', (req, res) => {
    const { key } = req.body;
    if (!key) {
        return res.status(400).json({ valid: false, message: 'Ключ не передан' });
    }

    const found = validKeys.find(k => k.key === key.trim());
    if (found) {
        return res.json({ valid: true, message: 'Авторизация успешна!' });
    } else {
        return res.status(401).json({ valid: false, message: 'Неверный или недействительный ключ!' });
    }
});

app.listen(PORT, () => {
    console.log(`[Backend] Сервер запущен на http://localhost:${PORT}`);
    console.log(`[Backend] Админка доступна по http://localhost:${PORT}/admin`);
});
