require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const multer = require('multer');
const sharp = require('sharp');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('HIBA: Állíts be egy legalább 32 karakteres JWT_SECRET értéket a .env fájlban!');
    process.exit(1);
}

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const ALLOWED_MIMES = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp',
    'image/gif': '.gif'
};

const storage = multer.memoryStorage();

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
        if (ALLOWED_MIMES[file.mimetype]) cb(null, true);
        else cb(new Error('Csak JPEG, PNG, WebP vagy GIF képfájl tölthető fel.'));
    }
});

async function resizeAndSavePhoto(file) {
    if (!file) return null;
    const ext = ALLOWED_MIMES[file.mimetype] || '.jpg';
    const filename = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
    const filePath = path.join(uploadDir, filename);

    await sharp(file.buffer)
        .resize({ width: 1200, withoutEnlargement: true })
        .toFile(filePath);

    return photoApiPath(filename);
}

const LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$/;

/*
app.use(cors({
    origin(origin, callback) {
        if (!origin || LOCAL_ORIGIN_RE.test(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS nem engedélyezett erről az origin-ről.'));
        }
    }
}));
*/
// Megengedő, de biztonságos CORS szabályozás helyi hálózatra (LAN), Tailscale VPN-re, localhostra és Cloudflare-re
const ALLOWED_ORIGIN_RE = /^(https?:\/\/(?:localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+\.ts\.net|[a-zA-Z0-9-]+\.trycloudflare\.com)(?::\d+)?)$/i;

app.use(cors({
    origin(origin, callback) {
        if (!origin || ALLOWED_ORIGIN_RE.test(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS nem engedélyezett erről az origin-ről.'));
        }
    }
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'inventory_db',
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306
});

// Automatikus adatbázis migrálás
(async () => {
    try {
        const [tables] = await db.query("SHOW TABLES LIKE 'users'");
        if (tables.length > 0) {
            const [columns] = await db.query('SHOW COLUMNS FROM users');
            const hasEmail = columns.some(col => col.Field === 'email');
            const hasResetToken = columns.some(col => col.Field === 'reset_token');
            const hasResetTokenExpires = columns.some(col => col.Field === 'reset_token_expires');

            if (!hasEmail) {
                console.log('Adding "email" column to "users" table...');
                await db.query('ALTER TABLE users ADD COLUMN email VARCHAR(100) DEFAULT NULL');
                await db.query('UPDATE users SET email = CONCAT(username, "@example.com") WHERE email IS NULL');
                await db.query('ALTER TABLE users MODIFY COLUMN email VARCHAR(100) NOT NULL');
                await db.query('ALTER TABLE users ADD UNIQUE KEY uq_email (email)');
            }
            if (!hasResetToken) {
                console.log('Adding "reset_token" column to "users" table...');
                await db.query('ALTER TABLE users ADD COLUMN reset_token VARCHAR(100) DEFAULT NULL');
            }
            if (!hasResetTokenExpires) {
                console.log('Adding "reset_token_expires" column to "users" table...');
                await db.query('ALTER TABLE users ADD COLUMN reset_token_expires TIMESTAMP DEFAULT NULL');
            }
        }
    } catch (err) {
        console.error('Hiba az adatbázis frissítésekor (migráció):', err);
    }
})();

// --- Segédfüggvények ---

const rateBuckets = new Map();

function rateLimit(windowMs, maxRequests) {
    return (req, res, next) => {
        const key = `${req.ip}:${req.path}`;
        const now = Date.now();
        let bucket = rateBuckets.get(key);

        if (!bucket || now - bucket.start > windowMs) {
            bucket = { start: now, count: 0 };
            rateBuckets.set(key, bucket);
        }

        bucket.count += 1;
        if (bucket.count > maxRequests) {
            return res.status(429).json({ error: 'Túl sok kísérlet. Próbáld újra később.' });
        }
        next();
    };
}

// Brute Force védelem bejelentkezési adatok zárolásával
const loginFailures = new Map();
const LOCKOUT_LIMIT = 5; // maximum 5 sikertelen kísérlet
const LOCKOUT_TIME = 10 * 60 * 1000; // 10 perc zárolás

function getLockoutStatus(username) {
    const record = loginFailures.get(username);
    if (!record) return { locked: false };

    const now = Date.now();
    if (record.lockedUntil && record.lockedUntil > now) {
        const remainingMs = record.lockedUntil - now;
        const remainingMin = Math.ceil(remainingMs / 60000);
        return { locked: true, remainingMin };
    }

    if (record.lockedUntil && record.lockedUntil <= now) {
        loginFailures.delete(username);
    }

    return { locked: false };
}

function recordLoginFailure(username) {
    const now = Date.now();
    let record = loginFailures.get(username);
    if (!record) {
        record = { count: 0, lockedUntil: null };
    }

    record.count += 1;
    if (record.count >= LOCKOUT_LIMIT) {
        record.lockedUntil = now + LOCKOUT_TIME;
    }

    loginFailures.set(username, record);
    return record;
}

function clearLoginFailures(username) {
    loginFailures.delete(username);
}

function validateUsername(username) {
    const trimmed = (username || '').trim();
    if (trimmed.length < 3 || trimmed.length > 50) {
        return { error: 'A felhasználónév 3–50 karakter hosszú legyen.' };
    }
    if (!/^[a-zA-Z0-9_áéíóöőúüűÁÉÍÓÖŐÚÜŰ.-]+$/.test(trimmed)) {
        return { error: 'A felhasználónév csak betűket, számokat és ._- karaktereket tartalmazhat.' };
    }
    return { value: trimmed };
}

function validateEmail(email) {
    const trimmed = (email || '').trim();
    if (!trimmed) {
        return { error: 'Az email cím megadása kötelező!' };
    }
    if (trimmed.length > 100) {
        return { error: 'Az email cím legfeljebb 100 karakter lehet.' };
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmed)) {
        return { error: 'Érvénytelen email cím formátum.' };
    }
    return { value: trimmed };
}

function validatePassword(password) {
    if (!password || password.length < 6) {
        return { error: 'A jelszó legalább 6 karakter hosszú legyen.' };
    }
    if (password.length > 128) {
        return { error: 'A jelszó legfeljebb 128 karakter lehet.' };
    }
    if (!/[a-z]/.test(password)) {
        return { error: 'A jelszónak tartalmaznia kell legalább egy kisbetűt (a-z).' };
    }
    if (!/[A-Z]/.test(password)) {
        return { error: 'A jelszónak tartalmaznia kell legalább egy nagybetűt (A-Z).' };
    }
    if (!/[^a-zA-Z0-9]/.test(password)) {
        return { error: 'A jelszónak tartalmaznia kell legalább egy speciális karaktert (pl. !@#$%^&*).' };
    }
    return { value: password };
}

function validateRequiredText(value, fieldLabel, maxLen = 200) {
    const trimmed = (value || '').trim();
    if (!trimmed) return { error: `${fieldLabel} kötelező!` };
    if (trimmed.length > maxLen) return { error: `${fieldLabel} legfeljebb ${maxLen} karakter lehet.` };
    return { value: trimmed };
}

function optionalText(value, maxLen = 500) {
    if (value == null || value === '') return null;
    const trimmed = String(value).trim();
    if (trimmed.length > maxLen) return { error: `A mező legfeljebb ${maxLen} karakter lehet.` };
    return trimmed;
}

function deletePhotoFile(photoUrl) {
    if (!photoUrl) return;
    const filename = path.basename(photoUrl);
    const filePath = path.join(uploadDir, filename);
    if (fs.existsSync(filePath)) {
        try { fs.unlinkSync(filePath); } catch (_) { /* ignore */ }
    }
}

function photoApiPath(filename) {
    return `/api/uploads/${filename}`;
}


const ADMIN_USER = 'admin'; // Cseréld le a saját felhasználónevedre

function checkAdmin(req, res, next) {
    if (req.user.username !== ADMIN_USER) {
        return res.status(403).json({ error: 'Nincs adminisztrátori jogosultságod.' });
    }
    next();
}

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/admin/stats', authMiddleware, checkAdmin, async (req, res) => {
    try {
        const [users] = await db.query('SELECT id, username, email, created_at FROM users');
        const [boxes] = await db.query('SELECT count(*) as count FROM boxes');
        const [items] = await db.query('SELECT count(*) as count FROM items');
        res.json({ users, stats: { boxes: boxes[0].count, items: items[0].count } });
    } catch (err) {
        res.status(500).json({ error: 'Hiba az adatok lekérésekor.' });
    }
});

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Nincs érvényes munkamenet.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (_err) {
        return res.status(401).json({ error: 'Érvénytelen munkamenet.' });
    }
}

function handleUploadError(err, req, res, next) {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'A kép mérete legfeljebb 5 MB lehet.' });
        }
        return res.status(400).json({ error: 'Hiba a fájl feltöltésekor.' });
    }
    if (err) {
        return res.status(400).json({ error: err.message });
    }
    next();
}

// --- AUTH ---

app.post('/api/auth/register', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
    const usernameResult = validateUsername(req.body.username);
    if (usernameResult.error) return res.status(400).json({ error: usernameResult.error });

    const emailResult = validateEmail(req.body.email);
    if (emailResult.error) return res.status(400).json({ error: emailResult.error });

    const passwordResult = validatePassword(req.body.password);
    if (passwordResult.error) return res.status(400).json({ error: passwordResult.error });

    try {
        const hash = await bcrypt.hash(passwordResult.value, 10);
        const [result] = await db.query(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [usernameResult.value, emailResult.value, hash]
        );
        const token = jwt.sign(
            { id: result.insertId, username: usernameResult.value },
            JWT_SECRET,
            { expiresIn: '30d' }
        );
        res.json({ success: true, token, username: usernameResult.value });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            if (err.message.includes('email') || err.message.includes('uq_email')) {
                return res.status(400).json({ error: 'Ez az email cím már regisztrálva van.' });
            }
            return res.status(400).json({ error: 'Ez a felhasználónév már foglalt.' });
        }
        res.status(500).json({ error: 'Szerverhiba a regisztráció során.' });
    }
});

app.post('/api/auth/forgot-password', rateLimit(15 * 60 * 1000, 5), async (req, res) => {
    const emailResult = validateEmail(req.body.email);
    if (emailResult.error) return res.status(400).json({ error: emailResult.error });

    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [emailResult.value]);
        if (users.length === 0) {
            // Biztonsági okokból sikeres üzenetet adunk vissza a felhasználói adatok védelmében
            return res.json({ success: true, message: 'Ha a megadott e-mail címmel létezik regisztráció, elküldtük a visszaállítási kódot.' });
        }

        const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 percig érvényes

        await db.query(
            'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?',
            [resetToken, expires, emailResult.value]
        );

        // Kiírjuk a szerver konzolba is a könnyű tesztelés érdekében
        console.log('\n==================================================');
        console.log(`JELSZÓ-VISSZAÁLLÍTÁSI KÓD (${emailResult.value}): ${resetToken}`);
        console.log('==================================================\n');

        let emailSent = false;
        if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
            try {
                const transporter = nodemailer.createTransport({
                    host: process.env.SMTP_HOST,
                    port: Number(process.env.SMTP_PORT) || 587,
                    secure: Number(process.env.SMTP_PORT) === 465,
                    auth: {
                        user: process.env.SMTP_USER,
                        pass: process.env.SMTP_PASS
                    }
                });

                await transporter.sendMail({
                    from: process.env.SMTP_FROM || `"Doboz Raktár" <${process.env.SMTP_USER}>`,
                    to: emailResult.value,
                    subject: 'Jelszó visszaállítása - Doboz Raktár',
                    text: `Kedves Felhasználó!\n\nA jelszavad visszaállításához szükséges 6-jegyű ellenőrző kód:\n\n${resetToken}\n\nA kód 15 percig érvényes.\nHa nem te kérted a visszaállítást, hagyd figyelmen kívül ezt a levelet.`,
                    html: `<p>Kedves Felhasználó!</p><p>A jelszavad visszaállításához szükséges 6-jegyű ellenőrző kód:</p><h2 style="color: #4f46e5; font-size: 24px; font-family: monospace;">${resetToken}</h2><p>A kód 15 percig érvényes.</p><p>Ha nem te kérted a visszaállítást, hagyd figyelmen kívül ezt a levelet.</p>`
                });
                emailSent = true;
            } catch (err) {
                console.error('Hiba az e-mail küldésekor:', err);
            }
        }

        res.json({ 
            success: true, 
            message: emailSent 
                ? 'Elküldtük a visszaállítási kódot az e-mail címedre.' 
                : 'A visszaállítási kód legenerálva. (Mivel nincs beállítva SMTP küldő, a kód a szerver konzolba lett kiírva!)' 
        });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a kérés feldolgozása során.' });
    }
});

app.post('/api/auth/reset-password', rateLimit(15 * 60 * 1000, 5), async (req, res) => {
    const emailResult = validateEmail(req.body.email);
    if (emailResult.error) return res.status(400).json({ error: emailResult.error });

    const token = (req.body.token || '').trim();
    if (!token || token.length !== 6) {
        return res.status(400).json({ error: 'Az ellenőrző kód pontosan 6 számjegyből áll.' });
    }

    const passwordResult = validatePassword(req.body.newPassword);
    if (passwordResult.error) return res.status(400).json({ error: passwordResult.error });

    try {
        const [users] = await db.query(
            'SELECT * FROM users WHERE email = ? AND reset_token = ? AND reset_token_expires > ?',
            [emailResult.value, token, new Date()]
        );

        if (users.length === 0) {
            return res.status(400).json({ error: 'Érvénytelen vagy lejárt ellenőrző kód.' });
        }

        const hash = await bcrypt.hash(passwordResult.value, 10);
        await db.query(
            'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
            [hash, users[0].id]
        );

        res.json({ success: true, message: 'A jelszó sikeresen megváltoztatva. Most már bejelentkezhetsz az új jelszóval.' });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a jelszó visszaállítása során.' });
    }
});

app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 20), async (req, res) => {
    const usernameResult = validateUsername(req.body.username);
    if (usernameResult.error) return res.status(400).json({ error: usernameResult.error });

    if (!req.body.password) return res.status(400).json({ error: 'A jelszó kötelező.' });

    const username = usernameResult.value;

    // Zárolás ellenőrzése
    const lockout = getLockoutStatus(username);
    if (lockout.locked) {
        return res.status(423).json({ 
            error: `Ez a fiók túl sok sikertelen bejelentkezési kísérlet miatt zárolva lett. Kérlek próbáld újra ${lockout.remainingMin} perc múlva.` 
        });
    }

    try {
        const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            // Nem adunk ki információt arról, hogy létezik-e a felhasználó
            return res.status(401).json({ error: 'Hibás felhasználónév vagy jelszó.' });
        }

        const match = await bcrypt.compare(req.body.password, users[0].password_hash);
        if (!match) {
            // Sikertelen kísérlet naplózása
            const record = recordLoginFailure(username);
            if (record.lockedUntil) {
                return res.status(423).json({ 
                    error: `Hibás jelszó. Elérted a maximális kísérletek számát. A fiók zárolva lett 10 percre.` 
                });
            } else {
                const remaining = LOCKOUT_LIMIT - record.count;
                return res.status(401).json({ 
                    error: `Hibás felhasználónév vagy jelszó. Még ${remaining} kísérleted maradt a fiók zárolása előtt.` 
                });
            }
        }

        // Sikeres bejelentkezés esetén töröljük a sikertelen kísérleteket
        clearLoginFailures(username);

        const token = jwt.sign(
            { id: users[0].id, username: users[0].username },
            JWT_SECRET,
            { expiresIn: '30d' }
        );
        res.json({ success: true, token, username: users[0].username });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a bejelentkezés során.' });
    }
});

// --- VÉDETT FÁJLOK ---

app.get('/api/uploads/:filename', authMiddleware, async (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(uploadDir, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Fájl nem található.' });
    }

    try {
        const [rows] = await db.query(`
            SELECT i.id FROM items i
            JOIN boxes b ON i.box_id = b.id
            WHERE (i.photo_url = ? OR i.photo_url = ?) AND b.user_id = ?
        `, [photoApiPath(filename), `/uploads/${filename}`, req.user.id]);

        if (rows.length === 0) {
            return res.status(403).json({ error: 'Nincs hozzáférés ehhez a fájlhoz.' });
        }

        res.sendFile(filePath);
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a fájl lekérésekor.' });
    }
});

// --- DOBOZOK ---

app.get('/api/boxes', authMiddleware, async (req, res) => {
    try {
        const [boxes] = await db.query(`
            SELECT b.*, COUNT(i.id) AS total_items, COALESCE(SUM(i.quantity), 0) AS total_quantity
            FROM boxes b
            LEFT JOIN items i ON b.id = i.box_id
            WHERE b.user_id = ?
            GROUP BY b.id
            ORDER BY b.created_at DESC
        `, [req.user.id]);
        res.json(boxes);
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a dobozok lekérésekor.' });
    }
});

app.get('/api/boxes/by-code/:code', authMiddleware, async (req, res) => {
    try {
        const [boxes] = await db.query(
            'SELECT * FROM boxes WHERE code = ? AND user_id = ?',
            [req.params.code, req.user.id]
        );
        if (boxes.length === 0) return res.status(404).json({ error: 'A doboz nem található.' });

        const [items] = await db.query('SELECT * FROM items WHERE box_id = ? ORDER BY id DESC', [boxes[0].id]);
        res.json({ box: boxes[0], items });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a doboz lekérésekor.' });
    }
});

app.post('/api/boxes', authMiddleware, async (req, res) => {
    const nameResult = validateRequiredText(req.body.name, 'A doboz neve');
    if (nameResult.error) return res.status(400).json({ error: nameResult.error });

    const location = optionalText(req.body.location, 200);
    if (location && location.error) return res.status(400).json({ error: location.error });

    const description = optionalText(req.body.description, 1000);
    if (description && description.error) return res.status(400).json({ error: description.error });

    let finalCode = req.body.code && req.body.code.trim() ? req.body.code.trim() : `BOX-${Date.now()}`;
    if (finalCode.length > 100) return res.status(400).json({ error: 'A doboz kód legfeljebb 100 karakter lehet.' });

    try {
        const [result] = await db.query(
            'INSERT INTO boxes (user_id, code, name, location, description) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, finalCode, nameResult.value, location || null, description || null]
        );
        res.json({ success: true, id: result.insertId, code: finalCode });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Ilyen kódú dobozod már van!' });
        res.status(500).json({ error: 'Szerverhiba a doboz létrehozásakor.' });
    }
});

app.put('/api/boxes/:id', authMiddleware, async (req, res) => {
    const nameResult = validateRequiredText(req.body.name, 'A doboz neve');
    if (nameResult.error) return res.status(400).json({ error: nameResult.error });

    const location = optionalText(req.body.location, 200);
    if (location && location.error) return res.status(400).json({ error: location.error });

    const description = optionalText(req.body.description, 1000);
    if (description && description.error) return res.status(400).json({ error: description.error });

    try {
        const [result] = await db.query(
            'UPDATE boxes SET name = ?, location = ?, description = ? WHERE id = ? AND user_id = ?',
            [nameResult.value, location || null, description || null, req.params.id, req.user.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'A doboz nem található vagy nincs jogosultságod.' });
        }

        res.json({ success: true });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a doboz módosításakor.' });
    }
});

app.delete('/api/boxes/:id', authMiddleware, async (req, res) => {
    try {
        const [boxes] = await db.query(
            'SELECT id FROM boxes WHERE id = ? AND user_id = ?',
            [req.params.id, req.user.id]
        );
        if (boxes.length === 0) {
            return res.status(404).json({ error: 'A doboz nem található vagy nincs jogosultságod.' });
        }

        const [items] = await db.query('SELECT photo_url FROM items WHERE box_id = ?', [req.params.id]);
        items.forEach(item => deletePhotoFile(item.photo_url));

        await db.query('DELETE FROM items WHERE box_id = ?', [req.params.id]);
        await db.query('DELETE FROM boxes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);

        res.json({ success: true });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a doboz törlésekor.' });
    }
});

// --- TÁRGYAK ---

app.post('/api/items', authMiddleware, upload.single('photo'), handleUploadError, async (req, res) => {
    const nameResult = validateRequiredText(req.body.name, 'A tárgy neve');
    if (nameResult.error) return res.status(400).json({ error: nameResult.error });

    const category = optionalText(req.body.category, 100);
    if (category && category.error) return res.status(400).json({ error: category.error });

    const itemCondition = optionalText(req.body.item_condition, 100);
    if (itemCondition && itemCondition.error) return res.status(400).json({ error: itemCondition.error });

    const description = optionalText(req.body.description, 1000);
    if (description && description.error) return res.status(400).json({ error: description.error });

    const quantity = Math.max(0, parseInt(req.body.quantity, 10) || 1);
    let photo_url = null;

    try {
        const [boxes] = await db.query('SELECT id FROM boxes WHERE id = ? AND user_id = ?', [req.body.box_id, req.user.id]);
        if (boxes.length === 0) {
            return res.status(403).json({ error: 'Nincs jogosultságod ehhez a dobozhoz.' });
        }

        if (req.file) {
            try {
                photo_url = await resizeAndSavePhoto(req.file);
            } catch (sharpErr) {
                console.error('Képfeldolgozási hiba:', sharpErr);
                return res.status(400).json({ error: 'Hiba a kép feldolgozása közben.' });
            }
        }

        const [result] = await db.query(
            `INSERT INTO items (box_id, name, quantity, category, item_condition, description, photo_url)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.body.box_id, nameResult.value, quantity, category || null, itemCondition || null, description || null, photo_url]
        );
        res.json({ success: true, id: result.insertId });
    } catch (_err) {
        if (photo_url) deletePhotoFile(photo_url);
        res.status(500).json({ error: 'Szerverhiba a tárgy létrehozásakor.' });
    }
});

app.put('/api/items/:id', authMiddleware, upload.single('photo'), handleUploadError, async (req, res) => {
    const nameResult = validateRequiredText(req.body.name, 'A tárgy neve');
    if (nameResult.error) return res.status(400).json({ error: nameResult.error });

    const category = optionalText(req.body.category, 100);
    if (category && category.error) return res.status(400).json({ error: category.error });

    const itemCondition = optionalText(req.body.item_condition, 100);
    if (itemCondition && itemCondition.error) return res.status(400).json({ error: itemCondition.error });

    const description = optionalText(req.body.description, 1000);
    if (description && description.error) return res.status(400).json({ error: description.error });

    const quantity = Math.max(0, parseInt(req.body.quantity, 10) || 1);
    let newPhotoUrl = null;

    try {
        const [items] = await db.query(`
            SELECT i.* FROM items i
            JOIN boxes b ON i.box_id = b.id
            WHERE i.id = ? AND b.user_id = ?
        `, [req.params.id, req.user.id]);

        if (items.length === 0) {
            return res.status(403).json({ error: 'Tárgy nem található vagy nincs jogosultság.' });
        }

        if (req.file) {
            try {
                newPhotoUrl = await resizeAndSavePhoto(req.file);
            } catch (sharpErr) {
                console.error('Képfeldolgozási hiba:', sharpErr);
                return res.status(400).json({ error: 'Hiba a kép feldolgozása közben.' });
            }
        }

        if (newPhotoUrl) {
            deletePhotoFile(items[0].photo_url);
            await db.query(`
                UPDATE items SET name = ?, quantity = ?, category = ?, item_condition = ?, description = ?, photo_url = ?
                WHERE id = ?
            `, [nameResult.value, quantity, category || null, itemCondition || null, description || null, newPhotoUrl, req.params.id]);
        } else {
            await db.query(`
                UPDATE items SET name = ?, quantity = ?, category = ?, item_condition = ?, description = ?
                WHERE id = ?
            `, [nameResult.value, quantity, category || null, itemCondition || null, description || null, req.params.id]);
        }

        res.json({ success: true });
    } catch (_err) {
        if (newPhotoUrl) deletePhotoFile(newPhotoUrl);
        res.status(500).json({ error: 'Szerverhiba a tárgy módosításakor.' });
    }
});

app.delete('/api/items/:id', authMiddleware, async (req, res) => {
    try {
        const [items] = await db.query(`
            SELECT i.* FROM items i
            JOIN boxes b ON i.box_id = b.id
            WHERE i.id = ? AND b.user_id = ?
        `, [req.params.id, req.user.id]);

        if (items.length === 0) {
            return res.status(404).json({ error: 'Tárgy nem található vagy nincs jogosultság.' });
        }

        deletePhotoFile(items[0].photo_url);
        await db.query('DELETE FROM items WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a tárgy törlésekor.' });
    }
});

app.patch('/api/items/:id/quantity', authMiddleware, async (req, res) => {
    const change = parseInt(req.body.change, 10);
    if (Number.isNaN(change)) {
        return res.status(400).json({ error: 'Érvénytelen mennyiség módosítás.' });
    }

    try {
        const [result] = await db.query(`
            UPDATE items i
            JOIN boxes b ON i.box_id = b.id
            SET i.quantity = GREATEST(0, i.quantity + ?)
            WHERE i.id = ? AND b.user_id = ?
        `, [change, req.params.id, req.user.id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Tárgy nem található vagy nincs jogosultság.' });
        }

        res.json({ success: true });
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a mennyiség módosításakor.' });
    }
});

app.get('/api/search', authMiddleware, async (req, res) => {
    const query = (req.query.q || '').trim();
    if (query.length < 2) return res.json([]);

    const q = `%${query.slice(0, 100)}%`;
    try {
        const [items] = await db.query(
            `SELECT i.*, b.name AS box_name, b.code AS box_code, b.location AS box_location
             FROM items i
             JOIN boxes b ON i.box_id = b.id
             WHERE b.user_id = ? AND (i.name LIKE ? OR i.description LIKE ? OR i.category LIKE ?)`,
            [req.user.id, q, q, q]
        );
        res.json(items);
    } catch (_err) {
        res.status(500).json({ error: 'Szerverhiba a keresés során.' });
    }
});

app.use((err, _req, res, next) => {
    if (err.message === 'CORS nem engedélyezett erről az origin-ről.') {
        return res.status(403).json({ error: err.message });
    }
    next(err);
});

app.listen(PORT, '0.0.0.0', () => console.log(`Szerver fut a ${PORT}-es porton!`));
