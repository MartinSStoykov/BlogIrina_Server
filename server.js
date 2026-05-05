require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');

// ── Cloudinary ──
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'blog-jwt-secret-change-this';

if (!process.env.DATABASE_URL) {
  console.warn('⚠ DATABASE_URL не е зададена.');
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : (process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false)
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      excerpt TEXT,
      content TEXT NOT NULL,
      category TEXT NOT NULL,
      image TEXT,
      images TEXT[],
      date TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS images TEXT[];`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      content TEXT NOT NULL,
      approved BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS categories (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      sort_order INTEGER DEFAULT 0
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);

  const u = await pool.query('SELECT COUNT(*)::int AS c FROM users');
  if (u.rows[0].c === 0) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASS || 'admin123', 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [
      process.env.ADMIN_USER || 'admin', hash
    ]);
  }

  const c = await pool.query('SELECT COUNT(*)::int AS c FROM categories');
  if (c.rows[0].c === 0) {
    const cats = ['Живот', 'Рецепти', 'Пътувания', 'Любими'];
    for (let i = 0; i < cats.length; i++) {
      await pool.query(
        'INSERT INTO categories (name, sort_order) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING',
        [cats[i], i]
      );
    }
  }

  const defaultSettings = {
    blogName: 'Моят блог', tagline: 'Истории от живота',
    author: 'Авторът', description: 'Лични истории, рецепти, пътувания и всичко, което ни прави по-живи.'
  };
  for (const [key, value] of Object.entries(defaultSettings)) {
    await pool.query(
      'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING',
      [key, value]
    );
  }
}

// ── Upload (Cloudinary) ──
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: { folder: 'blog-irina', allowed_formats: ['jpg', 'jpeg', 'png', 'webp', 'gif'] },
});
const upload = multer({
  storage: cloudinaryStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
    if (allowed.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
    else cb(new Error('Само изображения са позволени.'));
  }
});

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
app.use(cors({
  origin: FRONTEND_URL,
  credentials: false  // JWT не се нуждае от credentials
}));

// ── JWT Auth middleware ──
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization']
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  const token = authHeader.split(' ')[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.userId = payload.userId
    req.username = payload.username
    next()
  } catch {
    res.status(401).json({ error: 'Невалиден или изтекъл токен.' })
  }
}

const q = (text, params) => pool.query(text, params);

// ── Auth routes ──
app.get('/api/me', (req, res) => {
  const authHeader = req.headers['authorization']
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.json({ loggedIn: false })
  }
  const token = authHeader.split(' ')[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    res.json({ loggedIn: true, username: payload.username })
  } catch {
    res.json({ loggedIn: false })
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Попълни всички полета.' });
    const { rows } = await q('SELECT * FROM users WHERE username = $1', [username]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Грешно потребителско име или парола.' });
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    )
    res.json({ ok: true, username: user.username, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', (req, res) => {
  // JWT logout е само на клиента (изтриване на токена)
  res.json({ ok: true });
});

app.post('/api/change-credentials', requireAuth, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username) return res.status(400).json({ error: 'Потребителското име е задължително.' });
    if (password) {
      const hash = bcrypt.hashSync(password, 10);
      await q('UPDATE users SET username=$1, password=$2 WHERE id=$3', [username, hash, req.userId]);
    } else {
      await q('UPDATE users SET username=$1 WHERE id=$2', [username, req.userId]);
    }
    // Върни нов токен с обновено username
    const token = jwt.sign({ userId: req.userId, username }, JWT_SECRET, { expiresIn: '7d' })
    res.json({ ok: true, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Posts ──
app.get('/api/posts', async (req, res) => {
  try {
    const { category } = req.query;
    const sql = category ? 'SELECT * FROM posts WHERE category=$1 ORDER BY created_at DESC' : 'SELECT * FROM posts ORDER BY created_at DESC';
    const { rows } = await q(sql, category ? [category] : []);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/posts/:id', async (req, res) => {
  try {
    const { rows } = await q('SELECT * FROM posts WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Статията не е намерена.' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/posts', requireAuth, async (req, res) => {
  try {
    const { title, excerpt, content, category, image, images, date } = req.body;
    if (!title || !content || !category)
      return res.status(400).json({ error: 'Заглавие, съдържание и категория са задължителни.' });
    const imagesArr = Array.isArray(images) ? images : (images ? [images] : []);
    const mainImage = image || (imagesArr.length > 0 ? imagesArr[0] : null);
    const { rows } = await q(
      `INSERT INTO posts (title, excerpt, content, category, image, images, date) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [title, excerpt||'', content, category, mainImage, imagesArr.length>0 ? imagesArr : null, date||new Date().toISOString().slice(0,10)]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const { title, excerpt, content, category, image, images, date } = req.body;
    const exists = await q('SELECT id FROM posts WHERE id=$1', [req.params.id]);
    if (!exists.rows[0]) return res.status(404).json({ error: 'Статията не е намерена.' });
    const imagesArr = Array.isArray(images) ? images : (images ? [images] : []);
    const mainImage = image || (imagesArr.length > 0 ? imagesArr[0] : null);
    const { rows } = await q(
      `UPDATE posts SET title=$1,excerpt=$2,content=$3,category=$4,image=$5,images=$6,date=$7 WHERE id=$8 RETURNING *`,
      [title, excerpt||'', content, category, mainImage, imagesArr.length>0 ? imagesArr : null, date, req.params.id]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await q('SELECT * FROM posts WHERE id=$1', [req.params.id]);
    const post = rows[0];
    if (!post) return res.status(404).json({ error: 'Статията не е намерена.' });
    const allImages = post.images || (post.image ? [post.image] : []);
    for (const imgUrl of allImages) {
      if (imgUrl && imgUrl.includes('cloudinary.com')) {
        try {
          const parts = imgUrl.split('/');
          const publicId = `blog-irina/${parts[parts.length-1].split('.')[0]}`;
          await cloudinary.uploader.destroy(publicId);
        } catch (_) {}
      }
    }
    await q('DELETE FROM posts WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Comments ──
app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const { rows } = await q(
      'SELECT id, name, content, created_at FROM comments WHERE post_id=$1 AND approved=TRUE ORDER BY created_at ASC',
      [req.params.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/posts/:id/comments', async (req, res) => {
  try {
    const { name, content } = req.body;
    if (!name || !content) return res.status(400).json({ error: 'Попълни ime и коментар.' });
    if (content.length > 1000) return res.status(400).json({ error: 'Коментарът е твърде дълъг.' });
    await q('INSERT INTO comments (post_id, name, content) VALUES ($1, $2, $3)', [req.params.id, name.trim(), content.trim()]);
    res.json({ ok: true, message: 'Коментарът ти е изпратен за одобрение.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/admin/comments', requireAuth, async (req, res) => {
  try {
    const { rows } = await q(`
      SELECT c.id, c.name, c.content, c.approved, c.created_at,
             p.title AS post_title, p.id AS post_id
      FROM comments c JOIN posts p ON p.id = c.post_id
      ORDER BY c.approved ASC, c.created_at DESC
    `);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/admin/comments/:id/approve', requireAuth, async (req, res) => {
  try {
    await q('UPDATE comments SET approved=TRUE WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/admin/comments/:id', requireAuth, async (req, res) => {
  try {
    await q('DELETE FROM comments WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Categories ──
app.get('/api/categories', async (req, res) => {
  try {
    const { rows } = await q('SELECT name FROM categories ORDER BY sort_order, name');
    res.json(rows.map(r => r.name));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/categories', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Името е задължително.' });
    const max = await q('SELECT COALESCE(MAX(sort_order), 0) AS m FROM categories');
    try {
      await q('INSERT INTO categories (name, sort_order) VALUES ($1, $2)', [name.trim(), max.rows[0].m + 1]);
      res.json({ ok: true });
    } catch (_) { res.status(400).json({ error: 'Тази категория вече съществува.' }); }
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/categories/:name', requireAuth, async (req, res) => {
  try {
    await q('DELETE FROM categories WHERE name=$1', [decodeURIComponent(req.params.name)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Settings ──
app.get('/api/settings', async (req, res) => {
  try {
    const { rows } = await q('SELECT key, value FROM settings');
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    res.json(settings);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/settings', requireAuth, async (req, res) => {
  try {
    const allowed = ['blogName', 'tagline', 'author', 'description'];
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        await pool.query(
          `INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`,
          [key, req.body[key]]
        );
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Upload ──
app.post('/api/upload', requireAuth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Няма файл.' });
  res.json({ url: req.file.path });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n✦ Blog API running at http://localhost:${PORT}`);
      console.log(`  CORS allowed origin: ${FRONTEND_URL}`);
    });
  })
  .catch(err => { console.error('DB init failed:', err); process.exit(1); });
