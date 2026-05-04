require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
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

app.set('trust proxy', 1);

// ── Database (PostgreSQL) ──
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
  // Добавяме images колона ако не съществува (за стари инсталации)
  await pool.query(`
    ALTER TABLE posts ADD COLUMN IF NOT EXISTS images TEXT[];
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS "session" (
      "sid" varchar NOT NULL COLLATE "default",
      "sess" json NOT NULL,
      "expire" timestamp(6) NOT NULL,
      CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");`);

  const u = await pool.query('SELECT COUNT(*)::int AS c FROM users');
  if (u.rows[0].c === 0) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASS, 10);
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
    blogName: 'Моят блог',
    tagline: 'Истории от живота',
    author: 'Авторът',
    description: 'Лични истории, рецепти, пътувания и всичко, което ни прави по-живи.'
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
  cloudinary: cloudinary,
  params: {
    folder: 'blog-irina',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp', 'gif'],
  },
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

// ── Middleware ──
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
app.use(cors({ origin: FRONTEND_URL, credentials: true }));

const isProd = process.env.NODE_ENV === 'production';
app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'my-super-secret-blog-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: isProd ? 'none' : 'lax',
    secure: isProd
  }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

const q = (text, params) => pool.query(text, params);

// ── Auth routes ──
app.get('/api/me', (req, res) => {
  if (req.session.userId) res.json({ loggedIn: true, username: req.session.username });
  else res.json({ loggedIn: false });
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Попълни всички полета.' });
    const { rows } = await q('SELECT * FROM users WHERE username = $1', [username]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Грешно потребителско име или парола.' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ ok: true, username: user.username });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.post('/api/change-credentials', requireAuth, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username) return res.status(400).json({ error: 'Потребителското име е задължително.' });
    if (password) {
      const hash = bcrypt.hashSync(password, 10);
      await q('UPDATE users SET username = $1, password = $2 WHERE id = $3',
        [username, hash, req.session.userId]);
    } else {
      await q('UPDATE users SET username = $1 WHERE id = $2', [username, req.session.userId]);
    }
    req.session.username = username;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Posts routes ──
app.get('/api/posts', async (req, res) => {
  try {
    const { category } = req.query;
    const sql = category
      ? 'SELECT * FROM posts WHERE category = $1 ORDER BY created_at DESC'
      : 'SELECT * FROM posts ORDER BY created_at DESC';
    const { rows } = await q(sql, category ? [category] : []);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const { rows } = await q('SELECT * FROM posts WHERE id = $1', [req.params.id]);
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
      `INSERT INTO posts (title, excerpt, content, category, image, images, date)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [title, excerpt || '', content, category, mainImage,
       imagesArr.length > 0 ? imagesArr : null,
       date || new Date().toISOString().slice(0, 10)]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const { title, excerpt, content, category, image, images, date } = req.body;
    const exists = await q('SELECT id FROM posts WHERE id = $1', [req.params.id]);
    if (!exists.rows[0]) return res.status(404).json({ error: 'Статията не е намерена.' });
    const imagesArr = Array.isArray(images) ? images : (images ? [images] : []);
    const mainImage = image || (imagesArr.length > 0 ? imagesArr[0] : null);
    const { rows } = await q(
      `UPDATE posts SET title=$1, excerpt=$2, content=$3, category=$4, image=$5, images=$6, date=$7
       WHERE id=$8 RETURNING *`,
      [title, excerpt || '', content, category, mainImage,
       imagesArr.length > 0 ? imagesArr : null,
       date, req.params.id]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await q('SELECT * FROM posts WHERE id = $1', [req.params.id]);
    const post = rows[0];
    if (!post) return res.status(404).json({ error: 'Статията не е намерена.' });
    // Изтрий всички снимки от Cloudinary
    const allImages = post.images || (post.image ? [post.image] : []);
    for (const imgUrl of allImages) {
      if (imgUrl && imgUrl.includes('cloudinary.com')) {
        try {
          const parts = imgUrl.split('/');
          const filenameWithExt = parts[parts.length - 1];
          const publicId = `blog-irina/${filenameWithExt.split('.')[0]}`;
          await cloudinary.uploader.destroy(publicId);
        } catch (_) {}
      }
    }
    await q('DELETE FROM posts WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Categories routes ──
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
    const nextOrder = max.rows[0].m + 1;
    try {
      await q('INSERT INTO categories (name, sort_order) VALUES ($1, $2)', [name.trim(), nextOrder]);
      res.json({ ok: true });
    } catch (_) {
      res.status(400).json({ error: 'Тази категория вече съществува.' });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/categories/:name', requireAuth, async (req, res) => {
  try {
    await q('DELETE FROM categories WHERE name = $1', [decodeURIComponent(req.params.name)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Settings routes ──
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
          `INSERT INTO settings (key, value) VALUES ($1, $2)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
          [key, req.body[key]]
        );
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Upload route ──
app.post('/api/upload', requireAuth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Няма файл.' });
  res.json({ url: req.file.path });
});

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ── Start ──
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n✦ Blog API running at http://localhost:${PORT}`);
      console.log(`  CORS allowed origin: ${FRONTEND_URL}`);
    });
  })
  .catch(err => {
    console.error('DB init failed:', err);
    process.exit(1);
  });
