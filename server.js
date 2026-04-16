require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const jwt       = require("jsonwebtoken");
const bcrypt    = require("bcryptjs");
const { Pool }  = require("pg");
const passport  = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session   = require("express-session");
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const rawFrontendUrl = process.env.FRONTEND_URL || "http://localhost:5173";
const frontendUrl = rawFrontendUrl.endsWith('/') ? rawFrontendUrl.slice(0, -1) : rawFrontendUrl;
const app = express();

// --- CONFIGURATION ---
app.use(cors({ 
    origin: frontendUrl, 
    credentials: true 
}));
app.use(express.json());
app.get("/", (req, res) => {
  res.json({ status: "✅ DAGOAUTO API en ligne" });
});
app.use(session({ 
    secret: process.env.JWT_SECRET, 
    resave: false, 
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === "production" }
}));

const db = new Pool({ connectionString: process.env.DATABASE_URL });
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: { 
      accessKeyId: process.env.AWS_ACCESS_KEY_ID, 
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY 
  }
});

// --- INITIALISATION COMPLÈTE DE LA BASE DE DONNÉES ---
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value JSONB);
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, 
      password_hash TEXT, provider TEXT DEFAULT 'email', google_id TEXT, 
      avatar TEXT, is_banned BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS admins (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ecu_files (
      id SERIAL PRIMARY KEY, brand TEXT NOT NULL, model TEXT NOT NULL, engine TEXT NOT NULL, 
      fuel TEXT, calc_type TEXT NOT NULL, ecu_ref TEXT NOT NULL, s3_key TEXT NOT NULL, 
      price NUMERIC DEFAULT 0, tags TEXT[] DEFAULT '{}', active BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS downloads (
      id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), 
      file_id INTEGER REFERENCES ecu_files(id), created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log("✅ Base de données initialisée avec succès");
}

// --- MIDDLEWARES DE SÉCURITÉ ---
const requireAdmin = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Accès Admin requis" });
  try {
    const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    if (!decoded.isAdmin) throw new Error();
    req.admin = decoded; 
    next();
  } catch { res.status(403).json({ error: "Token Admin Invalide ou Expiré" }); }
};

// --- AUTH : GOOGLE OAUTH STRATEGY ---
passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  `${process.env.BACKEND_URL}/api/auth/google/callback`,
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value;
      let { rows } = await db.query("SELECT * FROM users WHERE google_id=$1 OR email=$2", [profile.id, email]);
      if (!rows.length) {
        const ins = await db.query(
          "INSERT INTO users(name,email,provider,google_id,avatar) VALUES($1,$2,'google',$3,$4) RETURNING *",
          [profile.displayName, email, profile.id, profile.photos[0]?.value]
        );
        rows = ins.rows;
      }
      done(null, rows[0]);
    } catch (e) { done(e); }
}));

passport.serializeUser((u, d) => d(null, u.id));
passport.deserializeUser(async (id, d) => {
    const { rows } = await db.query("SELECT * FROM users WHERE id=$1", [id]);
    d(null, rows[0]);
});

// --- ROUTES AUTHENTIFICATION ---
app.get("/api/auth/google", passport.authenticate("google", { 
  scope: ["profile", "email"],
  prompt: "select_account consent", // <--- AJOUTEZ CECI
  accessType: "offline"
}));
app.get("/api/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, isAdmin: false }, process.env.JWT_SECRET);
    res.redirect(`${process.env.FRONTEND_URL}/?token=${token}`);
});

app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    const { rows } = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!rows.length || !bcrypt.compareSync(password, rows[0].password_hash)) return res.status(401).json({ error: "Identifiants incorrects" });
    const token = jwt.sign({ id: rows[0].id, isAdmin: false }, process.env.JWT_SECRET);
    res.json({ token, user: { id: rows[0].id, name: rows[0].name, email: rows[0].email } });
});

app.post("/api/admin/login", async (req, res) => {
    const { email, password } = req.body;
    const { rows } = await db.query("SELECT * FROM admins WHERE email=$1", [email]);
    if (!rows.length || !bcrypt.compareSync(password, rows[0].password_hash)) return res.status(401).json({ error: "Admin non trouvé" });
    const token = jwt.sign({ id: rows[0].id, email, isAdmin: true }, process.env.JWT_SECRET);
    res.json({ token });
});

// --- ROUTES GESTION ADMIN (DYNAMIQUE) ---
app.get("/api/config", async (req, res) => {
    const { rows } = await db.query("SELECT * FROM config");
    res.json(rows.reduce((acc, r) => ({ ...acc, [r.key]: r.value }), { brands: {}, ecuTypes: [] }));
});

app.post("/api/admin/config", requireAdmin, async (req, res) => {
    const { key, value } = req.body;
    await db.query("INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", [key, JSON.stringify(value)]);
    res.json({ ok: true });
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
    const { rows } = await db.query(`
      SELECT u.*, (SELECT COUNT(*) FROM downloads d WHERE d.user_id = u.id) as total_files 
      FROM users u ORDER BY u.created_at DESC
    `);
    res.json(rows);
});

app.post("/api/admin/users/:id/toggle-ban", requireAdmin, async (req, res) => {
    await db.query("UPDATE users SET is_banned = NOT is_banned WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
});

// --- ROUTES FICHIERS & S3 ---
app.post("/api/admin/get-upload-url", requireAdmin, async (req, res) => {
    const { fileName, fileType } = req.body;
    const s3Key = `catalog/${Date.now()}_${fileName}`;
    const uploadUrl = await getSignedUrl(s3, new PutObjectCommand({ 
        Bucket: process.env.S3_BUCKET_NAME, Key: s3Key, ContentType: fileType 
    }), { expiresIn: 3600 });
    res.json({ uploadUrl, s3Key });
});

app.post("/api/admin/files", requireAdmin, async (req, res) => {
    const { brand, model, engine, fuel, calc_type, ecu_ref, s3_key, price, tags } = req.body;
    const { rows } = await db.query(
      "INSERT INTO ecu_files (brand,model,engine,fuel,calc_type,ecu_ref,s3_key,price,tags) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *",
      [brand, model, engine, fuel, calc_type, ecu_ref, s3_key, price, tags]
    );
    res.json(rows[0]);
});

app.get("/api/files", async (req, res) => {
    const { brand, model } = req.query;
    let q = "SELECT * FROM ecu_files WHERE active=true";
    const p = [];
    if (brand) { p.push(brand); q += ` AND brand=$${p.length}`; }
    if (model) { p.push(model); q += ` AND model=$${p.length}`; }
    const { rows } = await db.query(q + " ORDER BY created_at DESC", p);
    res.json(rows);
});

// --- TÉLÉCHARGEMENT ---
app.post("/api/download", async (req, res) => {
    const { fileId, userId } = req.body;
    if (userId) {
        const user = await db.query("SELECT is_banned FROM users WHERE id=$1", [userId]);
        if (user.rows[0]?.is_banned) return res.status(403).json({ error: "Accès bloqué" });
        await db.query("INSERT INTO downloads(user_id, file_id) VALUES($1,$2)", [userId, fileId]);
    }
    const file = await db.query("SELECT s3_key FROM ecu_files WHERE id=$1", [fileId]);
    const url = await getSignedUrl(s3, new GetObjectCommand({ 
        Bucket: process.env.S3_BUCKET_NAME, Key: file.rows[0].s3_key 
    }), { expiresIn: 600 });
    res.json({ downloadUrl: url });
});

// --- STATS ---
app.get("/api/admin/stats", requireAdmin, async (req, res) => {
    const u = await db.query("SELECT COUNT(*) FROM users");
    const d = await db.query("SELECT COUNT(*) FROM downloads");
    res.json({ users: parseInt(u.rows[0].count), downloads: parseInt(d.rows[0].count) });
});

// --- START ---
const PORT = process.env.PORT || 3001;
initDB().then(() => {
    app.listen(PORT, () => console.log(`🚀 DAGOAUTO en ligne sur le port ${PORT}`));
});