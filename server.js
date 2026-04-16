require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const { S3Client, GetObjectCommand, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const app = express();

// --- CONFIGURATION CORS & JSON ---
const frontendUrl = (process.env.FRONTEND_URL || "http://localhost:5173").replace(/\/$/, "");
app.use(cors({ origin: frontendUrl, credentials: true }));
app.use(express.json());

// --- SESSION POUR PASSPORT ---
app.use(session({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === "production" }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- DATABASE & S3 ---
const db = new Pool({ connectionString: process.env.DATABASE_URL });
const s3 = new S3Client({
    region: process.env.AWS_REGION,
    credentials: { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY }
});

// --- PASSPORT GOOGLE STRATEGY ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/api/auth/google/callback`,
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const email = profile.emails[0].value;
        let { rows } = await db.query("SELECT * FROM users WHERE google_id=$1 OR email=$2", [profile.id, email]);
        if (!rows.length) {
            const ins = await db.query(
                "INSERT INTO users(name, email, provider, google_id, avatar) VALUES($1, $2, 'google', $3, $4) RETURNING *",
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

// --- MIDDLEWARES ---
const requireAdmin = (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Accès Admin requis" });
    try {
        const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
        if (!decoded.isAdmin) throw new Error();
        req.admin = decoded; next();
    } catch { res.status(403).json({ error: "Interdit" }); }
};

// --- ROUTES AUTHENTIFICATION ---

// Login/Register Classique
app.post("/api/auth/register", async (req, res) => {
    const { name, email, password } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    try {
        const { rows } = await db.query("INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email", [name, email, hash]);
        const token = jwt.sign({ id: rows[0].id, isAdmin: false }, process.env.JWT_SECRET);
        res.json({ token, user: rows[0] });
    } catch { res.status(400).json({ error: "Email déjà utilisé" }); }
});

app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    const { rows } = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    if (!rows.length || !bcrypt.compareSync(password, rows[0].password_hash)) return res.status(401).json({ error: "Identifiants incorrects" });
    const token = jwt.sign({ id: rows[0].id, isAdmin: false }, process.env.JWT_SECRET);
    res.json({ token, user: { id: rows[0].id, name: rows[0].name, email: rows[0].email } });
});

// Google Redirect
app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"], prompt: "select_account" }));

app.get("/api/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, isAdmin: false }, process.env.JWT_SECRET);
    res.redirect(`${frontendUrl}/?token=${token}`);
});

// Login Admin
app.post("/api/admin/login", async (req, res) => {
    const { email, password } = req.body;
    const { rows } = await db.query("SELECT * FROM admins WHERE LOWER(email) = LOWER($1)", [email]);
    if (!rows.length || !bcrypt.compareSync(password, rows[0].password_hash)) return res.status(401).json({ error: "Admin non trouvé ou mot de passe incorrect" });
    const token = jwt.sign({ id: rows[0].id, email, isAdmin: true }, process.env.JWT_SECRET);
    res.json({ token });
});

// --- GESTION DU CATALOGUE & CONFIG ---

app.get("/api/config", async (req, res) => {
    const { rows } = await db.query("SELECT * FROM config");
    res.json(rows.reduce((acc, r) => ({ ...acc, [r.key]: r.value }), { brands: {} }));
});

app.post("/api/admin/config", requireAdmin, async (req, res) => {
    const { key, value } = req.body;
    await db.query("INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", [key, JSON.stringify(value)]);
    res.json({ ok: true });
});

app.get("/api/files", async (req, res) => {
    const { rows } = await db.query("SELECT * FROM ecu_files WHERE active=true ORDER BY created_at DESC");
    res.json(rows);
});

// --- UTILISATEURS & STATS (ADMIN) ---

app.get("/api/admin/users", requireAdmin, async (req, res) => {
    const { rows } = await db.query(`
        SELECT u.id, u.name, u.email, u.created_at, 
        (SELECT COUNT(*) FROM downloads d WHERE d.user_id = u.id) as total_files
        FROM users u ORDER BY u.created_at DESC
    `);
    res.json(rows);
});

app.post("/api/admin/users/:id/toggle-ban", requireAdmin, async (req, res) => {
    await db.query("UPDATE users SET is_banned = NOT is_banned WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
});

// --- TÉLÉCHARGEMENT S3 ---

app.post("/api/download", async (req, res) => {
    const { fileId, userId } = req.body;
    if (userId) {
        const user = await db.query("SELECT is_banned FROM users WHERE id=$1", [userId]);
        if (user.rows[0]?.is_banned) return res.status(403).json({ error: "Accès bloqué" });
        await db.query("INSERT INTO downloads(user_id, file_id) VALUES($1,$2)", [userId, fileId]);
    }
    const file = await db.query("SELECT s3_key FROM ecu_files WHERE id=$1", [fileId]);
    if (!file.rows.length) return res.status(404).json({ error: "Fichier introuvable" });

    const url = await getSignedUrl(s3, new GetObjectCommand({ 
        Bucket: process.env.S3_BUCKET_NAME, 
        Key: file.rows[0].s3_key 
    }), { expiresIn: 600 });
    res.json({ downloadUrl: url });
});

// Root check
app.get("/", (req, res) => res.json({ status: "DAGOAUTO API Online" }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 DAGOAUTO Server running on port ${PORT}`));