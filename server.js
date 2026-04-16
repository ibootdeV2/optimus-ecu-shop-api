require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

// CORS CONFIG (Nettoyage de l'URL pour éviter les bugs de slash)
const frontendUrl = (process.env.FRONTEND_URL || "http://localhost:5173").replace(/\/$/, "");
app.use(cors({ origin: frontendUrl, credentials: true }));
app.use(express.json());

const db = new Pool({ connectionString: process.env.DATABASE_URL });

// --- ROUTES ---
app.get("/", (req, res) => res.json({ status: "API Online" }));

// Login Admin avec Debug Logs
app.post("/api/admin/login", async (req, res) => {
    const { email, password } = req.body;
    console.log("Tentative login admin pour:", email);
    try {
        const { rows } = await db.query("SELECT * FROM admins WHERE LOWER(email) = LOWER($1)", [email]);
        if (!rows.length) return res.status(401).json({ error: "Admin non trouvé dans la base" });
        
        const valid = bcrypt.compareSync(password, rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: "Mot de passe incorrect" });

        const token = jwt.sign({ id: rows[0].id, email, isAdmin: true }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Récupérer la config (Marques)
app.get("/api/config", async (req, res) => {
    const { rows } = await db.query("SELECT * FROM config");
    const cfg = rows.reduce((acc, r) => ({ ...acc, [r.key]: r.value }), { brands: {} });
    res.json(cfg);
});

// Récupérer tous les fichiers
app.get("/api/files", async (req, res) => {
    const { rows } = await db.query("SELECT * FROM ecu_files WHERE active=true ORDER BY created_at DESC");
    res.json(rows);
});

// Récupérer les utilisateurs (Admin)
app.get("/api/admin/users", async (req, res) => {
    const { rows } = await db.query(`
        SELECT u.id, u.name, u.email, u.created_at, 
        (SELECT COUNT(*) FROM downloads d WHERE d.user_id = u.id) as total_files
        FROM users u ORDER BY u.created_at DESC
    `);
    res.json(rows);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));