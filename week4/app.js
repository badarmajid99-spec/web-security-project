const express = require("express");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const cors = require("cors");
const https = require("https");
const http = require("http");
const fs = require("fs");
const rateLimit = require("express-rate-limit");
const winston = require("winston");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const csurf = require("csurf");
const session = require("express-session");
const cookieParser = require("cookie-parser");

const app = express();

/* ================= DATABASE ================= */
let db;

async function initDB() {
    db = await open({
        filename: "./database.db",
        driver: sqlite3.Database
    });

    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    `);

    console.log("✅ SQLite Database Connected");
}

/* ================= LOGGER ================= */
const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.File({ filename: "security.log" })
    ]
});

/* ================= SECURITY ================= */
app.use(helmet());
app.disable("x-powered-by");

app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
});

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: true, credentials: true }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* ================= SESSION ================= */
app.use(session({
    secret: "kali-secret-123",
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 600000,
        httpOnly: true,
        secure: false,
        sameSite: "lax"
    }
}));

/* ================= CSRF ================= */
const csrfProtection = csurf({ cookie: true });

/* ================= RATE LIMIT ================= */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 4,
    handler: (req, res) => {
        return res.status(429).send("Too many attempts");
    }
});

/* ================= STYLE ================= */
const style = `
<style>
body { font-family: Arial; background: #2c3e50; margin: 0; }
.container { background: white; padding: 20px; margin: 50px auto; width: 300px; }
input, button { width: 100%; padding: 10px; margin: 5px 0; }
button { background: #3498db; color: white; border: none; }
.navbar { background: #1a252f; color: white; padding: 10px; }
</style>
`;

/* ================= HELPERS ================= */
function isValidUsername(username) {
    return /^[a-zA-Z0-9]{3,15}$/.test(username);
}

function isValidPassword(password) {
    return password && password.length >= 6;
}

/* ================= AUTH ================= */
function apiKeyAuth(req, res, next) {
    const apiKey = req.headers["x-api-key"];

    if (apiKey !== "secure-api-key-123") {
        return res.status(401).json({ message: "Invalid API Key" });
    }

    next();
}

/* ================= HOME ================= */
app.get("/", csrfProtection, (req, res) => {
    res.send(`
    <html>
    <head>${style}</head>
    <body>
        <div class="container">

            <h2>Register</h2>
            <form method="POST" action="/register">
                <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                <input name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <button>Register</button>
            </form>

            <h2>Login</h2>
            <form method="POST" action="/login">
                <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                <input name="username" placeholder="Username">
                <input type="password" name="password">
                <button>Login</button>
            </form>

        </div>
    </body>
    </html>
    `);
});

/* ================= REGISTER (DB FIXED) ================= */
app.post("/register", loginLimiter, csrfProtection, async (req, res) => {

    const { username = "", password = "" } = req.body;

    if (!isValidUsername(username) || !isValidPassword(password)) {
        return res.send("Invalid input");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.run(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [username, hashedPassword]
        );

        logger.info(`User registered: ${username}`);
        res.redirect("/");

    } catch (err) {
        res.send("User already exists or DB error");
    }
});

/* ================= LOGIN (DB FIXED) ================= */
app.post("/login", loginLimiter, csrfProtection, async (req, res) => {

    const { username = "", password = "" } = req.body;

    const user = await db.get(
    "SELECT * FROM users WHERE username = ?",
    [username]
);
    if (!user) return res.send("Invalid credentials");

    const match = await bcrypt.compare(password, user.password);

    if (match) {
        req.session.user = username;
        return res.redirect("/dashboard");
    }

    res.send("Invalid credentials");
});

/* ================= DASHBOARD ================= */
app.get("/dashboard", (req, res) => {

    if (!req.session.user) return res.redirect("/");

    res.send(`
    <html>
    <head>${style}</head>
    <body>
        <div class="navbar">Welcome ${req.session.user}</div>
        <div class="container">
            <h2>Dashboard</h2>
            <a href="/logout">Logout</a>
        </div>
    </body>
    </html>
    `);
});

/* ================= API ================= */
app.get("/api/users", apiKeyAuth, async (req, res) => {

    if (!req.session.user) {
        return res.status(403).json({ message: "Access denied" });
    }

    const users = await db.all("SELECT username FROM users");

    res.json(users);
});

/* ================= LOGOUT ================= */
app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
});

/* ================= SERVER ================= */
function startServer() {

    try {
        const options = {
            key: fs.readFileSync("key.pem"),
            cert: fs.readFileSync("cert.pem")
        };

        https.createServer(options, app).listen(8443, () => {
            console.log("🔒 HTTPS https://localhost:8443");
        });

    } catch (err) {
        http.createServer(app).listen(3000, () => {
            console.log("🌐 HTTP http://localhost:3000");
        });
    }
}

/* ================= INIT ================= */
initDB().then(startServer);
