const express = require("express");
const https = require("https");
const rateLimit = require("express-rate-limit");
const winston = require("winston");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const csurf = require("csurf");
const session = require("express-session");
const cookieParser = require("cookie-parser");

const app = express();

/* 🔒 LOGGER */
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

/* 🔒 SECURITY */
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  })
);
app.disable("x-powered-by");

/* 🔧 MIDDLEWARE */
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* 🔐 SESSION */
app.use(session({
    secret: "kali-secret-123",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 600000 }
}));

/* 🔒 CSRF */
app.use(csrf({
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  }
}));

const loginLimiter = rateLimit({
    windowMs: 15* 60 * 1000,
    max: 4,
    handler: (req, res) => {
        return res.status(429).send(`
            <h2>❌ Too many attempts</h2>
            <p>You are temporarily blocked</p>
            <a href="/">Go Back</a>
        `);
    }
});
/* 🎨 STYLE */
const style = `
<style>
body { font-family: Arial; background:#2c3e50; margin:0; }
.auth-page { display:flex; justify-content:center; align-items:center; height:100vh; }
.container { background:white; padding:30px; border-radius:8px; width:350px; }
input,button { width:100%; padding:10px; margin:8px 0; }
button { background:#3498db; color:white; border:none; }
.navbar { background:#1a252f; color:white; padding:15px; }
</style>
`;

/* ✅ HELPERS */
function isValidUsername(username) {
    return /^[a-zA-Z0-9]{3,15}$/.test(username);
}
function isValidPassword(password) {
    return password && password.length >= 6;
}

/* 💾 DATABASE */
let users = [];

/* ================= ROUTES ================= */

/* HOME */
app.get("/", csrfProtection, (req, res) => {
    res.send(`
    <html>
    <head><title>Secure App</title>${style}</head>
    <body class="auth-page">
        <div class="container">
            <h2>Register</h2>
            <form method="POST" action="/register">
                <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                <input name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Register</button>
            </form>

            <h2>Login</h2>
            <form method="POST" action="/login">
                <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                <input name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    `);
});

/* REGISTER */
app.post("/register", loginLimiter, csrfProtection, async (req, res) => {
    const { username = "", password = "" } = req.body;

    if (!isValidUsername(username) || !isValidPassword(password)) {
        return res.send("Invalid input <br><a href='/'>Back</a>");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });

    logger.info(`New user registered: ${username}`);

    res.redirect("/");
});

/* LOGIN */
app.post("/login", loginLimiter, csrfProtection, async (req, res) => {
    const { username = "", password = "" } = req.body;

    const user = users.find(u => u.username === username);

    if (!user) {
        logger.warn(`Failed login attempt for: ${username}`);
        return res.send("Invalid credentials <br><a href='/'>Back</a>");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
        logger.info(`User logged in: ${username}`);
        req.session.user = username;
        res.redirect("/dashboard");
    } else {
        logger.warn(`Failed login attempt for: ${username}`);
        res.send("Invalid credentials <br><a href='/'>Back</a>");
    }
});

/* DASHBOARD */
app.get("/dashboard", (req, res) => {
    if (!req.session.user) return res.redirect("/");

    res.send(`
    <html>
    <head><title>Dashboard</title>${style}</head>
    <body>
        <div class="navbar">Welcome ${req.session.user}</div>
        <div class="container">
            <h2>Dashboard</h2>
            <p>Login successful ✅</p>
            <a href="/logout">Logout</a>
        </div>
    </body>
    </html>
    `);
});

/* 🔒 API USERS */
app.get("/api/users", (req, res) => {

    if (!req.session.user) {
        logger.warn("Unauthorized API access attempt");
        return res.status(403).json({ message: "Access Denied" });
    }

    logger.info(`API accessed by: ${req.session.user}`);

    res.json(users.map(u => ({
        username: u.username
    })));
});

/* LOGOUT */
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

/* ❗ CSRF ERROR HANDLER */
app.use((err, req, res, next) => {
    if (err.code === "EBADCSRFTOKEN") {
        return res.send("❌ Invalid CSRF token. Please refresh.");
    }
    next(err);
});


const fs = require("fs");

const httpsOptions = {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem")
};

https.createServer(httpsOptions, app).listen(8443, () => {
    console.log("🔒 HTTPS Server running on https://localhost:8443");
});
