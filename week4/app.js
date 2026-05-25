const express = require("express");
const https = require("https");
const fs = require("fs");
const rateLimit = require("express-rate-limit");
const winston = require("winston");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const csurf = require("csurf");
const session = require("express-session");
const cookieParser = require("cookie-parser");

const app = express();

/* ================= STATIC FILES ================= */
app.use(express.static("public"));

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

/* ================= SECURITY HEADERS ================= */
app.use(
    helmet({
        contentSecurityPolicy: {
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
        },

        xContentTypeOptions: true,

        referrerPolicy: {
            policy: "no-referrer"
        },

        permissionsPolicy: {
            features: {
                camera: [],
                microphone: [],
                geolocation: []
            }
        },

        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        }
    })
);

app.disable("x-powered-by");

/* ================= CACHE CONTROL ================= */
app.use((req, res, next) => {
    res.setHeader(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private"
    );

    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    next();
});

/* ================= MIDDLEWARE ================= */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

/* ================= SESSION ================= */
app.use(session({
    secret: process.env.SESSION_SECRET || "veryStrongSecretKey123",
    resave: false,
    saveUninitialized: false,

    cookie: {
        maxAge: 600000,
        httpOnly: true,
        secure: true,
        sameSite: "strict"
    }
}));

/* ================= CSRF ================= */
const csrfProtection = csurf({
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "strict"
    }
});

/* ================= RATE LIMITER ================= */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 4,

    message: `
        <h2>❌ Too many attempts</h2>
        <p>You are temporarily blocked</p>
        <a href="/">Go Back</a>
    `
});

/* ================= VALIDATION HELPERS ================= */
function isValidUsername(username) {
    return /^[a-zA-Z0-9]{3,15}$/.test(username);
}

function isValidPassword(password) {
    return password && password.length >= 6;
}

/* ================= DATABASE (TEMP MEMORY) ================= */
let users = [];

/* ================= ROUTES ================= */

/* HOME PAGE */
app.get("/", csrfProtection, (req, res) => {

    res.send(`
    <html>

    <head>
        <title>Secure App</title>
        <link rel="stylesheet" href="/style.css">
    </head>

    <body class="auth-page">

        <div class="container">

            <h2>Register</h2>

            <form method="POST" action="/register">

                <input type="hidden" name="_csrf" value="${req.csrfToken()}">

                <input
                    name="username"
                    placeholder="Username"
                    required
                >

                <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    required
                >

                <button type="submit">
                    Register
                </button>

            </form>

            <h2>Login</h2>

            <form method="POST" action="/login">

                <input type="hidden" name="_csrf" value="${req.csrfToken()}">

                <input
                    name="username"
                    placeholder="Username"
                    required
                >

                <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    required
                >

                <button type="submit">
                    Login
                </button>

            </form>

        </div>

    </body>
    </html>
    `);
});

/* REGISTER */
app.post(
    "/register",
    loginLimiter,
    csrfProtection,
    async (req, res) => {

        const { username = "", password = "" } = req.body;

        if (
            !isValidUsername(username) ||
            !isValidPassword(password)
        ) {

            logger.warn("Invalid registration input");

            return res.send(`
                Invalid input
                <br>
                <a href="/">Back</a>
            `);
        }

        const existingUser = users.find(
            u => u.username === username
        );

        if (existingUser) {

            return res.send(`
                User already exists
                <br>
                <a href="/">Back</a>
            `);
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        users.push({
            username,
            password: hashedPassword
        });

        logger.info(`New user registered: ${username}`);

        res.redirect("/");
    }
);

/* LOGIN */
app.post(
    "/login",
    loginLimiter,
    csrfProtection,
    async (req, res) => {

        const { username = "", password = "" } = req.body;

        const user = users.find(
            u => u.username === username
        );

        if (!user) {

            logger.warn(
                `Failed login attempt for: ${username}`
            );

            return res.send(`
                Invalid credentials
                <br>
                <a href="/">Back</a>
            `);
        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {

            logger.warn(
                `Failed login attempt for: ${username}`
            );

            return res.send(`
                Invalid credentials
                <br>
                <a href="/">Back</a>
            `);
        }

        req.session.regenerate((err) => {

            if (err) {
                logger.error("Session regeneration failed");
                return res.send("Session Error");
            }

            req.session.user = username;

            logger.info(`User logged in: ${username}`);

            res.redirect("/dashboard");
        });
    }
);

/* DASHBOARD */
app.get("/dashboard", (req, res) => {

    if (!req.session.user) {
        return res.redirect("/");
    }

    res.send(`
    <html>

    <head>
        <title>Dashboard</title>
        <link rel="stylesheet" href="/style.css">
    </head>

    <body>

        <div class="navbar">
            Welcome ${req.session.user}
        </div>

        <div class="container">

            <h2>Dashboard</h2>

            <p>Login successful ✅</p>

            <a href="/logout">Logout</a>

        </div>

    </body>
    </html>
    `);
});

/* API ROUTE */
app.get("/api/users", (req, res) => {

    if (!req.session.user) {

        logger.warn(
            "Unauthorized API access attempt"
        );

        return res.status(403).json({
            message: "Access Denied"
        });
    }

    logger.info(
        `API accessed by: ${req.session.user}`
    );

    res.json(
        users.map(u => ({
            username: u.username
        }))
    );
});

/* LOGOUT */
app.get("/logout", (req, res) => {

    req.session.destroy(() => {

        res.clearCookie("connect.sid");

        res.redirect("/");
    });
});

/* CSRF ERROR HANDLER */
app.use((err, req, res, next) => {

    if (err.code === "EBADCSRFTOKEN") {

        logger.warn(
            "Invalid CSRF token attempt"
        );

        return res.status(403).send(`
            ❌ Invalid CSRF Token
            <br>
            <a href="/">Refresh</a>
        `);
    }

    next(err);
});

/* GLOBAL ERROR HANDLER */
app.use((err, req, res, next) => {

    logger.error(err.message);

    res.status(500).send(`
        Internal Server Error
    `);
});

/* ================= HTTPS ================= */
const httpsOptions = {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem")
};

https.createServer(
    httpsOptions,
    app
).listen(8443, () => {

    console.log(
        "🔒 HTTPS Server running on https://localhost:8443"
    );
});
