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

/* =========================================================
   BODY PARSERS
========================================================= */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

/* =========================================================
   STATIC FILES
========================================================= */
app.use(express.static("public"));

/* =========================================================
   LOGGER
========================================================= */
const logger = winston.createLogger({
    level: "info",

    format: winston.format.combine(
        winston.format.timestamp(),

        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),

    transports: [
        new winston.transports.File({
            filename: "security.log"
        })
    ]
});

/* =========================================================
   SECURITY HEADERS
========================================================= */
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

        referrerPolicy: {
            policy: "no-referrer"
        },

        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        },

        permissionsPolicy: {
            features: {
                camera: [],
                microphone: [],
                geolocation: []
            }
        }
    })
);

app.disable("x-powered-by");

/* =========================================================
   CACHE CONTROL
========================================================= */
app.use((req, res, next) => {

    res.setHeader(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private"
    );

    res.setHeader("Pragma", "no-cache");

    res.setHeader("Expires", "0");

    next();
});

/* =========================================================
   SESSION
========================================================= */
app.use(
    session({
        secret: process.env.SESSION_SECRET || "VeryStrongSecret123",

        resave: false,

        saveUninitialized: false,

        cookie: {
            maxAge: 5 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: "strict"
        }
    })
);

/* =========================================================
   FAKE DATABASE
========================================================= */
let users = [];

/* =========================================================
   RATE LIMITER
========================================================= */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    max: 5,

    message: `
        <h2>Too Many Requests</h2>
        <p>Please try again later.</p>
    `
});

/* =========================================================
   WAF (WEB APPLICATION FIREWALL)
========================================================= */
const waf = (req, res, next) => {

    const badPatterns = [

        /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,

        /\b(select|update|delete|insert|drop|union)\b/i,

        /<script.*?>/i,

        /<\/script>/i,

        /\.\.\//i,

        /javascript:/i
    ];

    let payload = "";

    try {

        payload = JSON.stringify({
            url: req.url,
            query: req.query || {},
            body: req.body || {}
        });

    } catch (err) {

        payload = req.url;
    }

    const malicious = badPatterns.some((pattern) => {
        return pattern.test(payload);
    });

    if (malicious) {

        logger.warn(`WAF BLOCKED: ${req.ip} ${req.url}`);

        return res.status(403).send(`
            <h2>403 Forbidden</h2>
            <p>Blocked by WAF</p>
        `);
    }

    next();
};

app.use(waf);

/* =========================================================
   CSRF PROTECTION
========================================================= */
const csrfProtection = csurf({
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "strict"
    }
});

/* =========================================================
   VALIDATION
========================================================= */
function isValidUsername(username) {

    return /^[a-zA-Z0-9]{3,15}$/.test(username);
}

function isValidPassword(password) {

    return typeof password === "string" &&
           password.length >= 6;
}

/* =========================================================
   AUTHORIZATION
========================================================= */
function requireAuth(req, res, next) {

    if (!req.session.user) {

        logger.warn(`Unauthorized access attempt from ${req.ip}`);

        return res.status(401).send(`
            <h2>401 Unauthorized</h2>
            <a href="/">Login</a>
        `);
    }

    next();
}

/* =========================================================
   ZERO TRUST LOGIN PROTECTION
========================================================= */
const loginAttempts = {};

const MAX_ATTEMPTS = 5;

const LOCK_TIME = 10 * 60 * 1000;

/* =========================================================
   HOME PAGE
========================================================= */
app.get("/", csrfProtection, (req, res) => {

    res.send(`
    <html>

    <head>

        <title>Secure App</title>

        <style>

            body{
                font-family:Arial;
                background:#f4f4f4;
                padding:40px;
            }

            .container{
                background:white;
                padding:30px;
                width:350px;
                margin:auto;
                border-radius:10px;
                box-shadow:0 0 10px rgba(0,0,0,0.1);
            }

            input{
                width:100%;
                padding:10px;
                margin-top:10px;
            }

            button{
                width:100%;
                padding:10px;
                margin-top:15px;
                background:#222;
                color:white;
                border:none;
            }

        </style>

    </head>

    <body>

        <div class="container">

            <h2>Register</h2>

            <form method="POST" action="/register">

                <input
                    type="hidden"
                    name="_csrf"
                    value="${req.csrfToken()}"
                >

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

            <hr>

            <h2>Login</h2>

            <form method="POST" action="/login">

                <input
                    type="hidden"
                    name="_csrf"
                    value="${req.csrfToken()}"
                >

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

/* =========================================================
   REGISTER
========================================================= */
app.post(
    "/register",
    loginLimiter,
    csrfProtection,

    async (req, res) => {

        const {
            username = "",
            password = ""
        } = req.body;

        if (
            !isValidUsername(username) ||
            !isValidPassword(password)
        ) {

            logger.warn("Invalid registration input");

            return res.send(`
                <h2>Invalid Input</h2>
                <a href="/">Back</a>
            `);
        }

        const existingUser = users.find((u) => {
            return u.username === username;
        });

        if (existingUser) {

            return res.send(`
                <h2>User Already Exists</h2>
                <a href="/">Back</a>
            `);
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        users.push({
            username,
            password: hashedPassword
        });

        logger.info(`User Registered: ${username}`);

        res.redirect("/");
    }
);

/* =========================================================
   LOGIN
========================================================= */
app.post(
    "/login",
    loginLimiter,
    csrfProtection,

    async (req, res) => {

        const {
            username = "",
            password = ""
        } = req.body;

        if (!loginAttempts[username]) {

            loginAttempts[username] = {
                attempts: 0,
                lockUntil: null
            };
        }

        const account = loginAttempts[username];

        if (
            account.lockUntil &&
            Date.now() < account.lockUntil
        ) {

            return res.send(`
                <h2>Account Locked</h2>
                <p>Try again later.</p>
            `);
        }

        const user = users.find((u) => {
            return u.username === username;
        });

        if (!user) {

            account.attempts++;

            if (account.attempts >= MAX_ATTEMPTS) {

                account.lockUntil =
                    Date.now() + LOCK_TIME;
            }

            logger.warn(`Invalid Login: ${username}`);

            return res.send(`
                <h2>Invalid Credentials</h2>
                <a href="/">Back</a>
            `);
        }

        const match = await bcrypt.compare(
            password,
            user.password
        );

        if (!match) {

            account.attempts++;

            if (account.attempts >= MAX_ATTEMPTS) {

                account.lockUntil =
                    Date.now() + LOCK_TIME;
            }

            logger.warn(`Invalid Login: ${username}`);

            return res.send(`
                <h2>Invalid Credentials</h2>
                <a href="/">Back</a>
            `);
        }

        account.attempts = 0;

        account.lockUntil = null;

        req.session.regenerate((err) => {

            if (err) {

                logger.error("Session regeneration failed");

                return res.send(`
                    <h2>Session Error</h2>
                `);
            }

            req.session.user = username;

            logger.info(`User Logged In: ${username}`);

            res.redirect("/dashboard");
        });
    }
);

/* =========================================================
   DASHBOARD
========================================================= */
app.get("/dashboard", requireAuth, (req, res) => {

    res.send(`
    <html>

    <head>
        <title>Dashboard</title>
    </head>

    <body>

        <h1>
            Welcome ${req.session.user}
        </h1>

        <p>Login Successful</p>

        <a href="/api/users">
            View Users API
        </a>

        <br><br>

        <a href="/training/phishing">
            🔐 Security Awareness Training
        </a>

        <br><br>

        <a href="/logout">
            Logout
        </a>

    </body>

    </html>
    `);
});

/* =========================================================
   API
========================================================= */
app.get("/api/users", requireAuth, (req, res) => {

    logger.info(`API Accessed By: ${req.session.user}`);

    res.json(
        users.map((u) => ({
            username: u.username
        }))
    );
});

/* =========================================================
   BONUS 3
   PHISHING AWARENESS TRAINING
========================================================= */

/* TRAINING PAGE */
app.get(
    "/training/phishing",
    requireAuth,
    csrfProtection,

    (req, res) => {

        res.send(`
        <html>

        <head>
            <title>Security Awareness</title>
        </head>

        <body>

            <h2>
                🔐 Security Awareness Training
            </h2>

            <p>
                This is a simulated phishing page
                for educational purposes only.
            </p>

            <form
                method="POST"
                action="/training/phishing-submit"
            >

                <input
                    type="hidden"
                    name="_csrf"
                    value="${req.csrfToken()}"
                >

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

            <br>

            <a href="/dashboard">
                Back to Dashboard
            </a>

        </body>

        </html>
        `);
    }
);

/* TRAINING SUBMIT */
app.post(
    "/training/phishing-submit",
    loginLimiter,
    csrfProtection,

    (req, res) => {

        const { username = "" } = req.body;

        logger.warn(
            `PHISHING SIMULATION TRIGGERED: ${username}`
        );

        console.log(
            "Training Input:",
            req.body
        );

        res.send(`
            <h2>
                ⚠️ Training Complete
            </h2>

            <p>
                You interacted with a
                simulated phishing page.
            </p>

            <p>
                No credentials were stored.
            </p>

            <a href="/dashboard">
                Back
            </a>
        `);
    }
);

/* =========================================================
   LOGOUT
========================================================= */
app.get("/logout", (req, res) => {

    req.session.destroy(() => {

        res.clearCookie("connect.sid");

        res.redirect("/");
    });
});

/* =========================================================
   CSRF ERROR HANDLER
========================================================= */
app.use((err, req, res, next) => {

    if (err.code === "EBADCSRFTOKEN") {

        logger.warn(`CSRF BLOCKED: ${req.ip}`);

        return res.status(403).send(`
            <h2>Invalid CSRF Token</h2>
        `);
    }

    next(err);
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */
app.use((err, req, res, next) => {

    logger.error(err.message);

    res.status(500).send(`
        <h2>Internal Server Error</h2>
    `);
});

/* =========================================================
   HTTPS SERVER
========================================================= */
const httpsOptions = {

    key: fs.readFileSync("key.pem"),

    cert: fs.readFileSync("cert.pem")
};

const PORT = 8443;

https
    .createServer(httpsOptions, app)
    .listen(PORT, () => {

        console.log(`
🔒 Secure Server Running:
https://localhost:${PORT}
        `);
    });
