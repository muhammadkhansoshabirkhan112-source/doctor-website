const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();

const app = express();

/* =========================================================
   BASIC CONFIG
========================================================= */

app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || "production";

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME || "drtanzil";

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD;

if (!ADMIN_PASSWORD) {
    console.error(
        "ERROR: ADMIN_PASSWORD environment variable is not set."
    );
    process.exit(1);
}

/* =========================================================
   PATHS
========================================================= */

const PUBLIC_DIR = path.join(__dirname, "public");

const DB_DIR =
    process.env.DB_DIR ||
    process.env.RAILWAY_VOLUME_MOUNT_PATH ||
    __dirname;

try {
    fs.mkdirSync(DB_DIR, {
        recursive: true
    });
} catch (error) {
    console.error(
        "Unable to create database directory:",
        error
    );
    process.exit(1);
}

const DB_PATH =
    path.join(DB_DIR, "appointments.db");

console.log("=================================");
console.log("Doctor Website Starting");
console.log("Environment:", NODE_ENV);
console.log("Port:", PORT);
console.log("Public directory:", PUBLIC_DIR);
console.log("Database:", DB_PATH);
console.log("=================================");

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
    express.json({
        limit: "50kb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "50kb"
    })
);

/* =========================================================
   SQLITE
========================================================= */

const db = new sqlite3.Database(
    DB_PATH,
    (error) => {
        if (error) {
            console.error(
                "SQLite connection error:",
                error
            );
            process.exit(1);
        }

        console.log("SQLite connected");
    }
);

db.serialize(() => {

    db.run(
        "PRAGMA foreign_keys = ON"
    );

    db.run(`
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            date TEXT NOT NULL,
            hospital TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT UNIQUE NOT NULL,
            admin_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id)
                REFERENCES admins(id)
                ON DELETE CASCADE
        )
    `);

    /* Add status column if an older database doesn't have it. */

    db.all(
        "PRAGMA table_info(appointments)",
        (error, columns) => {

            if (error) {
                console.error(
                    "Unable to inspect appointments table:",
                    error
                );
                return;
            }

            const hasStatus =
                columns.some(
                    column =>
                        column.name === "status"
                );

            if (!hasStatus) {

                db.run(
                    `
                    ALTER TABLE appointments
                    ADD COLUMN status TEXT
                    NOT NULL DEFAULT 'pending'
                    `,
                    (alterError) => {

                        if (alterError) {
                            console.error(
                                "Unable to add status column:",
                                alterError
                            );
                        } else {
                            console.log(
                                "status column added"
                            );
                        }

                    }
                );

            } else {

                console.log(
                    "status column exists"
                );

            }

        }
    );

    createAdmin();

});

/* =========================================================
   PASSWORD HASHING
========================================================= */

function hashPassword(password, salt) {

    return crypto
        .scryptSync(
            password,
            salt,
            64
        )
        .toString("hex");

}

function createPasswordData(password) {

    const salt =
        crypto
            .randomBytes(32)
            .toString("hex");

    const hash =
        hashPassword(
            password,
            salt
        );

    return {
        salt,
        hash
    };

}

function verifyPassword(
    password,
    storedHash,
    storedSalt
) {

    const calculatedHash =
        hashPassword(
            password,
            storedSalt
        );

    const a =
        Buffer.from(
            calculatedHash,
            "hex"
        );

    const b =
        Buffer.from(
            storedHash,
            "hex"
        );

    if (a.length !== b.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        a,
        b
    );

}

/* =========================================================
   CREATE ADMIN
========================================================= */

function createAdmin() {

    db.get(
        `
        SELECT id, username
        FROM admins
        LIMIT 1
        `,
        (error, admin) => {

            if (error) {
                console.error(
                    "Unable to check admin:",
                    error
                );
                return;
            }

            if (admin) {

                console.log(
                    "Admin account exists:",
                    admin.username
                );

                return;
            }

            const {
                salt,
                hash
            } = createPasswordData(
                ADMIN_PASSWORD
            );

            db.run(
                `
                INSERT INTO admins
                (
                    username,
                    password_hash,
                    password_salt
                )
                VALUES (?, ?, ?)
                `,
                [
                    ADMIN_USERNAME,
                    hash,
                    salt
                ],
                function (insertError) {

                    if (insertError) {

                        console.error(
                            "Unable to create admin:",
                            insertError
                        );

                    } else {

                        console.log(
                            "Admin account created:",
                            ADMIN_USERNAME
                        );

                    }

                }
            );

        }
    );

}

/* =========================================================
   COOKIE HELPERS
========================================================= */

function parseCookies(
    request
) {

    const header =
        request.headers.cookie;

    if (!header) {
        return {};
    }

    const cookies = {};

    header
        .split(";")
        .forEach(
            part => {

                const index =
                    part.indexOf("=");

                if (index === -1) {
                    return;
                }

                const key =
                    part
                        .slice(0, index)
                        .trim();

                const value =
                    part
                        .slice(index + 1)
                        .trim();

                cookies[key] =
                    decodeURIComponent(
                        value
                    );

            }
        );

    return cookies;

}

function createSessionToken() {

    return crypto
        .randomBytes(48)
        .toString("hex");

}

function hashSessionToken(
    token
) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}

function setSessionCookie(
    response,
    token
) {

    const secure =
        NODE_ENV === "production";

    const cookieParts = [
        `admin_session=${encodeURIComponent(token)}`,
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=86400"
    ];

    if (secure) {
        cookieParts.push("Secure");
    }

    response.setHeader(
        "Set-Cookie",
        cookieParts.join("; ")
    );

}

function clearSessionCookie(
    response
) {

    const secure =
        NODE_ENV === "production";

    const cookieParts = [
        "admin_session=",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=0"
    ];

    if (secure) {
        cookieParts.push("Secure");
    }

    response.setHeader(
        "Set-Cookie",
        cookieParts.join("; ")
    );

}

/* =========================================================
   ADMIN SESSION
========================================================= */

function getAdminFromRequest(
    request,
    callback
) {

    const cookies =
        parseCookies(request);

    const token =
        cookies.admin_session;

    if (!token) {
        callback(null, null);
        return;
    }

    const tokenHash =
        hashSessionToken(token);

    db.get(
        `
        SELECT
            admin_sessions.id AS session_id,
            admin_sessions.expires_at,
            admins.id,
            admins.username
        FROM admin_sessions
        INNER JOIN admins
            ON admins.id =
               admin_sessions.admin_id
        WHERE admin_sessions.token_hash = ?
        LIMIT 1
        `,
        [tokenHash],
        (error, row) => {

            if (error) {
                callback(error, null);
                return;
            }

            if (!row) {
                callback(null, null);
                return;
            }

            if (
                Number(row.expires_at) <
                Date.now()
            ) {

                db.run(
                    `
                    DELETE FROM admin_sessions
                    WHERE id = ?
                    `,
                    [row.session_id]
                );

                callback(null, null);
                return;
            }

            callback(
                null,
                {
                    id: row.id,
                    username: row.username,
                    sessionId:
                        row.session_id
                }
            );

        }
    );

}

/* =========================================================
   ADMIN AUTH MIDDLEWARE
========================================================= */

function requireAdmin(
    request,
    response,
    next
) {

    getAdminFromRequest(
        request,
        (error, admin) => {

            if (error) {

                console.error(
                    "Session error:",
                    error
                );

                return response
                    .status(500)
                    .json({
                        success: false,
                        message:
                            "Authentication error."
                    });

            }

            if (!admin) {

                if (
                    request.path.startsWith(
                        "/api/"
                    )
                ) {

                    return response
                        .status(401)
                        .json({
                            success: false,
                            message:
                                "Unauthorized."
                        });

                }

                return response.redirect(
                    "/admin/login"
                );

            }

            request.admin =
                admin;

            next();

        }
    );

}

/* =========================================================
   LOGIN RATE LIMIT
========================================================= */

const loginAttempts =
    new Map();

function getClientIp(
    request
) {

    const forwarded =
        request.headers[
            "x-forwarded-for"
        ];

    if (forwarded) {

        return forwarded
            .split(",")[0]
            .trim();

    }

    return (
        request.ip ||
        request.socket
            ?.remoteAddress ||
        "unknown"
    );

}

function isLoginBlocked(
    ip
) {

    const record =
        loginAttempts.get(ip);

    if (!record) {
        return false;
    }

    if (
        record.blockedUntil &&
        record.blockedUntil >
            Date.now()
    ) {

        return true;

    }

    if (
        record.blockedUntil &&
        record.blockedUntil <=
            Date.now()
    ) {

        loginAttempts.delete(ip);

    }

    return false;

}

function registerFailedLogin(
    ip
) {

    const now =
        Date.now();

    let record =
        loginAttempts.get(ip);

    if (!record) {

        record = {
            count: 0,
            blockedUntil: 0
        };

    }

    record.count += 1;

    if (record.count >= 5) {

        record.blockedUntil =
            now +
            15 * 60 * 1000;

    }

    loginAttempts.set(
        ip,
        record
    );

}

function clearLoginAttempts(
    ip
) {

    loginAttempts.delete(ip);

}

/* =========================================================
   APPOINTMENT RATE LIMIT
========================================================= */

const appointmentAttempts =
    new Map();

function appointmentRateLimited(
    ip
) {

    const now =
        Date.now();

    const windowMs =
        15 * 60 * 1000;

    let timestamps =
        appointmentAttempts.get(ip) ||
        [];

    timestamps =
        timestamps.filter(
            timestamp =>
                now - timestamp <
                windowMs
        );

    if (timestamps.length >= 10) {

        appointmentAttempts.set(
            ip,
            timestamps
        );

        return true;

    }

    timestamps.push(now);

    appointmentAttempts.set(
        ip,
        timestamps
    );

    return false;

}

/* =========================================================
   PAGE ROUTES
========================================================= */

/*
   Explicitly serve the homepage.
   This removes the Railway "/" 404 ambiguity.
*/

app.get(
    "/",
    (request, response) => {

        response.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );

    }
);

/*
   Admin login page.
*/

app.get(
    "/admin/login",
    (request, response) => {

        response.sendFile(
            path.join(
                PUBLIC_DIR,
                "admin-login.html"
            )
        );

    }
);

/*
   Admin dashboard.
*/

app.get(
    "/admin",
    requireAdmin,
    (request, response) => {

        response.sendFile(
            path.join(
                PUBLIC_DIR,
                "admin.html"
            )
        );

    }
);

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
    express.static(
        PUBLIC_DIR,
        {
            index: false,
            extensions: [
                "html"
            ]
        }
    )
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/health",
    (request, response) => {

        response.json({
            success: true,
            status: "ok",
            service:
                "doctor-website",
            timestamp:
                new Date().toISOString()
        });

    }
);

app.get(
    "/api/test",
    (request, response) => {

        response.json({
            success: true,
            message:
                "API is working."
        });

    }
);

/* =========================================================
   APPOINTMENT API
========================================================= */

app.post(
    "/api/appointments",
    (request, response) => {

        const ip =
            getClientIp(request);

        if (
            appointmentRateLimited(ip)
        ) {

            return response
                .status(429)
                .json({
                    success: false,
                    message:
                        "Too many appointment requests. Please try again later."
                });

        }

        const {
            name,
            phone,
            email,
            date,
            hospital,
            reason
        } = request.body || {};

        const cleanName =
            String(
                name || ""
            ).trim();

        const cleanPhone =
            String(
                phone || ""
            ).trim();

        const cleanEmail =
            String(
                email || ""
            ).trim();

        const cleanDate =
            String(
                date || ""
            ).trim();

        const cleanHospital =
            String(
                hospital || ""
            ).trim();

        const cleanReason =
            String(
                reason || ""
            ).trim();

        /* -------------------------
           VALIDATION
        ------------------------- */

        if (
            !cleanName ||
            cleanName.length < 2 ||
            cleanName.length > 100
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Please enter a valid name."
                });

        }

        if (
            !cleanPhone ||
            !/^[0-9+\-\s()]{7,25}$/.test(
                cleanPhone
            )
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Please enter a valid phone number."
                });

        }

        if (
            cleanEmail &&
            (
                cleanEmail.length > 150 ||
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                    cleanEmail
                )
            )
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Please enter a valid email address."
                });

        }

        if (!cleanDate) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Please select an appointment date."
                });

        }

        /*
           The frontend prevents past dates,
           but the server validates as well.
        */

        const requestedDate =
            new Date(
                `${cleanDate}T00:00:00`
            );

        if (
            Number.isNaN(
                requestedDate.getTime()
            )
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Please select a valid appointment date."
                });

        }

        const today =
            new Date();

        today.setHours(
            0,
            0,
            0,
            0
        );

        if (
            requestedDate <
            today
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Appointment date cannot be in the past."
                });

        }

        if (!cleanHospital) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Please select a hospital."
                });

        }

        if (
            cleanHospital.length > 200
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Invalid hospital."
                });

        }

        /* -------------------------
           SAVE
        ------------------------- */

        db.run(
            `
            INSERT INTO appointments
            (
                name,
                phone,
                email,
                date,
                hospital,
                reason,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
            `,
            [
                cleanName,
                cleanPhone,
                cleanEmail || null,
                cleanDate,
                cleanHospital,
                cleanReason || null
            ],
            function (error) {

                if (error) {

                    console.error(
                        "Appointment insert error:",
                        error
                    );

                    return response
                        .status(500)
                        .json({
                            success: false,
                            message:
                                "Unable to save appointment."
                        });

                }

                console.log(
                    `New appointment #${this.lastID} from ${ip}`
                );

                return response
                    .status(201)
                    .json({
                        success: true,
                        message:
                            "Appointment request submitted successfully.",
                        id: this.lastID
                    });

            }
        );

    }
);

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
    "/api/admin/login",
    (request, response) => {

        const ip =
            getClientIp(request);

        if (
            isLoginBlocked(ip)
        ) {

            return response
                .status(429)
                .json({
                    success: false,
                    message:
                        "Too many failed login attempts. Please try again in 15 minutes."
                });

        }

        const username =
            String(
                request.body?.username ||
                ""
            ).trim();

        const password =
            String(
                request.body?.password ||
                ""
            );

        if (
            !username ||
            !password
        ) {

            registerFailedLogin(ip);

            return response
                .status(401)
                .json({
                    success: false,
                    message:
                        "Invalid username or password."
                });

        }

        db.get(
            `
            SELECT
                id,
                username,
                password_hash,
                password_salt
            FROM admins
            WHERE username = ?
            LIMIT 1
            `,
            [username],
            (error, admin) => {

                if (error) {

                    console.error(
                        "Admin login database error:",
                        error
                    );

                    return response
                        .status(500)
                        .json({
                            success: false,
                            message:
                                "Login service unavailable."
                        });

                }

                if (!admin) {

                    registerFailedLogin(ip);

                    return response
                        .status(401)
                        .json({
                            success: false,
                            message:
                                "Invalid username or password."
                        });

                }

                let valid = false;

                try {

                    valid =
                        verifyPassword(
                            password,
                            admin.password_hash,
                            admin.password_salt
                        );

                } catch (verifyError) {

                    console.error(
                        "Password verification error:",
                        verifyError
                    );

                    valid = false;

                }

                if (!valid) {

                    registerFailedLogin(ip);

                    return response
                        .status(401)
                        .json({
                            success: false,
                            message:
                                "Invalid username or password."
                        });

                }

                clearLoginAttempts(ip);

                /*
                   Remove old sessions for this admin.
                */

                db.run(
                    `
                    DELETE FROM admin_sessions
                    WHERE admin_id = ?
                    `,
                    [admin.id],
                    (deleteError) => {

                        if (deleteError) {

                            console.error(
                                "Session cleanup error:",
                                deleteError
                            );

                        }

                        const token =
                            createSessionToken();

                        const tokenHash =
                            hashSessionToken(
                                token
                            );

                        const expiresAt =
                            Date.now() +
                            24 * 60 * 60 * 1000;

                        db.run(
                            `
                            INSERT INTO admin_sessions
                            (
                                token_hash,
                                admin_id,
                                expires_at
                            )
                            VALUES (?, ?, ?)
                            `,
                            [
                                tokenHash,
                                admin.id,
                                expiresAt
                            ],
                            (sessionError) => {

                                if (
                                    sessionError
                                ) {

                                    console.error(
                                        "Session creation error:",
                                        sessionError
                                    );

                                    return response
                                        .status(500)
                                        .json({
                                            success: false,
                                            message:
                                                "Unable to create login session."
                                        });

                                }

                                setSessionCookie(
                                    response,
                                    token
                                );

                                return response
                                    .json({
                                        success: true,
                                        message:
                                            "Login successful.",
                                        admin: {
                                            username:
                                                admin.username
                                        }
                                    });

                            }
                        );

                    }
                );

            }
        );

    }
);

/* =========================================================
   CURRENT ADMIN
========================================================= */

app.get(
    "/api/admin/me",
    (request, response) => {

        getAdminFromRequest(
            request,
            (error, admin) => {

                if (error) {

                    console.error(
                        "Admin session check error:",
                        error
                    );

                    return response
                        .status(500)
                        .json({
                            success: false,
                            message:
                                "Unable to check session."
                        });

                }

                if (!admin) {

                    return response
                        .status(401)
                        .json({
                            success: false,
                            message:
                                "Not authenticated."
                        });

                }

                return response.json({
                    success: true,
                    admin: {
                        username:
                            admin.username
                    }
                });

            }
        );

    }
);

/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post(
    "/api/admin/logout",
    (request, response) => {

        const cookies =
            parseCookies(request);

        const token =
            cookies.admin_session;

        if (token) {

            const tokenHash =
                hashSessionToken(token);

            db.run(
                `
                DELETE FROM admin_sessions
                WHERE token_hash = ?
                `,
                [tokenHash]
            );

        }

        clearSessionCookie(
            response
        );

        return response.json({
            success: true,
            message:
                "Logged out successfully."
        });

    }
);

/* =========================================================
   GET APPOINTMENTS
   IMPORTANT:
   admin.html expects a RAW ARRAY.
========================================================= */

app.get(
    "/api/appointments",
    requireAdmin,
    (request, response) => {

        db.all(
            `
            SELECT
                id,
                name,
                phone,
                email,
                date,
                hospital,
                reason,
                status,
                created_at
            FROM appointments
            ORDER BY
                datetime(created_at) DESC,
                id DESC
            `,
            [],
            (error, rows) => {

                if (error) {

                    console.error(
                        "Appointment fetch error:",
                        error
                    );

                    return response
                        .status(500)
                        .json({
                            success: false,
                            message:
                                "Unable to load appointments."
                        });

                }

                /*
                   IMPORTANT:
                   Do NOT wrap this in { success, appointments }.
                   Your existing admin.html expects the array directly.
                */

                return response.json(
                    rows || []
                );

            }
        );

    }
);

/* =========================================================
   ADMIN STATISTICS
========================================================= */

app.get(
    "/api/admin/stats",
    requireAdmin,
    (request, response) => {

        db.get(
            `
            SELECT
                COUNT(*) AS total,
                SUM(
                    CASE
                        WHEN status = 'pending'
                        THEN 1
                        ELSE 0
                    END
                ) AS pending,
                SUM(
                    CASE
                        WHEN status = 'approved'
                        THEN 1
                        ELSE 0
                    END
                ) AS approved,
                SUM(
                    CASE
                        WHEN status = 'rejected'
                        THEN 1
                        ELSE 0
                    END
                ) AS rejected
            FROM appointments
            `,
            [],
            (error, stats) => {

                if (error) {

                    console.error(
                        "Stats error:",
                        error
                    );

                    return response
                        .status(500)
                        .json({
                            success: false,
                            message:
                                "Unable to load statistics."
                        });

                }

                return response.json({
                    success: true,
                    stats: {
                        total:
                            Number(
                                stats?.total || 0
                            ),
                        pending:
                            Number(
                                stats?.pending || 0
                            ),
                        approved:
                            Number(
                                stats?.approved || 0
                            ),
                        rejected:
                            Number(
                                stats?.rejected || 0
                            )
                    }
                });

            }
        );

    }
);

/* =========================================================
   UPDATE APPOINTMENT STATUS
========================================================= */

app.put(
    "/api/appointments/:id/status",
    requireAdmin,
    (request, response) => {

        const id =
            Number(
                request.params.id
            );

        const status =
            String(
                request.body?.status ||
                ""
            ).trim().toLowerCase();

        if (
            !Number.isInteger(id) ||
            id <= 0
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Invalid appointment ID."
                });

        }

        if (
            ![
                "pending",
                "approved",
                "rejected"
            ].includes(status)
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Invalid appointment status."
                });

        }

        db.run(
            `
            UPDATE appointments
            SET status = ?
            WHERE id = ?
            `,
            [
                status,
                id
            ],
            function (error) {

                if (error) {

                    console.error(
                        "Status update error:",
                        error
                    );

                    return response
                        .status(500)
                        .json({
                            success: false,
                            message:
                                "Unable to update appointment status."
                        });

                }

                if (
                    this.changes === 0
                ) {

                    return response
                        .status(404)
                        .json({
                            success: false,
                            message:
                                "Appointment not found."
                        });

                }

                return response.json({
                    success: true,
                    message:
                        "Appointment status updated.",
                    id,
                    status
                });

            }
        );

    }
);

/* =========================================================
   DELETE APPOINTMENT
========================================================= */

app.delete(
    "/api/appointments/:id",
    requireAdmin,
    (request, response) => {

        const id =
            Number(
                request.params.id
            );

        if (
            !Number.isInteger(id) ||
            id <= 0
        ) {

            return response
                .status(400)
                .json({
                    success: false,
                    message:
                        "Invalid appointment ID."
                });

        }

        db.run(
            `
            DELETE FROM appointments
            WHERE id = ?
            `,
            [id],
            function (error) {

                if (error) {

                    console.error(
                        "Appointment delete error:",
                        error
                    );

                    return response
                        .status(500)
                        .json({
                            success: false,
                            message:
                                "Unable to delete appointment."
                        });

                }

                if (
                    this.changes === 0
                ) {

                    return response
                        .status(404)
                        .json({
                            success: false,
                            message:
                                "Appointment not found."
                        });

                }

                return response.json({
                    success: true,
                    message:
                        "Appointment deleted successfully.",
                    id
                });

            }
        );

    }
);

/* =========================================================
   CLEAN OLD SESSIONS
========================================================= */

function cleanExpiredSessions() {

    db.run(
        `
        DELETE FROM admin_sessions
        WHERE expires_at < ?
        `,
        [Date.now()],
        (error) => {

            if (error) {

                console.error(
                    "Session cleanup error:",
                    error
                );

            }

        }
    );

}

setInterval(
    cleanExpiredSessions,
    60 * 60 * 1000
);

/* =========================================================
   GENERAL 404
========================================================= */

app.use(
    (request, response) => {

        if (
            request.path.startsWith(
                "/api/"
            )
        ) {

            return response
                .status(404)
                .json({
                    success: false,
                    message:
                        "API endpoint not found."
                });

        }

        return response
            .status(404)
            .send(
                "Page not found."
            );

    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        request,
        response,
        next
    ) => {

        console.error(
            "Unhandled server error:",
            error
        );

        if (
            response.headersSent
        ) {
            return next(error);
        }

        return response
            .status(500)
            .json({
                success: false,
                message:
                    "Internal server error."
            });

    }
);

/* =========================================================
   START SERVER
========================================================= */

const server =
    app.listen(
        PORT,
        "0.0.0.0",
        () => {

            console.log(
                `Doctor website running on port ${PORT}`
            );

            console.log(
                `Homepage: /`
            );

            console.log(
                `Admin: /admin`
            );

            console.log(
                `Admin login: /admin/login`
            );

        }
    );

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

function shutdown(
    signal
) {

    console.log(
        `${signal} received. Shutting down...`
    );

    server.close(
        () => {

            db.close(
                (error) => {

                    if (error) {

                        console.error(
                            "Database close error:",
                            error
                        );

                        process.exit(1);

                    }

                    console.log(
                        "Server and database closed."
                    );

                    process.exit(0);

                }
            );

        }
    );

}

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);
