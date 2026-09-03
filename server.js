const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_DURATION = 8 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_BLOCK_TIME = 15 * 60 * 1000;
const APPOINTMENT_WINDOW = 15 * 60 * 1000;
const MAX_APPOINTMENTS_PER_WINDOW = 10;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Railway Volume persistence: when a volume is attached, Railway exposes
// RAILWAY_VOLUME_MOUNT_PATH automatically. Locally, keep the database beside the app.
const databaseDirectory =
  process.env.DB_DIR ||
  process.env.RAILWAY_VOLUME_MOUNT_PATH ||
  __dirname;

fs.mkdirSync(databaseDirectory, { recursive: true });

const databasePath = path.join(
  databaseDirectory,
  "appointments.db"
);

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error("==============================================");
  console.error("ADMIN LOGIN CONFIGURATION MISSING");
  console.error("==============================================");
  console.error("Please set ADMIN_USERNAME and ADMIN_PASSWORD");
  console.error("before starting the server.");
  process.exit(1);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = new sqlite3.Database(
  databasePath,
  (error) => {
    if (error) {
      console.error("Database error:", error.message);
    } else {
      console.log("Connected to SQLite database.");
    }
  }
);


// ==========================
// Appointments table
// ==========================

db.run(`
  CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT,
    date TEXT NOT NULL,
    hospital TEXT NOT NULL,
    reason TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`, (error) => {

  if (error) {

    console.error(
      "Appointments table error:",
      error.message
    );

    return;
  }

  console.log("Appointments table ready.");

  // Add status column to older databases if it is missing
  db.all(
    "PRAGMA table_info(appointments)",
    [],
    (infoError, columns) => {

      if (infoError) {

        console.error(
          "Could not inspect appointments table:",
          infoError.message
        );

        return;
      }

      const hasStatusColumn = columns.some(
        (column) => column.name === "status"
      );

      if (!hasStatusColumn) {

        console.log(
          "Adding missing status column to appointments table..."
        );

        db.run(
          `
            ALTER TABLE appointments
            ADD COLUMN status TEXT DEFAULT 'pending'
          `,
          (alterError) => {

            if (alterError) {

              console.error(
                "Could not add status column:",
                alterError.message
              );

            } else {

              console.log(
                "Status column added successfully."
              );

            }

          }
        );

      } else {

        console.log(
          "Appointments status column already exists."
        );

      }

    }
  );

});


// ==========================
// Admin table
// ==========================

db.run(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`, (error) => {

  if (error) {

    console.error(
      "Admin table error:",
      error.message
    );

  } else {

    console.log("Admin table ready.");

    initializeAdmin();

  }

});


// ==========================
// Admin sessions table
// ==========================

db.run(`
  CREATE TABLE IF NOT EXISTS admin_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    admin_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (admin_id)
      REFERENCES admins(id)
      ON DELETE CASCADE
  )
`, (error) => {

  if (error) {

    console.error(
      "Session table error:",
      error.message
    );

  } else {

    console.log(
      "Admin session table ready."
    );

  }

});


const loginAttempts = new Map();
const appointmentAttempts = new Map();


// ==========================
// Client IP
// ==========================

function getClientIP(req) {

  return (
    req.ip ||
    req.socket.remoteAddress ||
    "unknown"
  );

}


// ==========================
// Login rate limiting
// ==========================

function isLoginBlocked(ip) {

  const record = loginAttempts.get(ip);

  if (!record) {
    return false;
  }

  if (Date.now() >= record.blockedUntil) {

    loginAttempts.delete(ip);

    return false;

  }

  return (
    record.failedAttempts >=
    MAX_LOGIN_ATTEMPTS
  );

}


function recordFailedLogin(ip) {

  const now = Date.now();

  const record =
    loginAttempts.get(ip) || {
      failedAttempts: 0,
      blockedUntil: 0
    };

  record.failedAttempts += 1;

  if (
    record.failedAttempts >=
    MAX_LOGIN_ATTEMPTS
  ) {

    record.blockedUntil =
      now + LOGIN_BLOCK_TIME;

  }

  loginAttempts.set(ip, record);

}


function clearLoginAttempts(ip) {

  loginAttempts.delete(ip);

}


// ==========================
// Appointment rate limiting
// ==========================

function isAppointmentRateLimited(ip) {

  const now = Date.now();
  const record = appointmentAttempts.get(ip);

  if (!record || now - record.windowStart >= APPOINTMENT_WINDOW) {
    appointmentAttempts.set(ip, { windowStart: now, count: 1 });
    return false;
  }

  record.count += 1;
  return record.count > MAX_APPOINTMENTS_PER_WINDOW;
}


// ==========================
// Password security
// ==========================

function hashPassword(password) {

  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

  return `${salt}:${hash}`;

}


function verifyPassword(
  password,
  storedHash
) {

  try {

    const parts =
      storedHash.split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = parts[0];

    const originalHash =
      parts[1];

    const hash =
      crypto
        .scryptSync(password, salt, 64)
        .toString("hex");

    const currentBuffer =
      Buffer.from(hash, "hex");

    const originalBuffer =
      Buffer.from(
        originalHash,
        "hex"
      );

    if (
      currentBuffer.length !==
      originalBuffer.length
    ) {

      return false;

    }

    return crypto.timingSafeEqual(
      currentBuffer,
      originalBuffer
    );

  } catch (error) {

    return false;

  }

}


// ==========================
// Initialize admin
// ==========================

function initializeAdmin() {

  db.get(
    "SELECT * FROM admins WHERE username = ?",
    [ADMIN_USERNAME],
    (error, admin) => {

      if (error) {

        console.error(
          "Admin lookup error:",
          error.message
        );

        return;

      }

      if (admin) {

        console.log(
          `Admin account "${ADMIN_USERNAME}" is ready.`
        );

        return;

      }

      const passwordHash =
        hashPassword(
          ADMIN_PASSWORD
        );

      db.run(
        `
          INSERT INTO admins
          (username, password_hash)
          VALUES (?, ?)
        `,
        [
          ADMIN_USERNAME,
          passwordHash
        ],
        (insertError) => {

          if (insertError) {

            console.error(
              "Could not create admin:",
              insertError.message
            );

          } else {

            console.log(
              "Admin account created successfully."
            );

            console.log(
              `Username: ${ADMIN_USERNAME}`
            );

          }

        }
      );

    }
  );

}


// ==========================
// Session cookies
// ==========================

function setSessionCookie(
  res,
  token
) {

  const secure =
    process.env.NODE_ENV ===
    "production"
      ? "; Secure"
      : "";

  res.setHeader(
    "Set-Cookie",
    `admin_session=${encodeURIComponent(token)}; HttpOnly;${secure} SameSite=Strict; Max-Age=${Math.floor(
      SESSION_DURATION / 1000
    )}; Path=/`
  );

}


function clearSessionCookie(res) {

  const secure =
    process.env.NODE_ENV ===
    "production"
      ? "; Secure"
      : "";

  res.setHeader(
    "Set-Cookie",
    `admin_session=; HttpOnly;${secure} SameSite=Strict; Max-Age=0; Path=/`
  );

}


// ==========================
// Create session
// ==========================

function createSession(
  adminId,
  res
) {

  const token =
    crypto.randomBytes(32).toString("hex");

  const tokenHash =
    crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

  const now = Date.now();

  const expiresAt =
    now + SESSION_DURATION;

  db.run(
    `
      INSERT INTO admin_sessions
      (token_hash, admin_id, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `,
    [
      tokenHash,
      adminId,
      expiresAt,
      now
    ],
    (error) => {

      if (error) {

        console.error(
          "Session creation error:",
          error.message
        );

        return res.status(500).json({
          success: false,
          message:
            "Could not create login session."
        });

      }

      setSessionCookie(
        res,
        token
      );

      res.json({
        success: true,
        message:
          "Login successful."
      });

    }
  );

}


// ==========================
// Get session token
// ==========================

function getSessionToken(req) {

  const cookieHeader =
    req.headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  const cookies =
    cookieHeader
      .split(";")
      .reduce(
        (result, item) => {

          const parts =
            item.trim().split("=");

          const key =
            parts.shift();

          const value =
            parts.join("=");

          if (key) {

            result[key] =
              decodeURIComponent(
                value || ""
              );

          }

          return result;

        },
        {}
      );

  return (
    cookies.admin_session ||
    null
  );

}


// ==========================
// Protect admin routes
// ==========================

function requireAdmin(
  req,
  res,
  next
) {

  const token =
    getSessionToken(req);

  if (!token) {

    if (
      req.path.startsWith(
        "/api/"
      )
    ) {

      return res.status(401).json({
        success: false,
        message:
          "Authentication required."
      });

    }

    return res.redirect(
      "/admin/login"
    );

  }

  const tokenHash =
    crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

  db.get(
    `
      SELECT
        admin_sessions.id AS session_id,
        admins.id AS admin_id,
        admins.username,
        admin_sessions.expires_at
      FROM admin_sessions
      INNER JOIN admins
        ON admins.id =
           admin_sessions.admin_id
      WHERE admin_sessions.token_hash = ?
        AND admin_sessions.expires_at > ?
    `,
    [
      tokenHash,
      Date.now()
    ],
    (error, session) => {

      if (error) {

        console.error(
          "Session verification error:",
          error.message
        );

        return res.status(500).json({
          success: false,
          message:
            "Authentication error."
        });

      }

      if (!session) {

        clearSessionCookie(res);

        if (
          req.path.startsWith(
            "/api/"
          )
        ) {

          return res.status(401).json({
            success: false,
            message:
              "Session expired."
          });

        }

        return res.redirect(
          "/admin/login"
        );

      }

      req.admin = {
        id: session.admin_id,
        username:
          session.username
      };

      next();

    }
  );

}


// ==========================
// Health check (Railway)
// ==========================

app.get(
  "/health",
  (req, res) => {
    res.status(200).json({
      success: true,
      status: "ok"
    });
  }
);


// ==========================
// Backend test
// ==========================

app.get(
  "/api/test",
  (req, res) => {

    res.json({
      success: true,
      message:
        "Backend is working!"
    });

  }
);


// ==========================
// Create appointment
// ==========================

app.post(
  "/api/appointments",
  (req, res) => {

    const clientIP = getClientIP(req);
    if (isAppointmentRateLimited(clientIP)) {
      return res.status(429).json({
        success: false,
        message: "Too many appointment requests. Please try again later or call 0319 5049455."
      });
    }

    const {
      name,
      phone,
      email,
      date,
      hospital
    } = req.body;

    const cleanName = String(name || "").trim();
    const cleanPhone = String(phone || "").trim();
    const cleanEmail = String(email || "").trim();
    const cleanDate = String(date || "").trim();
    const cleanHospital = String(hospital || "").trim();

    const allowedHospitals = [
      "Fauji Foundation Hospital — Rawalpindi",
      "Safari OPD Complex — Rawalpindi",
      "Attock Oil Refinery Hospital — Morgah, Rawalpindi"
    ];

    if (
      !cleanName ||
      !cleanPhone ||
      !cleanDate ||
      !cleanHospital
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Please fill in all required fields."
      });

    }

    if (cleanName.length > 100 || cleanPhone.length > 30 || cleanEmail.length > 254) {
      return res.status(400).json({
        success: false,
        message: "Please check the length of the information entered."
      });
    }

    if (!allowedHospitals.includes(cleanHospital)) {
      return res.status(400).json({
        success: false,
        message: "Please select a valid consultation location."
      });
    }

    // Accept only the date format produced by <input type="date"> and
    // reject dates in the past. This also prevents malformed dates reaching SQLite.
    const datePattern = /^\d{4}-\d{2}-\d{2}$/;
    if (!datePattern.test(cleanDate)) {
      return res.status(400).json({
        success: false,
        message: "Please choose a valid appointment date."
      });
    }

    const requestedDate = new Date(`${cleanDate}T00:00:00`);
    if (Number.isNaN(requestedDate.getTime())) {
      return res.status(400).json({
        success: false,
        message: "Please choose a valid appointment date."
      });
    }

    const now = new Date();
    now.setHours(0, 0, 0, 0);
    if (requestedDate < now) {
      return res.status(400).json({
        success: false,
        message: "Please choose today or a future date."
      });
    }

    if (cleanEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address or leave it blank."
      });
    }

    const sql = `
      INSERT INTO appointments
      (name, phone, email, date, hospital, status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `;

    db.run(
      sql,
      [
        cleanName,
        cleanPhone,
        cleanEmail,
        cleanDate,
        cleanHospital
      ],
      function (error) {

        if (error) {

          console.error(
            "Insert error:",
            error.message
          );

          return res.status(500).json({
            success: false,
            message:
              "Could not save appointment."
          });

        }

        res.json({
          success: true,
          message:
            "Thank you! Your appointment has been saved.",
          appointmentId:
            this.lastID
        });

      }
    );

  }
);


// ==========================
// Admin login page
// ==========================

app.get(
  "/admin/login",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "admin-login.html"
      )
    );

  }
);


// ==========================
// Admin login
// ==========================

app.post(
  "/api/admin/login",
  (req, res) => {

    const ip =
      getClientIP(req);

    if (
      isLoginBlocked(ip)
    ) {

      return res.status(429).json({
        success: false,
        message:
          "Too many failed login attempts. Please try again in 15 minutes."
      });

    }

    const {
      username,
      password
    } = req.body;

    if (
      !username ||
      !password
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Username and password are required."
      });

    }

    db.get(
      "SELECT * FROM admins WHERE username = ?",
      [username],
      (error, admin) => {

        if (error) {

          console.error(
            "Login database error:",
            error.message
          );

          return res.status(500).json({
            success: false,
            message:
              "Login service unavailable."
          });

        }

        if (
          !admin ||
          !verifyPassword(
            password,
            admin.password_hash
          )
        ) {

          recordFailedLogin(ip);

          return res.status(401).json({
            success: false,
            message:
              "Invalid username or password."
          });

        }

        clearLoginAttempts(ip);

        db.run(
          `
            DELETE FROM admin_sessions
            WHERE admin_id = ?
          `,
          [admin.id]
        );

        createSession(
          admin.id,
          res
        );

      }
    );

  }
);


// ==========================
// Admin logout
// ==========================

app.post(
  "/api/admin/logout",
  (req, res) => {

    const token =
      getSessionToken(req);

    if (token) {

      const tokenHash =
        crypto
          .createHash("sha256")
          .update(token)
          .digest("hex");

      db.run(
        `
          DELETE FROM admin_sessions
          WHERE token_hash = ?
        `,
        [tokenHash]
      );

    }

    clearSessionCookie(res);

    res.json({
      success: true,
      message:
        "Logged out successfully."
    });

  }
);


// ==========================
// Current admin
// ==========================

app.get(
  "/api/admin/me",
  requireAdmin,
  (req, res) => {

    res.json({
      success: true,
      admin: {
        id: req.admin.id,
        username:
          req.admin.username
      }
    });

  }
);


// ==========================
// Admin dashboard
// ==========================

app.get(
  "/admin",
  requireAdmin,
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "admin.html"
      )
    );

  }
);


app.get(
  "/admin.html",
  requireAdmin,
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "admin.html"
      )
    );

  }
);


// ==========================
// Get appointments
// ==========================

app.get(
  "/api/appointments",
  requireAdmin,
  (req, res) => {

    db.all(
      `
        SELECT *
        FROM appointments
        ORDER BY created_at DESC
      `,
      [],
      (error, rows) => {

        if (error) {

          console.error(
            "Fetch error:",
            error.message
          );

          return res.status(500).json({
            success: false,
            message:
              "Could not load appointments."
          });

        }

        res.json(rows);

      }
    );

  }
);


// ==========================
// Update appointment status
// ==========================

app.put(
  "/api/appointments/:id/status",
  requireAdmin,
  (req, res) => {

    const id =
      req.params.id;

    const {
      status
    } = req.body;

    const allowedStatuses = [
      "pending",
      "approved",
      "rejected"
    ];

    if (
      !allowedStatuses.includes(
        status
      )
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Invalid status."
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
            error.message
          );

          return res.status(500).json({
            success: false,
            message:
              "Could not update appointment."
          });

        }

        if (
          this.changes === 0
        ) {

          return res.status(404).json({
            success: false,
            message:
              "Appointment not found."
          });

        }

        res.json({
          success: true,
          message:
            "Appointment status updated."
        });

      }
    );

  }
);


// ==========================
// Delete appointment
// ==========================

app.delete(
  "/api/appointments/:id",
  requireAdmin,
  (req, res) => {

    const id =
      req.params.id;

    db.run(
      `
        DELETE FROM appointments
        WHERE id = ?
      `,
      [id],
      function (error) {

        if (error) {

          console.error(
            "Delete error:",
            error.message
          );

          return res.status(500).json({
            success: false,
            message:
              "Could not delete appointment."
          });

        }

        if (
          this.changes === 0
        ) {

          return res.status(404).json({
            success: false,
            message:
              "Appointment not found."
          });

        }

        res.json({
          success: true,
          message:
            "Appointment deleted."
        });

      }
    );

  }
);


// ==========================
// Clean expired sessions
// ==========================

setInterval(
  () => {

    db.run(
      `
        DELETE FROM admin_sessions
        WHERE expires_at < ?
      `,
      [Date.now()]
    );

  },
  60 * 60 * 1000
);


// ==========================
// Clean appointment rate-limit records
// ==========================

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of appointmentAttempts) {
    if (now - record.windowStart >= APPOINTMENT_WINDOW) {
      appointmentAttempts.delete(ip);
    }
  }
}, 10 * 60 * 1000);


// ==========================
// Clean login attempts
// ==========================

setInterval(
  () => {

    const now =
      Date.now();

    for (
      const [
        ip,
        record
      ] of loginAttempts
    ) {

      if (
        record.blockedUntil &&
        now >=
          record.blockedUntil
      ) {

        loginAttempts.delete(
          ip
        );

      }

    }

  },
  10 * 60 * 1000
);


// ==========================
// Static website files
// ==========================

// Only the public directory is exposed. Server code, package files, and the
// SQLite database stay outside the public web root.
app.use(
  express.static(
    path.join(__dirname, "public"),
    {
      index: "index.html",
      dotfiles: "deny"
    }
  )
);


// ==========================
// JSON 404 handler for unknown API routes
// ==========================

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      success: false,
      message: "API endpoint not found."
    });
  }
  next();
});


// ==========================
// Start server
// ==========================

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "================================="
    );

    console.log(
      "Doctor website is running!"
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      "================================="
    );

  }
);