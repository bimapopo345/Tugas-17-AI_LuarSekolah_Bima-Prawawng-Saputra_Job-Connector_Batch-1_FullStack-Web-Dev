const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const db = new sqlite3.Database("./db/presensi.db");

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);
app.set("view engine", "ejs");

// Initialize Database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )`);

  db.run(`CREATE TABLE IF NOT EXISTS presensi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        clock_in TEXT,
        clock_out TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

  // Insert admin user if not exists
  db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync("admin123", 10);
      db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [
        "admin",
        hashedPassword,
        "admin",
      ]);
    }
  });
});

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req, res, next) {
  if (req.session.role === "admin") {
    next();
  } else {
    res.redirect("/dashboard");
  }
}

// Routes

// Home Route
app.get("/", (req, res) => {
  res.redirect("/login");
});

// Login Routes
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.userId = user.id;
      req.session.role = user.role;
      if (user.role === "admin") {
        res.redirect("/admin");
      } else {
        res.redirect("/dashboard");
      }
    } else {
      res.render("login", { error: "Invalid credentials" });
    }
  });
});

// Logout Route
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// Dashboard Route
app.get("/dashboard", isAuthenticated, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin");
  }
  db.get(
    `SELECT clock_in, clock_out FROM presensi WHERE user_id = ? ORDER BY id DESC LIMIT 1`,
    [req.session.userId],
    (err, presensi) => {
      res.render("dashboard", { presensi });
    }
  );
});

// Clock In Route
app.post("/clock_in", isAuthenticated, (req, res) => {
  // Check if already clocked in
  db.get(
    `SELECT * FROM presensi WHERE user_id = ? AND clock_out IS NULL`,
    [req.session.userId],
    (err, row) => {
      if (row) {
        res.redirect("/dashboard");
      } else {
        const clockInTime = new Date().toISOString();
        db.run(
          `INSERT INTO presensi (user_id, clock_in) VALUES (?, ?)`,
          [req.session.userId, clockInTime],
          function (err) {
            res.redirect("/dashboard");
          }
        );
      }
    }
  );
});

// Clock Out Route
app.post("/clock_out", isAuthenticated, (req, res) => {
  const clockOutTime = new Date().toISOString();
  db.run(
    `UPDATE presensi SET clock_out = ? WHERE user_id = ? AND clock_out IS NULL`,
    [clockOutTime, req.session.userId],
    function (err) {
      res.redirect("/dashboard");
    }
  );
});

// Admin Dashboard Route
app.get("/admin", isAuthenticated, isAdmin, (req, res) => {
  db.all(
    `SELECT users.id, users.username, presensi.clock_in, presensi.clock_out 
            FROM presensi 
            JOIN users ON presensi.user_id = users.id 
            ORDER BY presensi.id DESC`,
    [],
    (err, rows) => {
      res.render("admin", { presensi: rows });
    }
  );
});

// Edit User Route
app.get("/admin/edit/:id", isAuthenticated, isAdmin, (req, res) => {
  const userId = req.params.id;
  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
    res.render("edit_user", { user });
  });
});

app.post("/admin/edit/:id", isAuthenticated, isAdmin, (req, res) => {
  const userId = req.params.id;
  const { username, role } = req.body;
  db.run(
    `UPDATE users SET username = ?, role = ? WHERE id = ?`,
    [username, role, userId],
    function (err) {
      res.redirect("/admin");
    }
  );
});

// Tambahkan setelah route Edit User

// Add User Route
app.get("/admin/add", isAuthenticated, isAdmin, (req, res) => {
  res.render("add_user", { error: null });
});

app.post("/admin/add", isAuthenticated, isAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.render("add_user", { error: "All fields are required." });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
    [username, hashedPassword, role],
    function (err) {
      if (err) {
        return res.render("add_user", { error: "Username already exists." });
      }
      res.redirect("/admin");
    }
  );
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
