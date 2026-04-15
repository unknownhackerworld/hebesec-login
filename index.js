require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// ENV
const PORT = process.env.PORT || 5000;
const BASE_URL = process.env.API_BASE_URL;

// PostgreSQL Pool
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

// =======================
// INIT DB (create table)
// =======================
const initDB = async () => {
  await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            username VARCHAR(150) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
  console.log("✅ Users table ready");
};
initDB();

// =======================
// Auth Middleware
// =======================
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// =======================
// Routes
// =======================

// Health
app.get(`${BASE_URL}/health`, (req, res) => {
  res.json({
    status: "OK",
    uptime: process.uptime(),
    timestamp: new Date(),
  });
});


// hide this, dont reveal in public. READ MORE ABOUT IT IN https://cyberthulir.maattraan.xyz/learn#web
// Register
app.post(`${BASE_URL}/register`, async (req, res) => {
  try {
    const { username, password, name } = req.body;

    if (!name || !username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const userExists = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (userExists.rows.length > 0) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      parseInt(process.env.BCRYPT_SALT_ROUNDS)
    );

    const newUser = await pool.query(
      "INSERT INTO users (name, username, password) VALUES ($1, $2, $3) RETURNING id, username",
      [name, username, hashedPassword]
    );

    res.status(201).json({
      message: "User registered successfully",
      user: newUser.rows[0],
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post(`${BASE_URL}/login`, async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      message: "Login successful",
      token,
    });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});
// Profile (Protected)
app.get(`${BASE_URL}/profile`, authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, username, created_at FROM users WHERE id = $1",
      [req.user.id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Logout (stateless JWT)
app.post(`${BASE_URL}/logout`, (req, res) => {
  res.json({ message: "Logout successful (delete token client-side)" });
});

// =======================
// Global Error Handler
// =======================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong" });
});

// =======================
// Start Server
// =======================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});