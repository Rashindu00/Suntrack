const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const db = require("../config/db");
const config = require("../config/config");
const emailService = require("../utils/emailService");

// User Registration
exports.register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPassword], (err, result) => {
            if (err) return res.status(500).json(err);
            res.json({ message: "User registered successfully" });
        });
};

// User Login
exports.login = (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) return res.status(401).json({ message: "Invalid credentials" });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, email: user.email }, config.jwtSecret, { expiresIn: "1h" });
        res.json({ token });
    });
};

// Forgot Password (Send Reset Email)
exports.forgotPassword = (req, res) => {
    const { email } = req.body;
    const resetToken = Math.random().toString(36).substr(2, 10);

    db.query("UPDATE users SET reset_token = ? WHERE email = ?", [resetToken, email], async (err, result) => {
        if (err) return res.status(500).json(err);
        if (result.affectedRows === 0) return res.status(404).json({ message: "Email not found" });

        const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;
        emailService.sendResetEmail(email, resetLink);

        res.json({ message: "Reset link sent to email" });
    });
};

// Reset Password
exports.resetPassword = async (req, res) => {
    const { token, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?",
        [hashedPassword, token], (err, result) => {
            if (err) return res.status(500).json(err);
            if (result.affectedRows === 0) return res.status(400).json({ message: "Invalid or expired token" });

            res.json({ message: "Password reset successfully" });
        });
};
