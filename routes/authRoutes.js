const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const db = require("../config/db");
const config = require("../config/config");

const router = express.Router();

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    service: config.mailer.service,
    auth: config.mailer.auth
});


//User Registration

router.post(
    "/register",
    [
        body("name").notEmpty().withMessage("Name is required"),
        body("email").isEmail().withMessage("Invalid email format"),
        body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword],
            (err, result) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: "User registered successfully" });
            }
        );
    }
);


//User Login

router.post(
    "/login",
    [
        body("email").isEmail().withMessage("Invalid email format"),
        body("password").notEmpty().withMessage("Password is required"),
    ],
    async (req, res) => {
        const { email, password } = req.body;

        db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            if (results.length === 0) return res.status(401).json({ message: "Invalid credentials" });

            const user = results[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

            const token = jwt.sign({ id: user.id, email: user.email }, config.jwtSecret, { expiresIn: "1h" });

            res.json({ message: "Login successful", token });
        });
    }
);


//Forgot Password - Send Reset Link

router.post(
    "/forgot-password",
    [body("email").isEmail().withMessage("Invalid email format")],
    (req, res) => {
        const { email } = req.body;
        const resetToken = crypto.randomBytes(20).toString("hex");
        const resetTokenExpiry = Date.now() + 3600000; // Token valid for 1 hour

        db.query(
            "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
            [resetToken, resetTokenExpiry, email],
            async (err, result) => {
                if (err) return res.status(500).json({ error: err.message });
                if (result.affectedRows === 0) return res.status(404).json({ message: "Email not found" });

                const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;
                const mailOptions = {
                    from: config.mailer.auth.user,
                    to: email,
                    subject: "Password Reset Request",
                    text: `Click the link to reset your password: ${resetLink}. This link is valid for 1 hour.`,
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) return res.status(500).json({ error: error.message });
                    res.json({ message: "Reset link sent to email", resetLink });
                });
            }
        );
    }
);


//Reset Password

router.post(
    "/reset-password",
    [
        body("token").notEmpty().withMessage("Reset token is required"),
        body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
    ],
    async (req, res) => {
        const { token, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = ? AND reset_token_expiry > ?",
            [hashedPassword, token, Date.now()],
            (err, result) => {
                if (err) return res.status(500).json({ error: err.message });
                if (result.affectedRows === 0)
                    return res.status(400).json({ message: "Invalid or expired token" });

                res.json({ message: "Password reset successfully" });
            }
        );
    }
);

module.exports = router;
