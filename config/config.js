require('dotenv').config();

module.exports = {
    jwtSecret: process.env.JWT_SECRET || "9db9ef26b0a4b0661079d6ff21fd3b4a392931dd43ae851563486c51c0a07d1cfe6291096f872471e4900ace180fe9959d42c686691cbd3d9f232b59ca7b323f",
    mailer: {
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER, // Your email
            pass: process.env.EMAIL_PASS  // Your email password
        }
    }
};
