const db = require("../config/db");

const UserModel = {
    findByEmail: (email) => {
        return new Promise((resolve, reject) => {
            db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });
    },

    createUser: (name, email, hashedPassword) => {
        return new Promise((resolve, reject) => {
            db.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });
    },

    updateResetToken: (email, resetToken) => {
        return new Promise((resolve, reject) => {
            db.query("UPDATE users SET reset_token = ? WHERE email = ?", [resetToken, email], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });
    },

    updatePassword: (token, hashedPassword) => {
        return new Promise((resolve, reject) => {
            db.query("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?", [hashedPassword, token], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });
    },
};

module.exports = UserModel;
