const nodemailer = require("nodemailer");
const config = require("../config/config");

const transporter = nodemailer.createTransport({
    service: config.mailer.service,
    auth: config.mailer.auth
});

exports.sendResetEmail = (email, resetLink) => {
    const mailOptions = {
        from: config.mailer.auth.user,
        to: email,
        subject: "Password Reset Request",
        text: `Click the link to reset your password: ${resetLink}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Error sending email:", error);
        } else {
            console.log("Password reset email sent:", info.response);
        }
    });
};
