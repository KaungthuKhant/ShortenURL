const nodemailer = require('nodemailer');
const config = require('./config');

function checkPassword(password) {
    // At least 8 characters long
    // Contains at least one lowercase letter, one uppercase letter, and one digit
    // Allows special characters
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[\w\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]{8,}$/;
    return passwordRegex.test(password);
}

const transporter = nodemailer.createTransport({
    service: config.email.service,
    auth: {
        user: config.email.user,
        pass: config.email.pass,
    },
});

function sendConfirmationEmail(email, confirmationID) {
    const mailOptions = {
        from: config.email.user,
        to: email,
        subject: 'Confirm Your Email',
        text: `Please click on this link to confirm your email: ${config.server.url}/confirm/${confirmationID}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

function sendClickCountReachedEmail(link) {
    const mailOptions = {
        from: config.email.user,
        to: link.email,
        subject: 'Click Count Reached',
        text: `Your short URL ${link.shortUrl} has reached ${link.clicks} clicks.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

module.exports = {
    checkPassword,
    sendConfirmationEmail,
    sendClickCountReachedEmail
};