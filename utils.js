const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const dns = require('dns');
const { URL } = require('url');

// Load environment variables from .env file
dotenv.config();

// Access environment variables using process.env
const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASS;
const emailService = process.env.EMAIL_SERVICE;
const serverUrl = process.env.SERVER;

// Validate that these environment variables are set
if (!emailUser || !emailPass || !emailService || !serverUrl) {
    console.error('Missing required environment variables. Check .env file.');
    process.exit(1);
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (err) {
        return false;
    }
}

// Verify whether a given URL is accessible or exists by performing a DNS (Domain Name System) lookup
function checkUrlExists(url) {
    return new Promise((resolve) => {
        const hostname = new URL(url).hostname;
        dns.lookup(hostname, (err) => {
            if (err) {
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

function checkPassword(password) {
    // At least 8 characters long
    // Contains at least one lowercase letter, one uppercase letter, and one digit
    // Allows special characters
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[\w\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]{8,}$/;
    return passwordRegex.test(password);
}

const transporter = nodemailer.createTransport({
    service: emailService,
    auth: {
        user: emailUser,
        pass: emailPass,
    },
});

function sendConfirmationEmail(email, confirmationID) {
    const mailOptions = {
        from: emailUser,
        to: email,
        subject: 'Confirm Your Email',
        text: `Please click on this link to confirm your email: ${serverUrl}confirm/${confirmationID}`
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
        from: emailUser,
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

function checkSession(req) {
    if (req.session && req.session.lastActivity) {
        const currentTime = Date.now();
        const timeSinceLastActivity = currentTime - req.session.lastActivity;

        if (timeSinceLastActivity > parseInt(process.env.SESSION_TIMEOUT) * 60 * 1000) {
            return { valid: false, destroy: true };
        } else {
            req.session.lastActivity = currentTime;
            return { valid: true };
        }
    }
    return { valid: false };
}

module.exports = {
    isValidUrl,
    checkSession,
    checkUrlExists,
    checkPassword,
    sendConfirmationEmail,
    sendClickCountReachedEmail
};