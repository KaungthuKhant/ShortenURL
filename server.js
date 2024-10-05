if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const shortId = require('shortid');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const QRCode = require('qrcode');
const mongoose = require("mongoose");

const config = require('./config');
const User = require("./models/User");
const Url = require("./models/URL");
const { checkPassword, sendConfirmationEmail, sendClickCountReachedEmail } = require('./utils');
const { checkAuthenticated, checkNotAuthenticated } = require('./middleware');

const app = express();

mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost/ShortURLPractice");

const initializePassport = require('./passport-config');
initializePassport(
    passport,
    email => User.findOne({ email}),
    id => User.findById(id),
    saveUser
);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
app.use(express.static('public'));

// Middleware to disable DNS prefetching for all routes
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

async function saveUser(name, email, password, googleId) {
    const user = new User({
        name,
        email,
        password,
        googleId,
        confirmationID: crypto.randomBytes(16).toString('hex')
    });
    await user.save();
    console.log(user);
    return user;
}

async function saveLink(fullLink, shortLink, userId, expirationDate, clickCountsToNotify) {
    const existingLink = await Url.findOne({ shortUrl: shortLink });
    if (existingLink) {
        console.log("Short URL already used");
        return null;
    }

    const expiryDate = expirationDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const link = new Url({
        fullUrl: fullLink,
        shortUrl: shortLink,
        userId: userId,
        urlExpirationDate: expiryDate,
        clickCountToSendEmail: Number(clickCountsToNotify),
    });

    await link.save();
    console.log(link);
    return link;
}

app.get('/', checkAuthenticated, async (req, res) => {
    const links = await Url.find({ userId: req.user._id });
    res.render('index.ejs', { name: req.user.name, urls: links });
});

app.get('/fetch-urls', checkAuthenticated, async (req, res) => {
    try {
        const links = await Url.find({ userId: req.user._id });
        res.json({ urls: links });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch URLs' });
    }
});

app.post('/qr-code', async (req, res) => {
    try {
        const { shortUrl } = req.body;
        const user = await Url.findOne({ shortUrl });

        if (!user) {
            return res.status(404).send('URL not found');
        }

        const fullShortUrl = `${process.env.SERVER}${shortUrl}`;
        const qrCode = await QRCode.toDataURL(user.fullUrl);

        res.render('link-details', {
            fullUrl: user.fullUrl,
            shortUrl: fullShortUrl,
            clicks: user.clicks,
            qrCode,
            expirationDate: user.urlExpirationDate
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        // Check if the password meets the requirements
        if (!checkPassword(req.body.password)) {
            return res.render('register', { 
                message: "Password must contain at least one uppercase letter, one lowercase letter, one number, and be at least 8 characters long."
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            return res.render('register', { message: "Email already in use" });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const confirmationID = crypto.randomBytes(16).toString('hex');
        
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            confirmationID: confirmationID
        });
        await user.save();
        
        sendConfirmationEmail(user.email, confirmationID);
        
        res.redirect('/confirmation');
    } catch (error) {
        console.error(error);
        res.render('register', { message: "An error occurred during registration" });
    }
});

app.get('/confirmation', (req, res) => {
    res.render('confirmation');
});

app.get('/confirm/:randomID', async (req, res) => {
    try {
        const user = await User.findOneAndUpdate(
            { confirmationID: req.params.randomID },
            { isConfirmed: true },
            { new: true }
        );

        if (!user) {
            return res.status(404).send('User not found');
        }

        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error confirming email');
    }
});

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

app.post('/forgot-password', forgotPassword);

app.get('/reset-password/:id', async (req, res) => {
    const { id } = req.params;
    const user = await User.findOne({ confirmationID: id });
    if (!user) {
        return res.status(404).send('User not found');
    }
    if (user.resetPasswordExpires < Date.now()) {
        return res.status(400).send('Password reset link has expired');
    }
    res.render('reset-password', { id });
});

app.post('/reset-password', resetPassword);

app.get('/auth/google',
    passport.authenticate('google', { 
        scope: ['profile', 'email'],
        max_age: 2592000 // 30 days in seconds
    })
);

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/');
    }
);

app.post('/shortUrls', async (req, res) => {
    let short = req.body.shortUrl || await shortId.generate();
    const expirationDate = req.body.expirationDate ? new Date(req.body.expirationDate) : null;

    const link = await saveLink(req.body.fullUrl, short, req.user._id, expirationDate, req.body.clickCountsToNotify);
    if (!link) {
        return res.status(400).send('Short URL already in use');
    }
    res.redirect('/');
});

app.get('/:shortUrl', async (req, res) => {
    /* the following line is to prevent the browser from prefetching the url
     * When the user paste a link in the browser, the browser will prefetch the url
     * this cause this route to be called and increase the click by one
     * when the user actually click enter and go to the shortUrl, this route gets call agian
     * increasing the click one more time so when the user go to the shortUrl by pasting
     * the amount of click is increase by 2, to prevent that, we need to stop browser from prefatching the url
     * 
     * it is a hack, but it works       
     */         
    const purpose = req.get('Purpose') || req.get('X-Purpose');
  
    if (purpose === 'prefetch' || purpose === 'preview') {
        return res.status(204).end();
    }
    
    const result = await Url.findOneAndUpdate(
        { shortUrl: req.params.shortUrl },
        { $inc: { clicks: 1 } },
        { new: true }
    );

    if (!result) return res.sendStatus(404);

    if (result.clicks % result.clickCountToSendEmail === 0) {
        sendClickCountReachedEmail(result);
    }

    res.redirect(result.fullUrl);
});

app.post('/delete-url', async (req, res) => {
    await Url.deleteOne({ shortUrl: req.body.shortUrl });
    res.redirect('/');
});

app.post('/updateFullURL', async (req, res) => {
    const { fullUrl, shortUrl } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");
    try {
        const user = await Url.findOneAndUpdate(
            { shortUrl: short },
            { fullUrl: fullUrl },
            { new: true }
        );
        
        if (!user) {
            console.log('URL not found when searching using shortUrl ', short);
            return res.json({ success: false, message: 'URL not found' });
        }
        
        console.log('URL updated successfully');
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating URL:', error);
        res.json({ success: false, message: 'Failed to update URL' });
    }
});

app.post('/updateShortUrl', async (req, res) => {
    console.log('Received update request: ', req.body.originalShortUrl);
    const { shortUrl, originalShortUrl } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");
    const original = originalShortUrl.replace(process.env.SERVER, "");
    try {
        const existingUrl = await Url.findOne({ shortUrl: short });
        if (existingUrl) {
            return res.json({ success: false, message: 'Short URL already exists' });
        }

        const url = await Url.findOneAndUpdate(
            { shortUrl: original },
            { shortUrl: short },
            { new: true }
        );

        if (!url) {
            return res.json({ success: false, message: 'URL not found' });
        }
        console.log('URL updated successfully');
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating URL:', error);
        res.json({ success: false, message: 'Failed to update URL' });
    }
});

app.delete('/logout', function(req, res, next) {
    req.logOut(function(err){
        if (err) { return next(err); }
        res.redirect('/login');
    });
});

const transporter = nodemailer.createTransport({
    service: config.email.service,
    auth: {
      user: config.email.user,
      pass: config.email.pass,
    },
});

async function forgotPassword(req, res) {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send('User not found');
    }
    const randomID = crypto.randomBytes(32).toString('hex');
    user.confirmationID = randomID;
    user.resetPasswordExpires = Date.now() + 600000; // 10 minutes
    await user.save();
    const link = `http://localhost:${config.server.port}/reset-password/${randomID}`;
    const mailOptions = {
      from: config.email.user,
      to: user.email,
      subject: 'Reset Password',
      text: `Click on this link to reset your password: ${link}\nThe password reset link expires in 10 minutes.`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });
    res.render('confirmation');
}

async function resetPassword(req, res) {
    const { id, password, confirmPassword } = req.body;

    if (!checkPassword(password)) {
        return res.render('reset-password', {id: id, message: "Password is not valid. Password must contain at least one uppercase letter, one lowercase letter, one number and 8 or more characters." });
    }

    if (password !== confirmPassword) {
      return res.status(400).send('Passwords do not match');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.findOneAndUpdate(
        { confirmationID: id },
        { password: hashedPassword },
        { new: true }
    );
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.send('Password reset successfully');
} 

app.listen(process.env.PORT);
console.info("Listening on port "+ process.env.PORT);

// Check for expired URLs every hour and remove them
setInterval(async () => {
    const now = new Date();
    try {
        console.log("Checking for expired URLs...");
        const result = await Url.deleteMany({ urlExpirationDate: { $lt: now } });
        console.log(`${result.deletedCount} expired links deleted.`);
    } catch (error) {
        console.error("Error checking for expired URLs:", error);
    }
}, 60 * 60 * 1000); // Run every hour