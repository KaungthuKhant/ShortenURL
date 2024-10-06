// Load environment variables if not in production
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// Import required modules
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

// Import local modules and configurations
const config = require('./config');
const User = require("./models/User");
const Url = require("./models/URL");
const { checkPassword, sendConfirmationEmail, sendClickCountReachedEmail } = require('./utils');
const { checkAuthenticated, checkNotAuthenticated } = require('./middleware');

// Initialize Express app
const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost/ShortURLPractice");
console.log('Connected to MongoDB');

// Initialize Passport configuration
const initializePassport = require('./passport-config');
initializePassport(
    passport,
    email => User.findOne({ email}),
    id => User.findById(id),
    saveUser
);

// Set up view engine and middleware
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

// Function to save a new user
async function saveUser(name, email, password, googleId) {
    const user = new User({
        name,
        email,
        password,
        googleId,
        confirmationID: crypto.randomBytes(16).toString('hex')
    });
    await user.save();
    console.log('New user saved:', user.email);
    return user;
}

// Function to save a new short link
async function saveLink(fullLink, shortLink, userId, expirationDate, clickCountsToNotify) {
    const existingLink = await Url.findOne({ shortUrl: shortLink });
    if (existingLink) {
        console.log("Short URL already in use:", shortLink);
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
    console.log('New link saved:', link.shortUrl);
    return link;
}

// Route: Home page
app.get('/', checkAuthenticated, async (req, res) => {
    const links = await Url.find({ userId: req.user._id });
    res.render('index.ejs', { name: req.user.name, email: req.user.email, urls: links });
});


// Route: Home landing page
app.get('/home', (req, res) => {
    res.render('home.ejs', { message: null });
});

app.post('/checkURL', async (req, res) => {
    const { shortUrl } = req.body;
    const shortUrlAbbr = shortUrl.replace(process.env.SERVER, "");
    try {
        const url = await Url.findOne({ shortUrl: shortUrlAbbr });
        if (url) {
            res.json({ success: true, fullUrl: url.fullUrl });
        } else {
            res.json({ success: false, message: 'Short URL not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});


// Route: Fetch URLs for authenticated user
app.get('/fetch-urls', checkAuthenticated, async (req, res) => {
    try {
        const links = await Url.find({ userId: req.user._id });
        res.json({ urls: links });
    } catch (err) {
        console.error('Error fetching URLs:', err);
        res.status(500).json({ error: 'Failed to fetch URLs' });
    }
});

// Route: Generate QR code for a short URL
app.post('/url-details', async (req, res) => {
    try {
        const { shortUrl } = req.body;
        const url = await Url.findOne({ shortUrl });

        if (!url) {
            console.log('URL not found:', shortUrl);
            return res.status(404).send('URL not found');
        }

        const fullShortUrl = `${process.env.SERVER}${shortUrl}`;
        const qrCode = await QRCode.toDataURL(url.fullUrl);

        res.render('link-details', {
            fullUrl: url.fullUrl,
            shortUrl: fullShortUrl,
            clicks: url.clicks,
            qrCode,
            expirationDate: url.urlExpirationDate
        });
    } catch (error) {
        console.error('Error generating QR code:', error);
        res.status(500).send('Server error');
    }
});

// Route: Login page
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

// Route: Handle login
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

// Route: Registration page
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

// Route: Handle registration
app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        if (!checkPassword(req.body.password)) {
            return res.render('register', { 
                message: "Password must contain at least one uppercase letter, one lowercase letter, one number, and be at least 8 characters long."
            });
        }

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
        
        console.log('New user registered:', user.email);
        res.redirect('/confirmation');
    } catch (error) {
        console.error('Error during registration:', error);
        res.render('register', { message: "An error occurred during registration" });
    }
});

// Route: Confirmation page
app.get('/confirmation', (req, res) => {
    res.render('confirmation');
});

// Route: Confirm email
app.get('/confirm/:randomID', async (req, res) => {
    try {
        const user = await User.findOneAndUpdate(
            { confirmationID: req.params.randomID },
            { isConfirmed: true },
            { new: true }
        );

        if (!user) {
            console.log('User not found for confirmation:', req.params.randomID);
            return res.status(404).send('User not found');
        }

        console.log('User confirmed:', user.email);
        res.redirect('/login');
    } catch (err) {
        console.error('Error confirming email:', err);
        res.status(500).send('Error confirming email');
    }
});

// Route: Forgot password page
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

// Route: Handle forgot password
app.post('/forgot-password', forgotPassword);

// Route: Reset password page
app.get('/reset-password/:id', async (req, res) => {
    const { id } = req.params;
    const user = await User.findOne({ confirmationID: id });
    if (!user) {
        console.log('User not found for password reset:', id);
        return res.status(404).send('User not found');
    }
    if (user.resetPasswordExpires < Date.now()) {
        console.log('Password reset link expired for user:', user.email);
        return res.status(400).send('Password reset link has expired');
    }
    res.render('reset-password', { id });
});

// Route: Handle reset password
app.post('/reset-password', resetPassword);

// Route: Google OAuth login
app.get('/auth/google',
    passport.authenticate('google', { 
        scope: ['profile', 'email'],
        max_age: 2592000 // 30 days in seconds
    })
);

// Route: Google OAuth callback
app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        console.log('User logged in via Google:', req.user.email);
        res.redirect('/');
    }
);

// Route: Create short URL
app.post('/shortUrls', async (req, res) => {
    let short = req.body.shortUrl || await shortId.generate();
    let userEmail = req.body.userEmail;

    // get the user id from the email
    const user = await User.findOne({ email: userEmail });
    const userId = user._id;

    const expirationDate = req.body.expirationDate ? new Date(req.body.expirationDate) : null;

    const link = await saveLink(req.body.fullUrl, short, userId, expirationDate, req.body.clickCountsToNotify);
    if (!link) {
        return res.status(400).send('Short URL already in use');
    }
    res.redirect('/');
});

// Route: Redirect short URL to full URL
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

    if (!result) {
        console.log('Short URL not found:', req.params.shortUrl);
        return res.sendStatus(404);
    }

    if (result.clicks % result.clickCountToSendEmail === 0) {
        sendClickCountReachedEmail(result);
    }

    console.log('Redirecting:', req.params.shortUrl, 'to', result.fullUrl);
    res.redirect(result.fullUrl);
});

// Route: Delete URL
app.post('/delete-url', async (req, res) => {
    await Url.deleteOne({ shortUrl: req.body.shortUrl });
    console.log('URL deleted:', req.body.shortUrl);
    res.redirect('/');
});

// Route: Update full URL
app.post('/updateFullURL', async (req, res) => {
    const { fullUrl, shortUrl } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");
    try {
        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { fullUrl: fullUrl },
            { new: true }
        );
        
        if (!url) {
            console.log('URL not found when searching using shortUrl:', short);
            return res.json({ success: false, message: 'URL not found' });
        }
        
        const qrCode = await QRCode.toDataURL(url.fullUrl);
        
        console.log('Full URL updated successfully:', short);
        res.json({ success: true, qrCode: qrCode });
    } catch (error) {
        console.error('Error updating full URL:', error);
        res.json({ success: false, message: 'Failed to update URL' });
    }
});

// Route: Update short URL
app.post('/updateShortUrl', async (req, res) => {
    console.log('Received update request:', req.body.originalShortUrl);
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
        console.log('Short URL updated successfully:', original, 'to', short);
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating short URL:', error);
        res.json({ success: false, message: 'Failed to update URL' });
    }
});

// Route: Logout
app.delete('/logout', function(req, res, next) {
    req.logOut(function(err){
        if (err) { return next(err); }
        console.log('User logged out');
        res.redirect('/login');
    });
});

// Configure email transporter
const transporter = nodemailer.createTransport({
    service: config.email.service,
    auth: {
      user: config.email.user,
      pass: config.email.pass,
    },
});

// Function to handle forgot password
async function forgotPassword(req, res) {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found for forgot password:', email);
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
        console.error('Error sending password reset email:', error);
      } else {
        console.log('Password reset email sent:', info.response);
      }
    });
    res.render('confirmation');
}

// Function to handle password reset
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
      console.log('User not found for password reset:', id);
      return res.status(404).send('User not found');
    }
    console.log('Password reset successfully for user:', user.email);
    res.send('Password reset successfully');
} 

// Start the server
app.listen(process.env.PORT);
console.log("Server listening on port " + process.env.PORT);

// Check for expired URLs every hour and remove them
setInterval(async () => {
    const now = new Date();
    try {
        console.log("Checking for expired URLs...");
        const expiredUrls = await Url.find({ urlExpirationDate: { $lt: now } });
        
        for (const url of expiredUrls) {
            const user = await User.findById(url.userId);
            if (user && user.email) {
                const mailOptions = {
                    from: config.email.user,
                    to: user.email,
                    subject: 'URL Expired and Deleted',
                    text: `Your shortened URL (${url.fullUrl}) has expired and been deleted.`
                };
                
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending URL expiration email:', error);
                    } else {
                        console.log('URL expiration email sent:', info.response);
                    }
                });
            }
        }
        
        const result = await Url.deleteMany({ urlExpirationDate: { $lt: now } });
        console.log(`${result.deletedCount} expired links deleted and users notified.`);
    } catch (error) {
        console.error("Error checking for expired URLs:", error);
    }
}, 60 * 60 * 1000); // Run every hour

// Function to send reminder emails for URLs about to expire
async function sendExpirationReminders() {
    const now = new Date();
    const twentyFourHoursFromNow = new Date(now.getTime() + 48 * 60 * 60 * 1000);
    try {
        console.log("Checking for URLs about to expire...");
        const aboutToExpireUrls = await Url.find({ 
            urlExpirationDate: { $gt: now, $lt: twentyFourHoursFromNow } 
        });
        
        for (const url of aboutToExpireUrls) {
            const user = await User.findById(url.userId);
            if (user && user.email) {
                const mailOptions = {
                    from: config.email.user,
                    to: user.email,
                    subject: 'URL About to Expire',
                    text: `Your shortened URL (${url.fullUrl}) will expire in less than 48 hours.`
                };
                
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending URL expiration reminder email:', error);
                    } else {
                        console.log('URL expiration reminder email sent:', info.response);
                    }
                });
            }
        }
        
        console.log(`${aboutToExpireUrls.length} users notified about URLs about to expire.`);
    } catch (error) {
        console.error("Error checking for URLs about to expire:", error);
    }
}

// Run the reminder function every 12 hours
setInterval(sendExpirationReminders, 12 * 60 * 60 * 1000);