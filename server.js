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
const rateLimit = require('express-rate-limit');

// Import local modules and configurations
const User = require("./models/User");
const Url = require("./models/Url");
const { sendConfirmationEmail, sendClickCountReachedEmail, isValidUrl, checkUrlExists, checkPassword, checkSession } = require('./utils');
const { checkAuthenticated, checkNotAuthenticated, sessionTimeout } = require('./middleware');

// Initialize Express app
const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI);
console.log('Connected to MongoDB');

// Initialize Passport configuration
const initializePassport = require('./passport-config');
initializePassport(
    passport,
    email => User.findOne({ email}),
    id => User.findById(id),
    saveUser
);

// Reserved routes
const reservedRoutes = [
    'shortUrls', 'delete-url', 'updateFullURL', 'updateShortUrl', 'updateNotifyUser',
    'updateExpirationDate', 'updateRedirectionLimit', 'updateUrlPassword',
    'updateCustomMessage', 'check-session', 'logout', 'login', 'forgot-password',
    'reset-password', 'auth', 'register', 'confirmation', 'home', 'auth/google', 'auth/google/callback',
    'url-details', 'fetch-urls', 'check-session', 'confirm'
];

// Set up view engine and middleware
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        // Use secure cookies in production, this will send the cookie only over HTTPS
        // if secure is false, the cookie will be sent over HTTP
        secure: process.env.NODE_ENV === 'production', 
        maxAge: parseInt(process.env.SESSION_TIMEOUT) * 60 * 1000 // Convert minutes to milliseconds
    }
}));
app.use('/authenticated-routes', sessionTimeout); // Apply to all routes that require authentication
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
app.use(express.static('public'));

// Middleware to disable DNS prefetching for all routes
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Apply to all requests
app.use(limiter);

/**
 * Function to save a new user
 * 
 * This function creates a new User document in the database with the provided information.
 * It generates a unique confirmation ID for email verification purposes.
 * 
 * @param {string} name - The user's name
 * @param {string} email - The user's email address
 * @param {string} password - The user's password (should be pre-hashed)
 * @param {string} googleId - The user's Google ID (if using Google OAuth)
 * @returns {Promise<User>} The saved user document
 */
async function saveUser(name, email, password, googleId) {
    // Create a new User instance with provided data
    const user = new User({
        name,
        email,
        password,
        googleId,
        confirmationID: crypto.randomBytes(16).toString('hex') // Generate a unique confirmation ID
    });
    
    // Save the user to the database
    await user.save();
    console.log('New user saved:', user.email);
    return user;
}

/**
 * Function to save a new short link
 * 
 * This function creates a new Url document in the database, representing a shortened URL.
 * It checks for existing short URLs to avoid duplicates and sets an expiration date if provided.
 * 
 * @param {string} fullLink - The original, full URL
 * @param {string} shortLink - The generated short URL
 * @param {string} userId - The ID of the user creating this link
 * @param {Date} expirationDate - The date when this link should expire (optional)
 * @param {number} clickCountsToNotify - The number of clicks after which to notify the user
 * @returns {Promise<Url|null>} The saved Url document, or null if the short URL already exists
 */
async function saveLink(fullLink, shortLink, userId) {
    // Check if the short URL already exists
    const existingLink = await Url.findOne({ shortUrl: shortLink });
    if (existingLink) {
        console.log("Short URL already in use:", shortLink);
        return null;
    }

    // Set expiration date to 7 days from now
    const expiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    // Create a new Url instance
    const link = new Url({
        fullUrl: fullLink,
        shortUrl: shortLink,
        userId: userId,
        urlExpirationDate: expiryDate
    });

    // Save the link to the database
    await link.save();
    console.log('New link saved:', link.shortUrl);
    return link;
}

// Route: Home page
app.get('/', checkAuthenticated, async (req, res) => {
    const links = await Url.find({ userId: req.user._id });
    res.render('index.ejs', { 
        req: req,
        name: req.user.name, 
        email: req.user.email, 
        urls: links
    });
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
app.get('/url-details', checkAuthenticated, async (req, res) => {
    console.log("url-details called for: ", req.query.shortUrl);
    try {
        const { shortUrl } = req.query;
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
            expirationDate: url.urlExpirationDate,
            notifyUser: url.notifyUser,
            notifyHoursBefore: url.expirationNotificationHours,
            redirectionLimit: url.redirectionLimit,
            customMessage: url.customMessage,
            password: url.password
        });
    } catch (error) {
        console.error('Error generating QR code:', error);
        res.status(500).send('Server error');
    }
});

// Route: Login page
app.get('/login', checkNotAuthenticated, (req, res) => {
    let message = null;
    let isTimeout = false;

    // Check if this is a first-time login attempt
    const isFirstTimeLogin = !req.session || !req.session.lastActivity;

    if (!isFirstTimeLogin) {
        const sessionStatus = checkSession(req);

        if (!sessionStatus.valid) {
            if (sessionStatus.destroy) {
                req.session.destroy((err) => {
                    if (err) console.error('Session destruction error:', err);
                });
            }
            message = 'Your session has expired. Please log in again.';
            isTimeout = true;
        }
    }

    // If it's not a timeout, check for other messages
    if (!isTimeout) {
        if (req.session && req.session.message) {
            // If there's a message in the session, flash it and remove it
            message = req.session.message;
            req.flash('success', message);
            delete req.session.message;
        } else {
            // Check for flash messages
            const successMessages = req.flash('success');
            if (successMessages.length > 0) {
                message = successMessages[0];
            }
        }
    }

    console.log('Message:', message);

    res.render('login.ejs', { 
        timeout: isTimeout,
        message: message
    });
});

app.post('/login', passport.authenticate('local', {
    failureRedirect: '/login', 
    failureFlash: true
}), (req, res) => {
    req.session.lastActivity = Date.now();
    res.redirect('/');
});

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
        req.session.message = 'Email confirmed successfully.';
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
    let { fullUrl, shortUrl, userEmail } = req.body;
    
    // Add https:// if it's missing
    if (!/^https?:\/\//i.test(fullUrl)) {
        fullUrl = 'https://' + fullUrl.replace(/^(www\.)?/, 'www.');
    }

    // Check if the short URL is reserved
    if (reservedRoutes.includes(shortUrl)) {
        console.log('Short URL is reserved:', shortUrl);
        return res.status(400).json({
            error: 'This short URL is reserved. Please choose a different one.',
            errorComponent: 'short_url'
        });
    }

    // Validate URL format
    if (!isValidUrl(fullUrl)) {
        return res.status(400).json({
            error: 'Invalid URL format',
            errorComponent: 'full_url'
        });
    }

    try {
        // Check if the URL exists by performing a DNS lookup
        const urlExists = await checkUrlExists(fullUrl);
        if (!urlExists) {
            return res.status(400).json({
                error: 'The provided URL does not exist or is not accessible',
                errorComponent: 'full_url'
            });
        }

        // Get the user id from the email
        const user = await User.findOne({ email: userEmail });
        if (!user) {
            return res.status(400).json({
                error: 'User not found',
                errorComponent: 'user'
            });
        }
        const userId = user._id;

        const link = await saveLink(fullUrl, shortUrl, userId);
        if (!link) {
            return res.status(400).json({
                error: 'Short URL already in use',
                errorComponent: 'short_url'
            });
        }

        // Fetch all URLs for this user to send back
        const urls = await Url.find({ userId: userId });
        res.json({ success: true, urls: urls });
    } catch (error) {
        console.error('Error creating short URL:', error);
        res.status(500).json({
            error: 'An error occurred while creating the short URL',
            errorComponent: 'server'
        });
    }
});

// Route: Delete URL
app.post('/delete-url', checkAuthenticated, async (req, res) => {
    try {
        await Url.deleteOne({ shortUrl: req.body.shortUrl });
        console.log('URL deleted:', req.body.shortUrl);
        
        // Fetch updated URLs
        const urls = await Url.find({ userId: req.user._id });
        
        res.json({ success: true, urls: urls });
    } catch (error) {
        console.error('Error deleting URL:', error);
        res.status(500).json({ success: false, error: 'Failed to delete URL' });
    }
});

// Route: Update full URL
app.post('/updateFullURL', async (req, res) => {
    const { fullUrl, shortUrl } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");

    // Add https:// if it's missing
    if (!/^https?:\/\//i.test(fullUrl)) {
        fullUrl = 'https://' + fullUrl.replace(/^(www\.)?/, 'www.');
    }
    // Validate URL format
    if (!isValidUrl(fullUrl)) {
        return res.json({ success: false, message: 'Invalid URL Format' });
    }

    try {
        // Check if the URL exists by performing a DNS lookup
        const urlExists = await checkUrlExists(fullUrl);
        if (!urlExists) {
            console.log('URL does not exist:', fullUrl);
            return res.json({ success: false, message: 'URL does not exist' });
        }

        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { fullUrl: fullUrl },
            { new: true }
        );
        
        if (!url) {
            console.log('URL not found when searching using shortUrl:', short);
            return res.json({ success: false, message: 'Error updating full URL. Please try again later.' });
        }
        
        const qrCode = await QRCode.toDataURL(url.fullUrl);
        
        console.log('Full URL updated successfully:', short);
        return res.json({ success: true, message: 'Full URL updated successfully.', qrCode: qrCode });
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
        console.log(reservedRoutes);

        // Check if the short URL is reserved
        if (reservedRoutes.includes(short)) {
            return res.json({ success: false, message: 'This short URL is reserved. Please choose a different one.' });
        }

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
        return res.json({ success: true });
    } catch (error) {
        console.error('Error updating short URL:', error);
        return res.json({ success: false, message: 'Failed to update URL' });
    }
});

// Route: Update notify user
app.post('/updateNotifyUser', async (req, res) => {
    console.log('Received update notify user request:', req.body);
    const { shortUrl, notifyUser, notifyHoursBefore } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");

    try {
        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { notifyUser: notifyUser, expirationNotificationHours: notifyHoursBefore },
            { new: true }       // Return the updated document
        );

        if (!url) {
            console.log('URL not found when updating notifyUser:', short);
            return res.json({ success: false, message: 'URL not found' });
        }

        console.log('Notify user updated successfully for:', short);
        const message = notifyUser
            ? `Okay! We will notify you ${notifyHoursBefore} hours before your url expires.`
            : "Alright, no notifications — your inbox is safe from us!";
        res.json({ success: true, message });
    } catch (error) {
        console.error('Error updating notify user:', error);
        res.json({ success: false, message: 'Failed to update notify user' });
    }
});


// Route: Update URL expiration date
app.post('/updateExpirationDate', async (req, res) => {
    console.log('Received update expiration date request:', req.body);
    const { shortUrl, date, time } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");

    try {
        // Combine date and time into a single Date object
        const expirationDate = new Date(`${date}T${time}:00.000+00:00`);

        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { urlExpirationDate: expirationDate },
            { new: true }
        );

        if (!url) {
            console.log('URL not found when updating expiration date:', short);
            return res.json({ success: false, message: 'URL not found' });
        }

        console.log('Expiration date updated successfully for:', short);
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating expiration date:', error);
        res.json({ success: false, message: 'Failed to update expiration date' });
    }
});

// Route: Update redirection limit
app.post('/updateRedirectionLimit', async (req, res) => {
    console.log('Received update redirection limit request:', req.body);
    const { shortUrl, newRedirectionLimit } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");

    try {
        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { redirectionLimit: newRedirectionLimit },
            { new: true }
        );

        if (!url) {
            console.log('URL not found when updating redirection limit:', short);
            return res.json({ success: false, message: 'URL not found' });
        }

        console.log('Redirection limit updated successfully for:', short);
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating redirection limit:', error);
        res.json({ success: false, message: 'Failed to update redirection limit' });
    }
});

// Route: Update URL password
app.post('/updateUrlPassword', async (req, res) => {
    console.log('Received update URL password request:', req.body);
    const { shortUrl, newPassword } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");

    try {
        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { password: newPassword },
            { new: true }
        );

        if (!url) {
            console.log('URL not found when updating password:', short);
            return res.json({ success: false, message: 'URL not found' });
        }

        console.log('Password updated successfully for:', short);
        res.json({ success: true, message: "Password updated successfully." });
    } catch (error) {
        console.error('Error updating URL password:', error);
        res.json({ success: false, message: 'Failed to update URL password' });
    }
});

// Route: Update custom message
app.post('/updateCustomMessage', async (req, res) => {
    console.log('Received update custom message request:', req.body);
    const { shortUrl, newCustomMessage } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");

    try {
        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { customMessage: newCustomMessage },
            { new: true }
        );

        if (!url) {
            console.log('URL not found when updating custom message:', short);
            return res.json({ success: false, message: 'URL not found' });
        }

        console.log('Custom message updated successfully for:', short);
        res.json({ success: true, message: "Custom message updated successfully." });
    } catch (error) {
        console.error('Error updating custom message:', error);
        res.json({ success: false, message: 'Failed to update custom message' });
    }
});




// Route: Check session validity
app.get('/check-session', (req, res) => {
    console.log('Checking session validity');
    const sessionStatus = checkSession(req);
    if (sessionStatus.destroy) {
        req.session.destroy((err) => {
            if (err) console.error('Session destruction error:', err);
            res.json({ valid: false });
        });
    } else {
        res.json(sessionStatus);
    }
});

// Route: Logout
app.delete('/logout', function(req, res, next) {
    req.logOut(function(err){
        if (err) { return next(err); }
        console.log('User logged out');
        res.redirect('/home');
    });
});

// Configure email transporter
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
});


// Route: Redirect short URL to full URL
app.get('/:shortUrl', async (req, res) => {
    /* The following lines prevent the browser from prefetching the URL.
     * When the user pastes a link in the browser, the browser might prefetch the URL,
     * causing this route to be called and increasing the click count by one.
     * When the user actually clicks enter and goes to the shortUrl, this route gets called again,
     * increasing the click count one more time. So when the user goes to the shortUrl by pasting,
     * the click count is increased by 2. To prevent that, we need to stop the browser from prefetching the URL.
     * 
     * It's a hack, but it works.
     */
    const purpose = req.get('Purpose') || req.get('X-Purpose');
  
    if (purpose === 'prefetch' || purpose === 'preview') {
        return res.status(204).end();
    }

    // Find the URL document
    const url = await Url.findOne({ shortUrl: req.params.shortUrl });

    if (!url) {
        console.log('Short URL not found:', req.params.shortUrl);
        return res.sendStatus(404);
    }

    // Check if the URL is password protected
    if (url.password) {
        console.log('Password protected URL:', req.params.shortUrl);
        return res.render('urlPassword.ejs', { shortUrl: req.params.shortUrl, message: "Please enter the password to access this URL.", customMessage: url.customMessage });
    }

    // If not password protected, proceed with redirection
    const result = await Url.findOneAndUpdate(
        { shortUrl: req.params.shortUrl },
        { $inc: { clicks: 1 } },
        { new: true }
    );

    // Check if we need to send a notification email
    if (result.clicks % result.clickCountToSendEmail === 0) {
        sendClickCountReachedEmail(result);
    }

    // Check if the redirection limit has been reached
    if (result.clicks > result.redirectionLimit) {
        console.log('Redirection limit reached for:', req.params.shortUrl);
        return res.render('limitReached', { shortUrl: process.env.SERVER + req.params.shortUrl });
    }

    // All checks passed, redirect to the full URL
    res.redirect(result.fullUrl);
});

app.post('/:shortUrl/verify', async (req, res) => {
    const { password } = req.body;
    const { shortUrl } = req.params;

    const url = await Url.findOne({ shortUrl });

    if (!url) {
        return res.status(404).render('error', { message: 'URL not found' });
    }

    if (url.password !== password) {
        return res.render('urlPassword', { 
            shortUrl: shortUrl, 
            message: 'Incorrect password. Please try again.',
            customMessage: url.customMessage
        });
    }

    // Password is correct, update click count
    const result = await Url.findOneAndUpdate(
        { shortUrl },
        { $inc: { clicks: 1 } },
        { new: true }
    );

    if (result.clicks % result.clickCountToSendEmail === 0) {
        sendClickCountReachedEmail(result);
    }

    // Check if the redirection limit has been reached
    if (result.clicks > result.redirectionLimit) {
        console.log('Redirection limit reached for:', req.params.shortUrl);
        return res.render('limitReached', { shortUrl: process.env.SERVER + req.params.shortUrl });
    }

    // If everything is okay, redirect to the full URL
    res.redirect(result.fullUrl);
});

/**
 * Function to handle forgot password requests
 * 
 * This function generates a unique reset token, saves it to the user's document,
 * and sends an email with a reset link to the user's email address.
 * 
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 */
async function forgotPassword(req, res) {
    const { email } = req.body;
    
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found for forgot password:', email);
      return res.status(404).send('User not found');
    }
    
    // Generate a random reset token
    const randomID = crypto.randomBytes(32).toString('hex');
    user.confirmationID = randomID;
    user.resetPasswordExpires = Date.now() + 600000; // 10 minutes
    await user.save();
    
    // Create the reset link
    const link = `${process.env.SERVER}reset-password/${randomID}`;
    
    // Prepare and send the email
    const mailOptions = {
      from: process.env.EMAIL_USER,
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

/**
 * Function to handle password reset
 * 
 * This function validates the new password, updates the user's password in the database,
 * and sends a confirmation response.
 * 
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 */
async function resetPassword(req, res) {
    const { id, password, confirmPassword } = req.body;

    // Validate the new password
    if (!checkPassword(password)) {
        return res.render('reset-password', {id: id, message: "Password is not valid. Password must contain at least one uppercase letter, one lowercase letter, one number and 8 or more characters." });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).send('Passwords do not match');
    }
    
    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Update the user's password in the database
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

/**
 * Function to check for expired URLs and remove them
 * 
 * This function runs periodically to find and delete expired URLs from the database.
 * It also sends notification emails to users whose URLs have expired.
 */
async function checkForExpiredUrls() {
    const now = new Date();
    try {
        console.log("Checking for expired URLs...");
        
        // Find all expired URLs
        const expiredUrls = await Url.find({ urlExpirationDate: { $lt: now } });
        
        // Notify users and delete expired URLs
        for (const url of expiredUrls) {
            const user = await User.findById(url.userId);
            if (user && user.email) {
                // Prepare and send notification email
                const mailOptions = {
                    from: process.env.EMAIL_USER,
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
        
        // Delete all expired URLs from the database
        const result = await Url.deleteMany({ urlExpirationDate: { $lt: now } });
        console.log(`${result.deletedCount} expired links deleted and users notified.`);
    } catch (error) {
        console.error("Error checking for expired URLs:", error);
    }
}

/**
 * Function to send reminder emails for URLs about to expire
 * 
 * This function runs periodically to find URLs that are about to expire
 * and sends reminder emails to the users who own these URLs.
 */
async function sendExpirationReminders() {
    const now = new Date();
    const twentyFourHoursFromNow = new Date(now.getTime() + 48 * 60 * 60 * 1000);
    try {
        console.log("Checking for URLs about to expire...");
        
        // Find URLs that will expire in the next 48 hours
        const aboutToExpireUrls = await Url.find({ 
            urlExpirationDate: { $gt: now, $lt: twentyFourHoursFromNow } 
        });
        
        // Send reminder emails for each URL about to expire
        for (const url of aboutToExpireUrls) {
            const user = await User.findById(url.userId);
            if (user && user.email) {
                // Prepare and send reminder email
                const mailOptions = {
                    from: process.env.EMAIL_USER,
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
// Run the expired URL function every hour
setInterval(checkForExpiredUrls, 60 * 60 * 1000);


