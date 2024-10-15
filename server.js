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
const User = require("./models/User");
const Url = require("./models/Url");
const { checkPassword, sendConfirmationEmail, sendClickCountReachedEmail, isValidUrl, checkUrlExists } = require('./utils');
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
async function saveLink(fullLink, shortLink, userId, expirationDate, clickCountsToNotify) {
    // Check if the short URL already exists
    const existingLink = await Url.findOne({ shortUrl: shortLink });
    if (existingLink) {
        console.log("Short URL already in use:", shortLink);
        return null;
    }

    // Set expiration date to 7 days from now if not provided
    const expiryDate = expirationDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    // Create a new Url instance
    const link = new Url({
        fullUrl: fullLink,
        shortUrl: shortLink,
        userId: userId,
        urlExpirationDate: expiryDate,
        clickCountToSendEmail: Number(clickCountsToNotify),
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
        urls: links,
        error: req.query.error || null,
        fullUrl: req.query.fullUrl || '',
        shortUrl: req.query.shortUrl || '',
        clickCountsToNotify: req.query.clickCountsToNotify || '',
        expirationDate: req.query.expirationDate || ''
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
    const timeout = req.query.timeout === 'true';
    res.render('login.ejs', { 
        timeout: timeout,
        message: timeout ? 'Your session has expired. Please log in again.' : null
    });
});

// Route: Handle login
/*
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));
*/
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
    let fullUrl = req.body.fullUrl;
    let short = req.body.shortUrl;
    let clickCountsToNotify = req.body.clickCountsToNotify;
    let expirationDate = req.body.expirationDate ? new Date(req.body.expirationDate) : null;
    let userEmail = req.body.userEmail;

    // Validate URL format
    if (!isValidUrl(fullUrl)) {
        return res.redirect('/?error=' + encodeURIComponent('Invalid URL format') +
        '&fullUrl=' + encodeURIComponent(fullUrl) +
        '&shortUrl=' + encodeURIComponent(short) +
        '&clickCountsToNotify=' + encodeURIComponent(clickCountsToNotify) +
        '&expirationDate=' + encodeURIComponent(req.body.expirationDate));
    }

    try {
        // Check if the URL exists by performing a DNS lookup
        const urlExists = await checkUrlExists(fullUrl);
        if (!urlExists) {
            return res.redirect('/?error=' + encodeURIComponent('The provided URL does not exist or is not accessible') +
            '&fullUrl=' + encodeURIComponent(fullUrl) +
            '&shortUrl=' + encodeURIComponent(short) +
            '&clickCountsToNotify=' + encodeURIComponent(clickCountsToNotify) +
            '&expirationDate=' + encodeURIComponent(req.body.expirationDate));
        }

        // Get the user id from the email
        const user = await User.findOne({ email: userEmail });
        if (!user) {
            return res.redirect('/?error=' + encodeURIComponent('User not found'));
        }
        const userId = user._id;

        const link = await saveLink(fullUrl, short, userId, expirationDate, clickCountsToNotify);
        if (!link) {
            return res.redirect('/?error=' + encodeURIComponent('Short URL already in use') +
            '&fullUrl=' + encodeURIComponent(fullUrl) +
            '&shortUrl=' + encodeURIComponent(short) +
            '&clickCountsToNotify=' + encodeURIComponent(clickCountsToNotify) +
            '&expirationDate=' + encodeURIComponent(req.body.expirationDate));
        }
        res.redirect('/');
    } catch (error) {
        console.error('Error creating short URL:', error);
        res.redirect('/?error=' + encodeURIComponent('An error occurred while creating the short URL') +
        '&fullUrl=' + encodeURIComponent(fullUrl) +
        '&shortUrl=' + encodeURIComponent(short) +
        '&clickCountsToNotify=' + encodeURIComponent(clickCountsToNotify) +
        '&expirationDate=' + encodeURIComponent(req.body.expirationDate));
    }
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

// Route: Update notify user
app.post('/updateNotifyUser', async (req, res) => {
    console.log('Received update notify user request:', req.body);
    const { shortUrl, notifyUser, notifyHoursBefore } = req.body;
    const short = shortUrl.replace(process.env.SERVER, "");

    try {
        const url = await Url.findOneAndUpdate(
            { shortUrl: short },
            { notifyUser: notifyUser, notifyHoursBefore: notifyHoursBefore },
            { new: true }       // Return the updated document
        );

        if (!url) {
            console.log('URL not found when updating notifyUser:', short);
            return res.json({ success: false, message: 'URL not found' });
        }

        console.log('Notify user updated successfully for:', short);
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating notify user:', error);
        res.json({ success: false, message: 'Failed to update notify user' });
    }
});



// ===========================================================================================================================================================
// Route: Check session validity
app.get('/check-session', (req, res) => {
    // Check if session and lastActivity exist
    if (req.session && req.session.lastActivity) {
        const currentTime = Date.now();
        const timeSinceLastActivity = currentTime - req.session.lastActivity;
        
        // Check if session has expired (30 minutes of inactivity)
        if (timeSinceLastActivity > parseInt(process.env.SESSION_TIMEOUT) * 60 * 1000) { 
            // Destroy the session if it has expired
            req.session.destroy((err) => {
                if (err) {
                    console.error('Session destruction error:', err);
                }
                // Respond with invalid session status
                res.json({ valid: false });
            });
        } else {
            // Update last activity time and respond with valid session status
            req.session.lastActivity = currentTime;
            res.json({ valid: true });
        }
    } else {
        // If there's no session or lastActivity, consider it invalid
        res.json({ valid: false });
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