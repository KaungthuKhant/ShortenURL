if (process.env.NODE_ENV !== 'production'){
    require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const shortId = require('shortid')
const nodemailer = require('nodemailer');
const config = require('./config');
const crypto = require('crypto');
const QRCode = require('qrcode');

// mongodb requires
const mongoose = require("mongoose")
const User = require("./Users")

mongoose.connect("mongodb://localhost/ShortURLPractice")

async function saveUser(namePara, emailPara, passPara, googleIdPara) {
    const randomID = Math.random().toString(36).substr(2, 9); // generate a random ID
    const user = new User({
        schemaType: "User",
        name: namePara,
        email: emailPara,
        password: passPara,
        googleId: googleIdPara,
        confirmationID: randomID // save the random ID to the user document
    })
    await user.save()
    console.log(user)
    return { user, randomID }; // return the user and the random ID
}

async function saveLink(fullLink, shortLink, clicksParam, emailParam, expirationDate, clickCountsToNotify){
    console.log("searching for smilar results using short url of: " + shortLink)
    console.log("Click count to notify is: " + clickCountsToNotify)
    let searchResults = await findFullUrl(shortLink)
    if (searchResults != null){
        console.log("short url already used")
        return;
    }

    // Set the expiration date to 7 days from now if not provided
    const expiryDate = expirationDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const link = new User({
        schemaType: "Links", 
        fullUrl: fullLink, 
        shortUrl: shortLink, 
        email: emailParam, 
        clicks: clicksParam,
        urlExpirationDate: expiryDate,
        clickCountToSendEmail: Number(clickCountsToNotify),
    })

    await link.save()
    console.log(link)
}

async function findByEmail(eml){
    try{
        const user = await User.findOne({email: eml, schemaType: "User"})
        return user
    }
    catch(e){
        return null
    }
}

async function findLinksByEmail(emailParam){
    let links = await User.find({ schemaType: "Links", email: emailParam})
    return links
}

async function findFullUrl(shortUrlParam){
    let fullUrl = await User.findOne({schemaType: "Links", shortUrl: shortUrlParam})
    return fullUrl
}
    


const initializePassport = require('./passport-config')
initializePassport(
    passport,
    findByEmail,
    id => User.findById(id),
    saveUser
)
//const users = []

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false}))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))
app.use(express.static('public'));


// Middleware to disable DNS prefetching for all routes
// Without this, when a user paste a link in the brower like chrome
// it will be prefetched and server.js (/:shortUrl) will be called increasing 
// the number of clicks even though the user has not press enter yet, when they press enter, 
// it callas again so it counts as twice
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});


app.get('/', checkAuthenticated, async (req, res) =>{
    let links = await findLinksByEmail(req.user.email)
    res.render('index.ejs', {name: req.user.name, urls: links})
})

app.get('/fetch-urls', checkAuthenticated, async (req, res) => {
    try {
        let links = await findLinksByEmail(req.user.email); // Fetch updated URLs
        res.json({ urls: links }); // Send the updated URLs as a JSON response
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch URLs' });
    }
});



app.post('/qr-code', async (req, res) => {
    try {
        let shortUrl = req.body.shortUrl;

        console.log("short url: " + shortUrl);

        // Find the URL information using the shortUrl
        const user = await User.findOne({ shortUrl: shortUrl });

        if (!user) {
            return res.status(404).send('URL not found');
        }

        // asign the values from the user to the variables
        shortUrl = process.env.SERVER+shortUrl;
        const fullUrl = user.fullUrl;
        const clicks = user.clicks;
        const expirationDate = user.urlExpirationDate;
        const qrCode = await QRCode.toDataURL(fullUrl);

        // Render the EJS page and pass the variables to the template
        res.render('link-details', {fullUrl, shortUrl, clicks, qrCode, expirationDate});
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
    
});


app.get('/login', checkNotAuthenticated, (req, res) =>{
    res.render('login.ejs')
}) 

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
})) 

app.get('/register', checkNotAuthenticated, (req, res) =>{
    res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) =>{
    // this req.body.name correspond to the name field of <input type="password" id="password" name="password" required>
    // so req.body.password will look for name="password"
    try{
        // check if password is valid
        if (!checkPassword(req.body.password)){
            res.render('register', { message: "Password is not valid. Password must contain at least one uppercase letter, one lowercase letter, one number and 8 or more characters." })
            return;
        }

        // check if email is already used
        console.log("checking to see if the email is already registered")
        const user = await findByEmail(req.body.email);
        console.log("user: " + user); 
        if (user != null){
            console.log("user exists")
            res.render('register', { message: "Email already used" })
            return;
        }
        console.log("user does not exist, hashing the password and saveing the user")

        // hash the password
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        const { userObj, randomID } = await saveUser(req.body.name, req.body.email, hashedPassword, null)

        // Send confirmation email
        sendConfirmationEmail(req.body.email, randomID);

        res.redirect('/confirmation');
    }
    catch {
        console.log("error in the post /register route")
        res.redirect('/register')
    }
})



app.get('/confirmation', (req, res) => {
    res.render('confirmation');
});
  
app.get('/confirm/:randomID', async (req, res) => {
    try {
        console.log("searching with randomID: " + req.params.randomID)
        const user = await User.findOne({ confirmationID: req.params.randomID });

        if (!user) {
        return res.status(404).send('User not found');
        }

        // Update user's confirmation status
        user.isConfirmed = true;

        // Save the updated user document
        await user.save();

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
        // Successful authentication, redirect home.
        res.redirect('/');
    }
);

app.post('/shortUrls', async (req, res) =>{
    let short = req.body.shortUrl
    let clickCountsToNotify = req.body.clickCountsToNotify
    if (short == ""){
        short = await shortId.generate()
        console.log("short url is " + short)
    }

    const expirationDate = req.body.expirationDate ? new Date(req.body.expirationDate) : null;

    await saveLink(req.body.fullUrl, short, 0, req.user.email, expirationDate, clickCountsToNotify)
    res.redirect('/')
})

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
        // Ignore the prefetch request and return early.
        return res.status(204).end(); // 204 No Content response
    }
    

    let result = await findFullUrl(req.params.shortUrl)
    if (result == null) return res.sendStatus(404)

    result.clicks++
    result.save();

    const clickCountToSendEmail = result.clickCountToSendEmail;
    if (result.clicks % clickCountToSendEmail === 0) {
      sendClickCountReachedEmail(result);
    }

    res.redirect(result.fullUrl)

})

app.post('/delete-url', async (req, res) => {
    const shortUrl = req.body.shortUrl;
    await User.deleteOne({ shortUrl });
    res.redirect('/'); // refresh the table
});


app.delete('/logout', function(req, res, next) {
    req.logOut(function(err){
        if (err) { return next(err); }
        res.redirect('/login')
    })
})




function checkAuthenticated(req, res, next){
    if (req.isAuthenticated()){
        return next()
    }

    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next){
    if (req.isAuthenticated()){
        return res.redirect('/')
    }
    next()
}


// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: config.email.service,
    auth: {
      user: config.email.user,
      pass: config.email.pass,
    },
});

function sendConfirmationEmail(recipientEmail, randomID) {
    console.log("sending confirmation email to: " + recipientEmail);
    const confirmationUrl = `http://localhost:${config.server.port}/confirm/${randomID}`;

    const mailOptions = {
        from: config.email.user,
        to: recipientEmail,
        subject: 'Confirm your email address',
        text: `Click on the following link to confirm your email address: ${confirmationUrl}`,
    };

    transporter.sendMail(mailOptions, (error) => {
        if (error) {
        console.error(error);
        }
        console.log('Email sent: ' + info.response);
    });
}

function sendClickCountReachedEmail(url) {

    const mailOptions = {
        from: config.email.user,
        to: url.email,
        subject: 'Link Click Notification',
        text: `A new click count has been reached for this link: ${url.fullUrl}\n
        Full URL: ${url.fullUrl}\n
        Short URL: ${url.shortUrl}\n
        Clicks: ${url.clicks}\n
        Expiration Date: ${url.urlExpirationDate}`,
    };

    transporter.sendMail(mailOptions, (error) => {
        if (error) {
        console.error(error);
        }
        console.log('Email sent: ' + info.response);
    });
}


function checkPassword(password){
    if (password.length < 8) {
        return false
    }
    if (!password.match(/[a-z]/g)){
        return false
    }
    if (!password.match(/[A-Z]/g)){
        return false
    }
    if (!password.match(/[0-9]/g)){
        return false
    }
    return true
}


async function forgotPassword(req, res) {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      res.status(404).send('User not found');
      return;
    }
    const randomID = crypto.randomBytes(32).toString('hex');
    user.confirmationID = randomID;
    user.resetPasswordExpires = Date.now() + 600000;     // the reset password link will be valid for 10 minute
    await user.save();
    const link = `http://localhost:${config.server.port}/reset-password/${randomID}`;
    // send email to user with link
    const mailOptions = {
      from: 'maungkaungthukhant@gmail.com',
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
    console.log("resetting password");
    const { id, password, confirmPassword } = req.body;

    // check if password is valid
    if (!checkPassword(password)){
        console.log("password is not valid");
        res.render('reset-password', {id: id, message: "Password is not valid. Password must contain at least one uppercase letter, one lowercase letter, one number and 8 or more characters." })
        return;
    }

    if (password !== confirmPassword) {
      res.status(400).send('Passwords do not match');
      return;
    }
    const hashedPassword = await bcrypt.hash(password, 10)
    const user = await User.findOne({ confirmationID: id });
    if (!user) {
      res.status(404).send('User not found');
      return;
    }
    user.password = hashedPassword;
    await user.save();
    res.send('Password reset successfully');
} 

app.listen(process.env.PORT)
console.info("Listening on port "+ process.env.PORT)

// Check for expired URLs every hour and remove them
setInterval(async () => {
    const now = new Date();
    try {
        // Find and delete expired URLs
        console.log("Checking for expired URLs...");
        // Find the links that are less than the now date
        const expiredLinks = await User.find({ schemaType: "Links", urlExpirationDate: { $lt: now } });      
        if (expiredLinks.length > 0) {
            console.log("Expired links found. Deleting...");
            console.log("Total number of expired links to be deleted " + expiredLinks.length);

            // Delete expired links
            await User.deleteMany({ schemaType: "Links", urlExpirationDate: { $lt: now } });
            console.log("Expired links deleted.");
        }
    } catch (error) {
        console.error("Error checking for expired URLs:", error);
    }
},  60* 60 * 1000); // Run every minute


