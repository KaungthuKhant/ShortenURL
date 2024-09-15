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

// mongodb requires
const mongoose = require("mongoose")
const User = require("./Users")

mongoose.connect("mongodb://localhost/ShortURLPractice")

async function saveUser(namePara, emailPara, passPara, googleIdPara) {
    const user = new User({
        schemaType: "User",
        name: namePara,
        email: emailPara,
        password: passPara,
        googleId: googleIdPara
    })
    await user.save()
    console.log(user)
    return user
}

async function saveLink(fullLink, shortLink, clicksParam, emailParam){
    console.log("searching for smilar results using short url of: " + shortLink)
    let searchResults = await findFullUrl(shortLink)
    console.log("results found " + searchResults)
    if (searchResults != null){
        console.log("short url already used")
        return;
    }
    const link = new User({schemaType: "Links", fullUrl: fullLink, shortUrl: shortLink, email: emailParam, clicks: clicksParam})
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


app.get('/', checkAuthenticated, async (req, res) =>{
    let links = await findLinksByEmail(req.user.email)
    res.render('index.ejs', {name: req.user.name, urls: links})
})

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
        saveUser(req.body.name, req.body.email, hashedPassword, null) // new code 

        // Send confirmation email
        sendConfirmationEmail(req.body.email);

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
  
app.get('/confirm/:email', async (req, res) => {
    try {
        console.log("searching with email: " + req.params.email)
        const user = await User.findOne({ email: req.params.email });

        if (!user) {
        return res.status(404).send('User not found');
        }

        // Update user's confirmation status
        user.isConfirmed = true;

        // Save the updated user document
        await user.save();

        res.redirect('/login');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});


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
    if (short == ""){
        short = await shortId.generate()
        console.log("short url is " + short)
    }
    await saveLink(req.body.fullUrl, short, 0, req.user.email)
    res.redirect('/')
})

app.get('/:shortUrl', async (req, res) => {
    let result = await findFullUrl(req.params.shortUrl)
    if (result == null) return res.sendStatus(404)

    result.clicks++
    result.save()

    res.redirect(result.fullUrl)

})


app.delete('/logout', function(req, res, next) {
    req.logOut(function(err){
        if (err) { return next(err); }
        res.redirect('/login')
    })
})
 
/*
app.get('/logout', (req, res) =>{
    console.log("Loggin out");
    req.logout();
    res.redirect('/')
})
*/
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

function sendConfirmationEmail(recipientEmail) {
    console.log("sending confirmation email to: " + recipientEmail);
    const confirmationUrl = `http://localhost:${config.server.port}/confirm/${recipientEmail}`;

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

app.listen(8800)
console.info("Listening on port 8800")
