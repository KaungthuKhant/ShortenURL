const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const User = require('./models/User');

function initialize(passport) {
    passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
        try {
            const user = await User.findOne({ email: email.toLowerCase() });
            if (!user) {
                return done(null, false, { message: 'No user with that email' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return done(null, false, { message: 'Password incorrect' });
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }));

    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.SERVER + "/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await User.findOne({ email: profile.emails[0].value });
            if (!user) {
                user = new User({
                    name: profile.displayName,
                    email: profile.emails[0].value,
                    googleId: profile.id
                });
                await user.save();
            } else if (!user.googleId) {
                user.googleId = profile.id;
                await user.save();
            }

            return done(null, user);
        } catch (err) {
            return done(err, false);
        }
    }));

    passport.serializeUser((user, done) => done(null, user.id));

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user);
        } catch (err) {
            done(err, null);
        }
    });
}

module.exports = initialize;

/**
 * NOTE: Understanding the passport.serializeUser and deserializeUser 
 * Stackoverflow link for that https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize
 * Explains what the passport does https://stackoverflow.com/questions/45428107/what-does-passport-js-do-and-why-we-need-it
 * Better documentation for the passport https://github.com/jwalton/passport-api-docs?tab=readme-ov-file#passportinitialize 
 */


