const GoogleStrategy = require('passport-google-oauth2').Strategy;

function initialize(passport, getUserByEmail, getUserById) {
    
    // Google OAuth 2.0 Strategy
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:8800/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            // Check if the user already exists in the database
            let user = await getUserByEmail(profile.emails[0].value);
            
            // If the user doesn't exist, create a new one
            if (!user) {
                user = await saveUser(profile.displayName, profile.emails[0].value, null);
            }
            
            // Pass the user to the done callback
            return done(null, user);
        } catch (err) {
            return done(err, false);
        }
    }));

    // Serialize user to store in session
    passport.serializeUser((user, done) => done(null, user.id));

    // Deserialize user from session
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await getUserById(id);
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


