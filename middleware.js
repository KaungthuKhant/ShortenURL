function checkAuthenticated(req, res, next) {
    console.log("Checking authentication");
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/home');
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}

function sessionTimeout(req, res, next) {
    if (req.session && req.session.lastActivity) {
        const currentTime = Date.now();
        const timeSinceLastActivity = currentTime - req.session.lastActivity;
        
        if (timeSinceLastActivity > 30 * 60 * 1000) { // 30 minutes
            req.session.destroy((err) => {
                if (err) {
                    console.error('Session destruction error:', err);
                }
                return res.redirect('/login?timeout=true');
            });
        } else {
            req.session.lastActivity = currentTime;
        }
    } else {
        req.session.lastActivity = Date.now();
    }
    next();
}

module.exports = {
    checkAuthenticated,
    checkNotAuthenticated,
    sessionTimeout
};