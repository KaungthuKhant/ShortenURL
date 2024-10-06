const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: false,
    },
    googleId: {
        type: String,
        required: false,
    },
    createdAt: {
        type: Date,
        immutable: true,
        default: () => Date.now(),
    },
    updatedAt: {
        type: Date,
        default: () => Date.now(),
    },
    isConfirmed: { 
        type: Boolean, 
        default: false 
    },
    confirmationID: {
        type: String,
    },
    resetPasswordExpires: {
        type: Date,
    }
});

userSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

userSchema.pre('validate', function(next) {
    if (!this.googleId && !this.password) {
        this.invalidate('password', 'Password is required for non-Google OAuth users');
    }
    next();
});

const User = mongoose.model("User", userSchema);

module.exports = User;