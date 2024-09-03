const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    schemaType: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: function () {
            return this.schemaType === "User";
        }
    },
    email: {
        type: String,
        required: function () {
            return this.schemaType === "User";
        },
        lowercase: true,
    },
    password: {
        type: String,
        required: function () {
            return this.schemaType === "User" && !this.googleId;
        },
        // Password will be optional if using Google OAuth (i.e., if googleId exists)
    },
    googleId: {
        type: String,
        required: false, // Optional, only for Google OAuth users
    },
    fullUrl: {
        type: String,
        required: function () {
            return this.schemaType === "Links";
        }
    },
    shortUrl: {
        type: String,
        required: function () {
            return this.schemaType === "Links";
        }
    },
    clicks: {
        type: Number,
        default: 0
    },
    createdAt: {
        type: Date,
        immutable: true,
        default: () => Date.now(),
    },
    updatedAt: {
        type: Date,
        default: () => Date.now(),
    }
});

// Middleware to update the updatedAt field before saving
userSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model("User", userSchema);