const mongoose = require("mongoose");

const urlSchema = new mongoose.Schema({
    fullUrl: {
        type: String,
        required: true
    },
    shortUrl: {
        type: String,
        required: true
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
    },
    urlExpirationDate: { 
        type: Date 
    },
    clickCountToSendEmail: {
        type: Number,
        default: 1000
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    notifyUser: {
        type: Boolean,
        default: false
    },
    expirationNotificationHours: {
        type: Number,
        default: 24
    },
    password: {
        type: String
    },
    redirectionLimit: {
        type: Number,
        default: 1
    },
    customMessage: {
        type: String
    }
});

urlSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

const Url = mongoose.model("Url", urlSchema);

module.exports = Url;