const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema({
    reportedUrl: {
        type: String,
        required: true
    },
    urlId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Url',
        required: true
    },
    urlOwner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    reportType: {
        type: String,
        required: true,
        enum: ['broken', 'malicious', 'spam', 'other']
    },
    reportedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: false  // Optional for anonymous reports
    },
    description: {
        type: String,
        required: false,
        maxLength: 1000  // Limit description length
    },
    status: {
        type: String,
        required: true,
        enum: ['pending', 'reviewed', 'resolved'],
        default: 'pending'
    },
    ownerNotified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        immutable: true,
        default: () => Date.now()
    },
    updatedAt: {
        type: Date,
        default: () => Date.now()
    },
    reviewedAt: {
        type: Date
    },
    reviewedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: false
    },
    resolution: {
        type: String,
        required: false
    }
});

// Update the updatedAt timestamp before saving
reportSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

const Report = mongoose.model("Report", reportSchema);

module.exports = Report;
