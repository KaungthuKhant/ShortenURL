const mongoose = require("mongoose")


const linkSchema = new mongoose.Schema({
    longLink: String,
    shortLink: String,
    count: Number
})


/**
 * email: {
        type: String,
        required: true,
        lowercase: true,
    },
 */

const userSchema = new mongoose.Schema({
    schemaType: {
        type: String,
        require: true,
    },
    name: String,
    email: String,
    password: String,
    fullUrl: String,
    shortUrl: String,
    clicks: Number,
    createdAt: {
        type: Date,
        immutable: true,
        default: () => Date.now(),
    },
    updatedAt: {
        type: Date,
        default: () => Date.now(),
    }
})

module.exports = mongoose.model("User", userSchema)