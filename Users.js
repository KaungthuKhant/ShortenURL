const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    schemaType: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: function () {
            console.log('Validating name field, schemaType:', this.schemaType);
            return this.schemaType === "User";
        }
    },
    email: {
        type: String,
        required: function () {
            console.log('Validating email field, schemaType:', this.schemaType);
            return this.schemaType === "User";
        },
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
    fullUrl: {
        type: String,
        required: function () {
            console.log('Validating fullUrl field, schemaType:', this.schemaType);
            return this.schemaType === "Links";
        }
    },
    shortUrl: {
        type: String,
        required: function () {
            console.log('Validating shortUrl field, schemaType:', this.schemaType);
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
    },
    isConfirmed: { 
        type: Boolean, 
        default: false 
    },
    confirmationID: {
        type: String,
    }

});

// Middleware to update the updatedAt field before saving
userSchema.pre('save', function (next) {
    console.log('Pre-save middleware triggered');
    this.updatedAt = Date.now();
    next();
});

// Custom validation
userSchema.pre('validate', function(next) {
    console.log('Pre-validate middleware triggered');
    console.log('Current document state:', JSON.stringify(this.toObject(), null, 2));
    
    if (this.schemaType === "User" && !this.googleId && !this.password) {
        console.log('Validation failed: Password required for non-Google OAuth user');
        this.invalidate('password', 'Password is required for non-Google OAuth users');
    } else {
        console.log('Validation passed');
    }
    next();
});

// Add post-save hook for logging
userSchema.post('save', function(doc, next) {
    console.log('Post-save hook triggered');
    console.log('Saved document:', JSON.stringify(doc.toObject(), null, 2));
    next();
});

const User = mongoose.model("User", userSchema);

// Add error logging to the model
const originalCreate = User.create;
User.create = async function(...args) {
    try {
        const result = await originalCreate.apply(this, args);
        console.log('User.create succeeded');
        return result;
    } catch (error) {
        console.error('User.create failed:', error);
        throw error;
    }
};

module.exports = User;