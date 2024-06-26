const mongoose = require("mongoose");
const { required } = require("nodemon/lib/config");
const { v4: uuidv4 } = require('uuid');
const { boolean } = require("zod");
const { JOB_SCHEMA_OPTIONS } = require('../config');
const { stringify } = require("nodemon/lib/utils");

// Create and export db schemas
mongoose.connect(process.env.MONGODB_URL_DEV);

// Admin Schemna 
const AdminSchema = new mongoose.Schema({
    username: {
        type: String,
        set: (value) => value.toLowerCase()
    },
    email: {
        type: String,
        unique: true,
        set: (value) => value.toLowerCase()
    },
    encryptedPassword: String,
    DateCreated: {
        type: Date,
        default: () => Date.now()
    },
    customId: {
        type: String,
        default: uuidv4,
        unique: true
    },
    suspended: {
        type: Boolean,
        default: false
    },
    suspendedOn: Date,
    SuspensionReason: String
})

// InfluencerSchema
const InfluencerSchema = new mongoose.Schema({
    username: {
        type: String,
        set: (value) => value.toLowerCase()
    },
    email: {
        type: String,
        unique: true,
        set: (value) => value.toLowerCase()
    },
    encryptedPassword: String,
    createdJobs: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Job'
    }],
    customId: {
        type: String,
        default: uuidv4,
        unique: true
    },
    Youtube: String,
    Youtube_api: String,
    Instagram: String,
    Instagram_api: String,
    Facebook: String,
    Facebook_api: String,
    suspended: {
        type: Boolean,
        default: false
    },
    suspendedOn: Date,
    SuspensionReason: String,
    tags: [String],
    googleAcessScope: String,
    googleRefreshToken: String,
    googleAccessToken: String,
    googleAccessModifiedOn: String,
    googleAccessTokenExpiry: String
})

// userSchame
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        set: (value) => value.toLowerCase()
    },
    email: {
        type: String,
        unique: true,
        set: (value) => value.toLowerCase()
    },
    encryptedPassword: String,
    JobsTaken: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Job'
    }],
    customId: {
        type: String,
        default: uuidv4,
        unique: true
    },
    Youtube: String,
    X: String,
    Instagram: String,
    Facebook: String,
    Portfolio: String,
    suspended: {
        type: Boolean,
        default: false
    },
    suspendedOn: Date,
    SuspensionReason: String,

}, { timestamps: true })

const JobSchema = new mongoose.Schema({
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Influencer'
    },
    users: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    rawFiles: [{
        key: String,
        fileName: String,
        CreatedDate: {
            type: Date,
            default: () => Date.now()
        }
    }],
    editedFiles: [{
        key: String,
        fileName: String,
        CreatedDate: {
            type: Date,
            default: () => Date.now()
        }
    }],
    finalFiles: [{
        key: String,
        fileName: String,
        CreatedDate: {
            type: Date,
            default: () => Date.now()
        }
    }],
    JobTitle: {
        type: String,
        required: true
    },
    Description: {
        type: String,
        required: true
    },
    CreatedDate: {
        type: Date,
        default: () => Date.now()
    },
    StartDate: Date,
    DueDate: Date,
    ClosedDate: Date,
    CloseReason: String,
    Stage: {
        type: String,
        enum: ["new", "started", "closed", "suspended", "uploaded"],
        default: "new"
    },
    customId: {
        type: String,
        default: uuidv4,
        unique: true
    },
    suspended: {
        type: Boolean,
        default: false
    },
    suspendedOn: Date,
    SuspensionReason: String,
    tags: {
        type: [String],
        enum: JOB_SCHEMA_OPTIONS
    }
})

const Admin = mongoose.model('Admin', AdminSchema);
const Influencer = mongoose.model('Influencer', InfluencerSchema);
const User = mongoose.model('User', UserSchema);
const Job = mongoose.model('Job', JobSchema);

module.exports = {
    Admin,
    Influencer,
    User,
    Job
}