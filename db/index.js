const mongoose = require("mongoose");
const { required } = require("nodemon/lib/config");
const { v4: uuidv4 } = require('uuid');
const { boolean } = require("zod");
const { JOB_SCHEMA_OPTIONS } = require('../config')

// Create and export db schemas
mongoose.connect(process.env.MONGODB_URL_DEV);

// Admin Schemna 
const AdminSchema = new mongoose.Schema({
    username: String,
    email: {
        type: String,
        unique: true,
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
    username: String,
    email: {
        type: String,
        unique: true,
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
    X: String,
    Instagram: String,
    Facebook: String,
    suspended: {
        type: Boolean,
        default: false
    },
    suspendedOn: Date,
    SuspensionReason: String,
    tags: [String]
})

// userSchame
const UserSchema = new mongoose.Schema({
    username: String,
    email: {
        type: String,
        unique: true,
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
    SuspensionReason: String
})

const JobSchema = new mongoose.Schema({
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Influencer'
    },
    users: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    rawfiles: [String],
    finalFiles: [String],
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
        enum: ["new", "started", "closed", "suspended"],
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