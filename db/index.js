const mongoose = require("mongoose");
const { v4: uuidv4 } = require('uuid');
const { boolean } = require("zod");
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
    SuspensionReason: String
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
        ref: 'Influencer'
    }],
    files: [String],
    JobTitle: String,
    CreatedDate: {
        type: Date,
        default: () => Date.now()
    },
    StartDate: Date,
    DueDate: Date,
    ClosedDate: Date,
    CompletedDate: Date,
    Stage: {
        type: String,
        enum: ["new", "started", "closed"]
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
    tags:[String]
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