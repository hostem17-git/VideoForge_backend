const { Router } = require("express");
const sharedAccessMiddleware = require("../middleware/shared");
const { User, Influencer, Job } = require('../db/index');


const router = Router();


router.get("/user/:userId", sharedAccessMiddleware, async (req, res) => {
    try {
        const userID = req.params.userId;
        if (!userID) {
            return res.status(400).json({ error: "User id not provided" })
        }
        const data = await User.findOne({ customId: userID }).populate("JobsTaken").select('-encryptedPassword ');

        if (data) {
            return res.status(200).json({
                data: data
            })
        }
        else {
            return res.status(404).json({
                message: "User not found"
            })
        }
    }
    catch (error) {
        console.log("shared get user error", error)
        res.status(500).json({ error: "Unable to fetch user" });
    }
});

// TODO: test populate
//  Get all users
router.get("/users", sharedAccessMiddleware, async (req, res) => {

    try {
        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 10;

        const offSet = (page - 1) * pageSize;

        const totalCount = await User.countDocuments();
        const totalPages = Math.ceil(totalCount / pageSize);

        const data = await User.find({}).select('-encryptedPassword ').populate("JobsTaken").skip(offSet).limit(pageSize);

        if (data.length > 0) {
            return res.status(200).json({
                page,
                pageSize,
                totalCount,
                totalPages,
                data,

            })
        }
        else {
            return res.status(404).json({
                message: "No users found"
            })
        }
    }
    catch (error) {
        console.log("Shared : get users error", error)
        res.status(500).json({ error: "Unable to fetch users" });
    }

});

// TODO: test populate
// To get specific influencer
router.get("/influencer/:influencerId", sharedAccessMiddleware, async (req, res) => {
    try {
        const influencerId = req.params.influencerId;
        if (!influencerId) {
            return res.status(400).json({ error: "Influencer id not provided" })
        }
        const data = await Influencer.findOne({ customId: influencerId }).select('-encryptedPassword ').populate("createdJobs");

        if (data) {
            return res.status(200).json({
                data: data
            })
        }
        else {
            return res.status(404).json({
                message: "Influencer not found"
            })
        }
    }
    catch (error) {
        console.log("shared get influencer error", error)
        res.status(500).json({ error: "Unable to fetch influencer" });
    }
});

// TODO: test populate
// Get all influencers
router.get("/influencers", sharedAccessMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 10;

        const offSet = (page - 1) * pageSize;

        const totalCount = await Influencer.countDocuments();

        const totalPages = Math.ceil(totalCount / pageSize);

        const data = await Influencer.find({}).select('-encryptedPassword ').populate("createdJobs").skip(offSet).limit(pageSize);

        if (data.length > 0) {
            return res.status(200).json({
                page,
                pageSize,
                totalCount,
                totalPages,
                data
            })
        }
        else {
            return res.status(404).json({
                message: "No influencers found"
            })
        }
    }
    catch (error) {
        console.log("shared get all influencer error", error)
        res.status(500).json({ error: "Unable to fetch influencers" });
    }
})

// TODO: test populate 
// To get specific job
router.get("/job/:jobId", sharedAccessMiddleware, async (req, res) => {
    try {
        const jobId = req.params.jobId;
        if (!jobId) {
            return res.status(400).json({ error: "Job id not provided" })
        }
        const data = await Job.findOne({ jobId }).populate("owner users");

        if (data) {
            return res.status(200).json({
                data: data
            })
        }
        else {
            return res.status(404).json({
                message: "Job not found"
            })
        }
    }
    catch (error) {
        console.log("shared get Job error", error)
        res.status(500).json({ error: "Unable to fetch Job" });
    }
});

// TODO: test populate
//  Get all jobs
router.get("/jobs", sharedAccessMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 10;

        const offSet = (page - 1) * pageSize;

        const totalCount = await Job.countDocuments();

        const totalPages = Math.ceil(totalCount / pageSize);

        const data = await Job.find({}).select('-encryptedPassword ').skip(offSet).limit(pageSize).populate("owner");

        if (data.length > 0) {
            return res.status(200).json({
                page,
                pageSize,
                totalCount,
                totalPages,
                data
            })
        }
        else {
            return res.status(404).json({
                message: "No Jobs found"
            })
        }
    }
    catch (error) {
        console.log("shared get all jobs error", error)
        res.status(500).json({ error: "Unable to fetch jobs" });
    }
})

// User validation
router.get("/userValidation/:token", (req, res) => {
    try {
        const token = req.params.token;
        if (!token) {
            res.status(400).json({ error: "Token missing" });
        }
        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);
        if (decodedValue) {
            res.status(200).json({
                userValid: true,
                role: decodedValue.role
            })
        }
        return res.status(403).json({
            userValid: true,
            error: "Unauthorized"
        })
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "authorization token expired" })
        }
        console.log("admin JWT verification error", error)
        res.status(401).json({ error: "Invalid inputs" })
    }
})


module.exports = router;