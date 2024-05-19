const { Router } = require("express");
const sharedAccessMiddleware = require("../middleware/shared");
const { User, Influencer, Job } = require('../db/index');
const jwt = require("jsonwebtoken");
const { default: mongoose } = require("mongoose");


const router = Router();


router.get("/logout", sharedAccessMiddleware, async (req, res) => {
    try {
        res.cookie("token", '', {
            maxAge: 0, // 6 hours
            httpOnly: true,
            //secure:true ,  //To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie("role", "", {
            maxAge: 0, // 6 hours
            httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie('id', '', {
            maxAge: 0, // 6 hours
            httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })
        return res.status(200).json({ message: "logged out" })
    } catch (error) {
        console.log("shared logout error", error);
        res.status(500).json({ error: "Internal server error" })
    }
});

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
                error: "User not found"
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
        const pageSize = parseInt(req.query.pageSize) || 25;

        const offSet = (page - 1) * pageSize;

        const totalCount = await User.countDocuments();
        const totalPages = Math.ceil(totalCount / pageSize);

        const data = await User.find({}).select('-encryptedPassword ').skip(offSet).limit(pageSize);

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
                error: "No users found"
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

        const data = await Influencer.findOne({ customId: influencerId }).select('-encryptedPassword -Youtube_api -X_api -Instagram_api -Facebook_api -createdJobs');

        if (data) {
            return res.status(200).json({
                data: data
            })
        }
        else {
            return res.status(404).json({
                error: "Influencer not found"
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
        const pageSize = parseInt(req.query.pageSize) || 25;

        const offSet = (page - 1) * pageSize;

        const totalCount = await Influencer.countDocuments();

        const totalPages = Math.ceil(totalCount / pageSize);

        const data = await Influencer.find({}).select('-encryptedPassword -Youtube_api -X_api -Instagram_api -Facebook_api -createdJobs').skip(offSet).limit(pageSize);

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
                error: "No influencers found"
            })
        }
    }
    catch (error) {
        console.log("shared get all influencer error", error)
        res.status(500).json({ error: "Unable to fetch influencers" });
    }
})

// TODO: Test if populate owner provides confidential data too
// TODO: test populate
//  Get all jobs
router.get("/jobs/:stage?", sharedAccessMiddleware, async (req, res) => {
    try {
        const stage = req.params.stage;

        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 25;

        const offSet = (page - 1) * pageSize;

        const totalCount = await Job.countDocuments();

        const totalPages = Math.ceil(totalCount / pageSize);

        const query = {};


        if (stage) {
            query.Stage = stage
        };

        const data = await Job.find(query).skip(offSet).limit(pageSize).select('-rawFiles -editedFiles -EditedFiles -finalFiles').sort({ CreatedDate: -1 });

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
                error: "No Jobs found"
            })
        }
    }
    catch (error) {
        console.log("shared get all jobs error", error)
        res.status(500).json({ error: "Unable to fetch jobs" });
    }
})

// User validation
router.get("/userValidation/", (req, res) => {
    try {
        const cookie = req.cookies;
        if (!cookie || !cookie.token) {
            return res.status(401).json({ error: "Authorization token missing" });
        }
        const token = cookie.token

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

router.get("/job/:jobId", sharedAccessMiddleware, async (req, res) => {
    try {

        const jobId = req.params.jobId;

        if (!jobId) {
            return res.status(400).json({ error: "Job id not provided" })
        }
        const data = await Job.findOne({ customId: jobId }).select("-rawFiles -editedFiles -EditedFiles -finalFiles").populate("users", "username").populate("owner", "username");

        if (data) {
            return res.status(200).json({
                data: data
            })
        }

        else {
            return res.status(404).json({
                error: "Job not found"
            })
        }
    }
    catch (error) {
        console.log("user get Job error", error)
        res.status(500).json({ error: "Unable to fetch Job" });
    }
});


router.post("/GoogleSignUp", async (req, res) => {
    let session;
    try {

        const { Googletoken, userType } = req.body;
        const decodedValue = jwt.decode(Googletoken);

        const email = decodedValue.email;
        const username = decodedValue.name;

        let userDocument;

        if (userType !== "creator" && userType !== "user") {
            return res.status(401).json({ error: "invalid user type" })
        }

        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiating a DB session" })
        }
        session.startTransaction();

        if (userType === "creator") {

            userDocument = await Influencer.create({
                username: username.trim(),
                email: email.trim(),
            })
        } else if (userType === "user") {

            userDocument = await User.create({
                username: username.trim(),
                email: email.trim()
            })

        }
        await session.commitTransaction();
        session.endSession();


        const token = jwt.sign({
            email: email.trim(),
            role: `${userType === "creator" ? "influencer" : "user"}`,
        }, process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        res.cookie("token", token, {
            maxAge: 3600000, // 1 hour
            httpOnly: true,
            //secure:true ,  //To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie("role", `${userType === "creator" ? "creator" : "user"}`, {
            maxAge: 3600000, // 1 hour
            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie('id', userDocument.customId, {
            maxAge: 3600000, // 1 hour
            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })


        res.status(200).json({ message: `${userType === "creator" ? "influencer" : "user"} created successfully` })
    } catch (error) {
        if (error.code == 11000) {
            res.status(409).json({ error: "Email already exists" })
        } else {
            console.error("Error signing up influencer:", error);
            res.status(500).json({ error: "Internal server error" });
        }
        if (session) {
            await session.abortTransaction();
            session.endSession();
        }
    } finally {
        if (session) {
            session.endSession();
        }
    }
});

router.post("/GoogleSignIn", async (req, res) => {
    try {
        const { Googletoken, userType } = req.body;
        const decodedValue = jwt.decode(Googletoken);


        const email = decodedValue.email;

        let userDocument;

        if (userType !== "creator" && userType !== "user") {
            return res.status(401).json({ error: "invalid user type" })
        }

        if (userType === "creator") {
            userDocument = await Influencer.findOne({
                email: email.trim()
            }).select('-Youtube_api -X_api -Instagram_api -Facebook_api');
        }
        else if (userType === "user") {
            userDocument = await User.findOne({
                email: email.trim()
            }).select('-Youtube_api -X_api -Instagram_api -Facebook_api');
        }

        if (!userDocument) {
            return res.status(401).json({
                error: "user not found"
            })
        }

        if (userDocument.suspended) {
            return res.status(403).json({
                error: "Influencer suspended",
                errorReason: userDocument.SuspensionReason
            })
        }

        const token = jwt.sign({
            email: email.trim(),
            role: `${userType === "creator" ? "influencer" : "user"}`,
        }, process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        res.cookie("token", token, {
            maxAge: 3600000, // 6 hours
            httpOnly: true,
            //secure:true ,  //To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie("role", `${userType === "creator" ? "creator" : "user"}`, {
            maxAge: 3600000, // 6 hours
            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie('id', userDocument.customId, {
            maxAge: 3600000, // 6 hours
            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.status(200).json({ message: `${userType} logged in` })

    } catch (err) {
        console.log("Influencer Sign in error", err);
        return res.status(500).json({ error: "Internal server error" })
    }
});


module.exports = router;