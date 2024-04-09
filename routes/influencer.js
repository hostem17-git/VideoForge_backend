const { Router } = require('express');
const influencerMiddleware = require('../middleware/influencer');
const { Influencer, Job, User } = require('../db/index');
const jwt = require("jsonwebtoken");
const zod = require("zod");
const bcrypt = require("bcrypt");
const { validate } = require('uuid');
const { JOB_SCHEMA_OPTIONS } = require('../config')
const mongoose = require("mongoose");
const { route } = require('./admin');


const router = Router();
const emailSchema = zod.string().email();

const socialSchema = zod.object({
    url: zod.string().url(),
    api: zod.string().optional()
})

const jobSchema = zod.object({
    jobTitle: zod.string().min(10).max(30),
    jobDescription: zod.string().min(30),
    startDate: zod.string().datetime(),
    dueDate: zod.string().datetime(),
    tags: zod.string().array().min(0).max(10).refine(values => {
        return values.every(value => JOB_SCHEMA_OPTIONS.includes(value)
        )
    })
})

// only to be called after verification
function tokenDecoder(token) {

    const decodedValue = jwt.decode(token, process.env.JWT_SECRET);
    return decodedValue;
}

function verifyEmail(email) {
    const response = emailSchema.safeParse(email);
    return response.success;
}

router.post("/Signup", async (req, res) => {
    let session;
    try {

        const { username, email, password } = req.body;

        if (!username || !email || !password)
            return res.status(400).json({ error: "missing inputs" })

        if (!verifyEmail(email)) {
            return res.status(400).json({ error: "Invalid email provided" })
        }

        const salt = await bcrypt.genSalt(10);
        const encryptedPassword = await bcrypt.hash(password.trim(), salt);

        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiating a DB session" })
        }

        session.startTransaction();
        await Influencer.create({
            username: username.trim(),
            email: email.trim(),
            encryptedPassword: encryptedPassword
        })

        await session.commitTransaction();
        session.endSession();
        res.status(200).json({ message: "Influencer created successfully" })
    } catch (error) {
        if (error.code == 11000) {
            res.status(409).json({ message: "Email already exists" })
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

router.post("/SignIn", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ error: "missing inputs" });

    try {
        const influencer = await Influencer.findOne({
            email: email.trim()
        });

        if (!influencer) {
            return res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        if (influencer.suspended) {
            return res.status(403).json({
                error: "Influencer suspended",
                errorReason: influencer.SuspensionReason
            })
        }

        const match = await bcrypt.compare(password.trim(), influencer.encryptedPassword);

        if (!match) {
            return res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        const token = jwt.sign({
            email: email.trim(),
            role: "influencer"
        }, process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        return res.status(200).json({
            token: token
        })


    } catch (err) {
        console.log("Influencer Sign in error", err);
        return res.status(500).json({ error: "Internal server error" })
    }
});

// TODO: How to make it secure???????????????????  | Reset via link???
router.post("/reset-password", async (req, res) => {

})

// To create a new job
router.post("/createjob", influencerMiddleware, async (req, res) => {
    let session;

    try {
        const { jobTitle, jobDescription, startDate, dueDate, tags } = req.body;

        if (!jobTitle || !jobDescription || !startDate || !dueDate) {
            return res.status(400).json({ error: "missing inputs" });
        }

        const jobValidation = jobSchema.safeParse({
            jobTitle: jobTitle.trim(),
            jobDescription: jobDescription.trim(),
            startDate,
            dueDate,
            tags
        })

        if (!jobValidation.success) {
            return res.status(400).json({ error: jobValidation.error.errors })
        }
        // *********************

        const decodedToken = tokenDecoder(req.headers.authorization.split(" ")[1]);
        const email = decodedToken.email;

        const owner = await Influencer.findOne({ email: email.trim() }).select('-encryptedPassword -Youtube_api -X_api -Instagram_api -Facebook_api');

        const influencer = res.locals.influencerDocument;
        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiating DB session" })
        }

        session.startTransaction();

        const job = await Job.create([{
            owner,
            JobTitle: jobTitle.trim(),
            Description: jobDescription.trim(),
            StartDate: startDate,
            DueDate: dueDate,
            tags: tags
        }], { session });


        influencer.createdJobs.push(job[0]);

        await influencer.save({ session });

        await session.commitTransaction();

        session.endSession();

        res.status(200).json({
            message: "Job created",
            id: job._id
        })
    } catch (error) {
        console.log("Influencer Job creation error", error);
        res.status(500).json({ error: "Error creating job" });
        if (session) {
            session.abortTransaction();
            session.endSession()
        }
    } finally {
        if (session) {
            session.endSession();
        }
    }
});

// TODO: update Raw files | need AWS S3 
// TODO: remove Raw Files | need AWS S3
// TODO: rename files?    | need AWS S3
// TODO: trigger upload   | need AWS S3

// for influencers to hire users
router.put("/hire", influencerMiddleware, async (req, res) => {
    let session;
    try {
        const { jobId, userId } = req.body;

        if (!jobId || !userId) {
            return res.status(400).json({ error: "Invalid inputs" });
        }

        const job = await Job.findOne({ customId: jobId.trim() }).populate("owner");

        if (!job) {
            return res.status(400).json({ error: "Invalid job ID" });
        }

        const influencerMail = tokenDecoder(req.headers.authorization.split(" ")[1]).email;

        if (job.owner.email !== influencerMail) {
            return res.status(403).json({ error: "Cannot hire to a non-owned job" })
        }
        if (job.Stage !== "new") {
            return res.status(400).json({ error: `Cannot hire on job which already ${job.Stage}` })
        }

        if (job.suspended) {
            return res.status(400).json({ error: "Job not available" })
        }

        const user = await User.findOne({ customId: userId.trim() });

        if (!user) {
            return res.status(400).json({ error: "Invalid user Id" })
        }

        if (user.suspended) {
            return res.status(400).json({ error: "Cannot hire a suspended user" })
        }

        session = await mongoose.startSession();
        session.startTransaction();

        job.users.push(user);
        job.Stage = "started";
        user.JobsTaken.push(job);

        await job.save({ session });
        await user.save({ session });

        await session.commitTransaction();
        session.endSession();

        return res.status(200).json({
            message: "hired successfully"
        })
    } catch (error) {
        console.log("Hire user error", error);
        res.status(500).json({ error: "Error hiring user" })
        if (session) {
            await session.abortTransaction();
            session.endSession();
        }
    } finally {
        if (session) {
            session.endSession();
        }
    }
})

// To close job
// TODO: Add option to select close type - "Withdrawan","Completed"
router.put("/closejob", influencerMiddleware, async (req, res) => {
    let session;
    try {
        const { jobId, closeReason } = req.body;

        if (!jobId) {
            await session.abortTransaction();
            return res.status(400).json({ error: "Invalid inputs" });
        }

        const job = await Job.findOne({ customId: jobId.trim() }).session(session).populate("owner");

        if (!job) {
            await session.abortTransaction();
            return res.status(400).json({ error: "Invalid job ID" });
        }

        const influencerMail = tokenDecoder(req.headers.authorization.split(" ")[1]).email;

        if (job.owner.email !== influencerMail) {
            await session.abortTransaction();
            return res.status(403).json({ error: "Cannot close a non-owned job" })
        }

        if (job.suspended) {
            await session.abortTransaction();
            return res.status(400).json({ error: "Job not available" })
        }

        if (job.Stage === "closed") {
            await session.abortTransaction();
            return res.status(409).json({ error: "Job already closed" })
        }

        session = await mongoose.startSession();
        session.startTransaction();

        job.Stage = "closed";
        job.CloseReason = closeReason.trim();
        job.ClosedDate = new Date().toISOString();
        await job.save({ session });

        await session.commitTransaction();
        session.endSession();

        return res.status(200).json({
            message: "Job closed successfully",
            closedJob: job
        })

    } catch (error) {
        console.log("Close job error", error);
        await session.abortTransaction();
        if (session) {
            await session.abortTransaction();
            session.endSession();

        }
        res.status(500).json({
            error: "Error closing job"
        })

    } finally {
        if (session) {
            session.endSession();
        }
    }

});

router.put("/updateSocials", influencerMiddleware, async (req, res) => {
    let session;
    try {
        const { Youtube, Youtube_api, Instagram, Instagram_api, Facebook, Facebook_api } = req.body;

        if (!Youtube && !Instagram && !Facebook) {
            res.status(400).json({ error: "atleast one social URL and api needed" })
        }

        if (Youtube) {
            const result = socialSchema.safeParse({
                url: Youtube.trim(),
                api: Youtube_api.trim()
            })
            if (!result.success) {
                return res.status(400).json({ error: "Invalid Youtube url/api" })
            }
        }

        if (Instagram) {
            const result = socialSchema.safeParse({
                url: Instagram.trim(),
                api: Instagram_api.trim()
            })
            if (!result.success) {
                return res.status(400).json({ error: "Invalid Instagram url/api" })
            }
        }

        if (Facebook) {
            const result = socialSchema.safeParse({
                url: Facebook.trim(),
                api: Facebook_api.trim()
            })
            if (!result.success) {
                return res.status(400).json({ error: "Invalid Facebook url/api" })
            }
        }

        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiaing a DB session" })
        }

        session.startTransaction();

        const influencer = res.locals.influencerDocument;

        if (Youtube) {
            influencer.Youtube = Youtube.trim();
            influencer.Youtube_api = Youtube_api ? Youtube_api.trim() : undefined;
        }

        if (Instagram) {
            influencer.Instagram = Instagram.trim();
            influencer.Instagram_api = Instagram_api ? Instagram_api.trim() : undefined;
        }

        if (Facebook) {
            influencer.Facebook = Facebook.trim();
            influencer.Facebook_api = Facebook_api ? Facebook_api.trim() : undefined;
        }

        await influencer.save();

        session.commitTransaction();
        session.endSession();
        res.status(200).json({ message: "Socials updated" })


    } catch (error) {
        console.log("Update profile error", error);
        res.status(500).json({ error: "Error updating profile" });
        if (session) {

            session.abortTransaction();
            session.endSession();
        }
    }
    finally {
        if (session) {
            session.endSession();
        }
    }
});


module.exports = router;