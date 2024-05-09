const { Router } = require('express');
const userMiddleware = require('../middleware/user');
const { User, Job } = require('../db/index');
const jwt = require("jsonwebtoken");
const zod = require("zod");
const bcrypt = require("bcrypt");

const router = Router();
const emailSchema = zod.string().email();
const socialSchema = zod.object({
    url: zod.string().url(),
    // api: zod.string().optional()
})

function verifyEmail(email) {
    const response = emailSchema.safeParse(email);
    return response.success;
}

router.post("/Signup", async (req, res) => {
    const { username, email, password } = req.body;

    if (!verifyEmail(email)) {
        return res.status(400).json({ error: "Invalid email provided" })
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const encryptedPassword = await bcrypt.hash(password, salt);

        await User.create({
            username: username,
            email: email,
            encryptedPassword: encryptedPassword
        })
        res.status(200).json({ message: "User created successfully" })
    } catch (error) {
        if (error.code == 11000) {
            res.status(409).json({ error: "Email already exists" })
        } else {
            console.error("Error signing up User:", error);
            res.status(500).json({ error: "Internal server error" });
        }
    }
});

router.post("/SignIn", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({
            email
        });

        if (!user) {
            return res.status(401).json({
                error: "user not found"
            })
        }

        if (user.suspended) {
            return res.status(403).json({
                error: "User suspended",
                errorReason: user.SuspensionReason
            })
        }

        const match = await bcrypt.compare(password, user.encryptedPassword);

        if (!match) {
            return res.status(401).json({
                error: "Incorrect password"
            })
        }

        const token = jwt.sign({
            email: email,
            role: "user"
        }, process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        return res.status(200).json({
            token: token,
            role: "user",
            id: user.customId
        })


    } catch (err) {
        console.log("User Sign in error", err);
        return res.status(500).json({ error: "Internal server error" })
    }



});

// to update socials
router.put("/updateSocials", userMiddleware, async (req, res) => {
    let session;
    try {
        const { Youtube, Instagram, Facebook } = req.body;

        if (!Youtube && !Instagram && !Facebook) {
            res.status(400).json({ error: "atleast one social URL needed" })
        }

        if (Youtube) {
            const result = socialSchema.safeParse({
                url: Youtube.trim(),
            })
            if (!result.success) {
                return res.status(400).json({ error: "Invalid Youtube url" })
            }
        }

        if (Instagram) {
            const result = socialSchema.safeParse({
                url: Instagram.trim(),
            })
            if (!result.success) {
                return res.status(400).json({ error: "Invalid Instagram url/api" })
            }
        }

        if (Facebook) {
            const result = socialSchema.safeParse({
                url: Facebook.trim(),
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

        const user = res.locals.userDocument;

        if (Youtube) {
            user.Youtube = Youtube.trim();
        }

        if (Instagram) {
            user.Instagram = Instagram.trim();
        }

        if (Facebook) {
            user.Facebook = Facebook.trim();
        }

        await user.save();

        session.commitTransaction();
        session.endSession();
        res.status(200).json({ message: "Socials updated" })


    } catch (error) {
        console.log("Update user profile error", error);
        res.status(500).json({ error: "Error updating user profile" });
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


// To get specific that has been assinged to user 
router.get("/myjob/:jobId", userMiddleware, async (req, res) => {
    try {
        const user = res.locals.userDocument;
        const userId = user._id;
        const jobId = req.params.jobId;

        if (!jobId) {
            return res.status(400).json({ error: "Job id not provided" })
        }
        const data = await Job.findOne({ customId: jobId, users: { $in: [userId] } }).populate("users", "username").populate("owner", "username");

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

// To get all assinged Jobs
router.get("/myjobs/:stage?", userMiddleware, async (req, res) => {
    try {
        const user = res.locals.userDocument;
        const userId = user._id;

        const stage = req.params.stage;

        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 25;

        const offSet = (page - 1) * pageSize;

        const totalCount = await Job.countDocuments();

        const totalPages = Math.ceil(totalCount / pageSize);

        const query = { users: { $in: [userId] } };


        if (stage) {
            query.Stage = stage
        };

        const data = await Job.find(query).skip(offSet).limit(pageSize).populate('owner').select("-rawfiles -editedFiles -EditedFiles -finalFiles").sort({ CreatedDate: -1 });

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
        console.log("user get all jobs error", error)
        res.status(500).json({ error: "Unable to fetch jobs" });
    }
})

// router.get("/myJobs", userMiddleware, async (req, res) => {
//     try {
//         const user = res.locals.userDocument;
//         const userId = user._id;
//         const page = parseInt(req.query.page) || 1;
//         const pageSize = parseInt(req.query.pageSize) || 25;
//         const offSet = (page - 1) * pageSize;
//         const totalCount = await Job.countDocuments({ owner: influencerId });
//         const totalPages = Math.ceil(totalCount / pageSize);

//         // const jobs = await Job.find({ owner: influencerId }).skip(offSet).limit(pageSize).sort({ CreatedDate: -1 });

//         const jobs = await Job.find({ users: { $in: [userId] } }).populate('owner', 'username email').select("-rawfiles -editedFiles -EditedFiles -finalFiles")


//         res.status(200).json(
//             {
//                 page,
//                 pageSize,
//                 totalCount,
//                 totalPages,
//                 jobs
//             }
//         );
//     } catch (error) {
//         console.log("Error Fetching my jobs for influencer", error)
//         res.status(500).json({
//             error: error
//         })
//     }


// })


module.exports = router;