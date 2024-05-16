const { Router } = require('express');
const userMiddleware = require('../middleware/user');
const { User, Job } = require('../db/index');
const jwt = require("jsonwebtoken");
const zod = require("zod");
const bcrypt = require("bcrypt");
const cuid = require('cuid');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');

const mongoose = require("mongoose");


const router = Router();
const emailSchema = zod.string().email();

const client = new S3Client({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_KEY
    }
})


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

// TODO: Add csurf

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

        res.cookie("token", token, {
            maxAge: 21600000, // 6 hours
            httpOnly: true,
            //secure:true ,  //To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie("role", "user", {
            maxAge: 21600000, // 6 hours
            httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.cookie('id', user.customId, {
            maxAge: 21600000, // 6 hours
            httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: 'Strict'
        })

        res.status(200).json({ message: "user logged in" })


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

        const data = await Job.find(query).skip(offSet).limit(pageSize).populate('owner').select("-rawFiles -editedFiles -EditedFiles -finalFiles").sort({ CreatedDate: -1 });

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


// to get presigned url to upload raw files
router.put("/uploadPreSigner", userMiddleware, async (req, res) => {
    try {
        const { fileName, fileExtension, jobId } = req.body;


        if (!fileName)
            return res.status(400).json({ error: "filename not provided" })

        if (!fileExtension)
            return res.status(400).json({ error: "file extension not provided" })

        if (!jobId)
            return res.status(400).json({ error: "job id not provided" })


        const user = res.locals.userDocument;
        const userId = user._id;

        const job = await Job.findOne({ customId: jobId, users: { $in: [userId] } }).populate("users", "username").populate("owner", "customId");



        if (!job)
            return res.status(400).json({ error: "no owned job with provided job id" })

        const influencerId = job.owner.customId;


        const key = `${influencerId}/${jobId}/${fileName}-${cuid()}.${fileExtension}`
        console.log(key)
        const url = await getSignedUrl(client,
            new PutObjectCommand({
                Bucket: process.env.AWS_BUCKET,
                Key: key,
                Metadata: {
                    type: `application/${fileExtension}`
                }
            }),
            { expiresIn: 60 * 5 } // expires in 5 minutes
        )
        res.status(200).json({
            url,
            key: key
        })
    } catch (error) {
        console.log("user get uploadePreSigner Error", error);
        res.status(500).json({ error: error })
    }
})

router.put("/updateFileKey", userMiddleware, async (req, res) => {
    let session;
    try {
        const { key, jobId, type, fileName } = req.body;

        if (!key)
            return res.status(400).json({ error: "key not provided" });
        if (!jobId)
            return res.status(400).json({ error: "job id not provided" });
        if (!type)
            return res.status(400).json({ error: "type not provided" });
        if (!fileName)
            return res.status(400).json({ error: "file name not provided" });
        if (type !== "rawFile" && type !== "finalFile")
            return res.status(400).json({ error: "invalid file type" })


        const user = res.locals.userDocument;
        const userId = user._id;

        const job = await Job.findOne({ customId: jobId, users: { $in: [userId] } }).populate("users", "username");

        if (!job)
            return res.status(400).json({ error: "no assigned job with provided job id" })

        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiaing a DB session" })
        }

        session.startTransaction();

        // if (type === "rawFile") {
        job.editedFiles.push({
            key, fileName
        })
        // } else if (type === "finalFile") {

        // }

        await job.save();
        session.commitTransaction();
        session.endSession();
        return res.status(200).json({ message: "file uploaded successfully" })

    } catch (error) {
        console.log("user update file key error", error);
        res.status(500).json({ error })
        if (session) {
            await session.abortTransaction();
            session.endSession();
        }
    } finally {
        if (session)
            session.endSession();
    }
})



router.put("/downloadPreSigner", userMiddleware, async (req, res) => {
    try {
        const { jobId, key } = req.body;

        if (!jobId)
            return res.status(400).json({ error: "job id not provided" })

        if (!key)
            return res.status(400).json({ error: "file key id not provided" })

        const user = res.locals.userDocument;
        const userId = user._id;


        const data = await Job.findOne({
            customId: jobId,
            users: { $in: [userId] },
            $or: [{
                rawFiles: {
                    $elemMatch: { key }
                }

            }, {
                editedFiles: {
                    $elemMatch: { key }
                }

            }, {
                finalFiles: {
                    $elemMatch: { key }
                }

            }]
        })

        if (!data)
            return res.status(403).json({ error: "access not available for this file" });


        const url = await getSignedUrl(client,
            new GetObjectCommand({
                Bucket: process.env.AWS_BUCKET,
                Key: key
            }),
            { expiresIn: 60 * 5 }// expires in 5 minutes. 
        )

        return res.status(200).json({ url })

    } catch (error) {
        console.log("user download presigned error", error);
        res.status(500).json(error)
    }
}

)




module.exports = router;