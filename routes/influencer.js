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
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3")

const cuid = require("cuid");
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const router = Router();

const client = new S3Client({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_KEY
    }
})


const emailSchema = zod.string().email();

const socialSchema = zod.object({
    url: zod.string().url(),
    api: zod.string().optional()
})

const jobSchema = zod.object({
    jobTitle: zod.string().min(10).max(30),
    jobDescription: zod.string().min(30),
    startDate: zod.string().date(),
    dueDate: zod.string().date(),
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

router.post("/SignIn", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ error: "missing inputs" });

    try {
        const influencer = await Influencer.findOne({
            email: email.trim()
        }).select('-Youtube_api -X_api -Instagram_api -Facebook_api');

        if (!influencer) {
            return res.status(401).json({
                error: "user not found"
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
                error: "Incorrect password"
            })
        }

        const token = jwt.sign({
            email: email.trim(),
            role: "influencer",
        }, process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        return res.status(200).json({
            token: token,
            role: "influencer",
            id: influencer.customId
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

        // const influencer = res.locals.influencerDocument;
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


        owner.createdJobs.push(job[0]);

        await owner.save({ session });

        await session.commitTransaction();

        session.endSession();


        res.status(200).json({
            message: "Job created",
            job: job[0].customId
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
    // console.log("in close joib")
    let session;
    try {
        const { jobId } = req.body;

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
            return res.status(403).json({ error: "Your are not owner of this job" })
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
            return res.status(400).json({ error: "Social URL not provided" })
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
        }

        if (Youtube_api && Youtube_api.trim() !== "") {
            influencer.Youtube_api = Youtube_api.trim()
        }

        if (Instagram) {
            influencer.Instagram = Instagram.trim();
        }

        if (Instagram_api && Instagram_api.trim() !== "") {
            influencer.Instagram_api = Instagram_api.trim()
        }

        if (Facebook) {
            influencer.Facebook = Facebook.trim();
        }

        if (Facebook_api && Facebook_api.trim() !== "") {
            influencer.Facebook_api = Facebook_api.trim()

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

// TODO: test populate 

// To get specific job
// Moved it from shared route because this also fetches potentially confidential data such as raw files, final files, etc.
router.get("/job/:jobId", influencerMiddleware, async (req, res) => {
    try {
        const influencer = res.locals.influencerDocument;
        const influencerId = influencer._id;

        const jobId = req.params.jobId;
        if (!jobId) {
            return res.status(400).json({ error: "Job id not provided" })
        }

        const data = await Job.findOne({ customId: jobId, owner: influencerId }).populate("users", "username").populate("owner", "username");

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
        console.log("influencer get Job error", error)
        res.status(500).json({ error: "Unable to fetch Job" });
    }
});


router.get("/myjobs", influencerMiddleware, async (req, res) => {
    try {
        const influencer = res.locals.influencerDocument;
        const influencerId = influencer._id;

        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 25;
        const offSet = (page - 1) * pageSize;
        const totalCount = await Job.countDocuments({ owner: influencerId });
        const totalPages = Math.ceil(totalCount / pageSize);

        const jobs = await Job.find({ owner: influencerId }).skip(offSet).limit(pageSize).sort({ CreatedDate: -1 });

        res.status(200).json(
            {
                page,
                pageSize,
                totalCount,
                totalPages,
                jobs
            }
        );
    } catch (error) {
        console.log("Error Fetching my jobs for influencer", error)
        res.status(500).json({
            error: error
        })
    }


})

// To get my id along with my keys
router.get("/myId", influencerMiddleware, async (req, res) => {
    try {

        const influencer = res.locals.influencerDocument;
        const influencerId = influencer.customId;

        if (!influencerId) {
            return res.status(400).json({ error: "Influencer id not available" })
        }

        const data = await Influencer.findOne({ customId: influencerId }).select('-encryptedPassword -createdJobs');

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
        console.log("fetch influencer profile error", error)
        res.status(500).json({ error: "Unable to fetch influencer" });
    }
});

// to get presigned url to upload raw files
router.put("/uploadPreSigner", influencerMiddleware, async (req, res) => {
    try {
        const { fileName, fileExtension, jobId } = req.body;

        if (!fileName)
            return res.status(400).json({ error: "filename not provided" })

        if (!fileExtension)
            return res.status(400).json({ error: "file extension not provided" })

        if (!jobId)
            return res.status(400).json({ error: "job id not provided" })

        const influencer = res.locals.influencerDocument;
        const influencerId = influencer.customId;

        const job = await Job.findOne({ customId: jobId, owner: influencer._id }).populate("users", "username").populate("owner", "username");

        if (!job)
            return res.status(400).json({ error: "no owned job with provided job id" })

        console.log(`${influencerId}/${jobId}/${fileName}-${cuid()}.${fileExtension}`)
        const url = await getSignedUrl(client,
            new PutObjectCommand({
                Bucket: process.env.AWS_BUCKET,
                Key: `${influencerId}/${jobId}/${fileName}-${cuid()}.${fileExtension}`,
                Metadata: {
                    type: `application/${fileExtension}`
                }
            }),
            { expiresIn: 60 * 5 } // expires in 5 minutes
        )
        res.status(200).json({
            url,
            key: `${influencerId}/${jobId}/${fileName}-${cuid()}.${fileExtension}`
        })
    } catch (error) {
        console.log("Influencer get uploadePreSigner Error", error);
        res.status(500).json({ error: error })
    }
})


router.put("/updateFileKey", influencerMiddleware, async (req, res) => {
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
        // console.log(type)
        if (type !== "rawFile" && type !== "finalFile")
            return res.status(400).json({ error: "invalid file type" })

        const influencer = res.locals.influencerDocument;
        // const influencerId = influencer.customId;
        const job = await Job.findOne({ customId: jobId, owner: influencer._id }).populate("users", "username").populate("owner", "username");

        if (!job)
            return res.status(400).json({ error: "no owned job with provided job id" })

        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiaing a DB session" })
        }

        session.startTransaction();

        if (type === "rawFile") {
            job.rawfiles.push({
                key, fileName
            })
        } else if (type === "finalFile") {
            job.finalFiles.push({
                key, fileName
            })
        }

        await job.save();
        session.commitTransaction();
        session.endSession();
        return res.status(200).json({ message: "file uploaded successfully" })

    } catch (error) {
        console.log("influencer update file key error", error);
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

router.put("/downloadPreSigner", influencerMiddleware, async (req, res) => {
    try {
        const { jobId, key } = req.body;

        if (!jobId)
            return res.status(400).json({ error: "job id not provided" })

        if (!key)
            return res.status(400).json({ error: "file key id not provided" })

        const influencer = res.locals.influencerDocument;

        console.log("jobID", jobId);
        console.log("key", key);

        // {rawfiles:{$elemMatch:{key:"31ee4416-0ce8-441a-a880-e0709172081c/c119c56e-cc23-4cc2-84f9-6da12dd0b333/baaki batien peene baad-clw1ob8q400024gve5agdbomm.mp4"}}}

        const query1 = {
            customId: jobId,
            owner: influencer._id,
            rawFiles: {
                $elemMatch: { key: key }
            }

        }

        const query2 = {
            customId: 'c119c56e-cc23-4cc2-84f9-6da12dd0b333',
            owner: influencer._id,
            rawfiles: {
                $elemMatch:
                {
                    key:key
                        // "31ee4416-0ce8-441a-a880-e0709172081c/c119c56e-cc23-4cc2-84f9-6da12dd0b333/baaki batien peene baad-clw1ob8q400024gve5agdbomm.mp4"
                }
            }
        }






console.log(query1 === query2)

        console.log("query1", query1)
        console.log("query2", query2)
        const job2 = await Job.findOne(query1)
        console.log("job2", job2);


        const job3 = await Job.findOne(query2)

        console.log("job3", job3)



        // { rawfiles: { $elemMatch: { key: "31ee4416-0ce8-441a-a880-e0709172081c/c119c56e-cc23-4cc2-84f9-6da12dd0b333/baaki batien peene baad-clw1ob8q400024gve5agdbomm.mp4" } } }

        // const query = [
        //     {
        //         "rawFiles },
        //     { "editedFiles.key": key },
        //     { "finalFiles.key": key }
        // ]

        const data = await Job.findOne({
            customId: jobId,
            owner: influencer._id,
            $or: [{
                rawfiles: {
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
        console.log("---->")
        console.log(data)

        if (!data)
            return res.status(403).json({ error: "access not available for this file" });


        const url = await getSignedUrl(client,
            new GetObjectCommand({
                Bucket: process.env.AWS_BUCKET,
                Key: key
            }),
            { expiresIn: 60 * 5 }// expires in 5 hours. 
        )

        return res.status(200).json({ url })

    } catch (error) {
        console.log("download presigned error", error);
        res.status(500).json(error)
    }
}

)
module.exports = router;