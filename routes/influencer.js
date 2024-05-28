const { Router } = require('express');
const influencerMiddleware = require('../middleware/influencer');
const { Influencer, Job, User } = require('../db/index');
const jwt = require("jsonwebtoken");
const zod = require("zod");
const bcrypt = require("bcrypt");
const { validate } = require('uuid');
const { JOB_SCHEMA_OPTIONS, DOMAIN, JWT_LIFE } = require('../config')
const mongoose = require("mongoose");
const { route } = require('./admin');
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3")
const cuid = require("cuid");
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const { OAuth2Client, UserRefreshClient } = require('google-auth-library');

const { LambdaClient, InvokeCommand } = require('@aws-sdk/client-lambda');


const router = Router();

const client = new S3Client({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_KEY
    }
})


const lambdaClient = new LambdaClient({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: process.env.AWS_LAMBDA_ACCESS_KEY,
        secretAccessKey: process.env.AWS_LAMBDA_SECRET_KEY
    }
});

const oAuth2ClientGoogle = new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET,
    "postmessage"
)


const getAccessToken = async (influencer, res, req, session) => {
    const expiry = new Date(influencer.googleAccessTokenExpiry).getTime();
    const present = new Date.getTime();

    if (expiry > present + 5 * 60 * 10000) {// 5 minutes till acccess token expires
        return influencer.googleAccessToken;
    } else {
        let session;
        try {
            const user = new UserRefreshClient(
                process.env.GOOGLE_CLIENT_ID,
                process.env.GOOGLE_CLIENT_SECRET,
                req.body.refreshToken,
            );
            const { tokens } = await user.refreshAccessToken(); // optain new tokens

            session = await mongoose.startSession();

            if (!session) {
                return res.status(500).json({ error: "Error initiaing a DB session" })
            }

            session.startTransaction();

            const expiry_date = new Date(tokens.expiry_date)

            influencer.googleAccessToken = tokens.access_token;
            influencer.googleAccessTokenExpiry = expiry_date;
            influencer.googleAcessScope = tokens.scope;

            await influencer.save();

            session.commitTransaction();
            session.endSession();

            return tokens.access_token
        } catch (error) {
            console.log("Influencer google authorization refresh token error", error);
            throw error;
            if (session) {
                await session.abortTransaction();
                session.endSession();
            }
        } finally {
            if (session)
                session.endSession();
        }

    }
}

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
// TODO: Handle singin attempt from SSO logged user
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

        res.cookie("token", token, {
            maxAge: 3600000, // 6 hours
            httpOnly: true,
            //secure:true ,  //To be uncommented when out of localhost,
            sameSite: "lax"
        })

        res.cookie("role", "creator", {
            maxAge: 3600000, // 6 hours
            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,

            sameSite: "lax"
        })

        res.cookie('id', influencer.customId, {
            maxAge: 3600000, // 6 hours

            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: "lax"
        })

        res.status(200).json({ message: "influencer logged in" })



    } catch (err) {
        console.log("Influencer Sign in error", err);
        return res.status(500).json({ error: "Internal server error" })
    }
});

// TODO: How to make it secure???????????????????  | Reset via link???
router.post("/reset-password", async (req, res) => {

})

// To create a new job
//  Check if we need to refetch influencer document as owner or not
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


        const influencer = res.locals.influencerDocument;

        const influencerMail = influencer.email


        const owner = await Influencer.findOne({ email: influencerMail.trim() }).select('-encryptedPassword -Youtube_api -X_api -Instagram_api -Facebook_api');

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

        const influencer = res.locals.influencerDocument;

        const influencerMail = influencer.email

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


        const influencer = res.locals.influencerDocument;

        const influencerMail = influencer.email

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


        const key = `${influencerId}/${jobId}/${fileName}-${cuid()}.${fileExtension}`

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
        console.log("Influencer get uploadePreSigner Error", error);
        res.status(500).json({ error: "Internal server error" })
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
        if (type !== "rawFile" && type !== "finalFile")
            return res.status(400).json({ error: "invalid file type" })

        const influencer = res.locals.influencerDocument;
        const job = await Job.findOne({ customId: jobId, owner: influencer._id }).populate("users", "username").populate("owner", "username");

        if (!job)
            return res.status(400).json({ error: "no owned job with provided job id" })

        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiaing a DB session" })
        }

        session.startTransaction();

        if (type === "rawFile") {
            job.rawFiles.push({
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
        res.status(500).json({ error: "Internal server error" })
        if (session) {
            await session.abortTransaction();
            session.endSession();
        }
    } finally {
        if (session)
            session.endSession();
    }
})

router.put("/approveFile", influencerMiddleware, async (req, res) => {
    let session;
    try {
        const { key, jobId } = req.body;

        if (!key)
            return res.status(400).json({ error: "key not provided" });
        if (!jobId)
            return res.status(400).json({ error: "job id not provided" });

        const influencer = res.locals.influencerDocument;
        const job = await Job.findOne({ customId: jobId, owner: influencer._id })

        if (!job)
            return res.status(400).json({ error: "no owned job with provided job id" })

        let editedFiles = job.editedFiles;

        const finalFile = editedFiles.filter(file => file.key === key)

        if (finalFile.length === 0)
            return res.status(400).json({ error: "provided file not in edited files list" })

        editedFiles = editedFiles.filter(file => file.key !== key)
        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiaing a DB session" })
        }

        session.startTransaction();

        job.finalFiles.push(finalFile[0]);

        job.editedFiles = editedFiles;

        await job.save();
        session.commitTransaction();
        session.endSession();
        return res.status(200).json({ message: "file approved successfully" })

    } catch (error) {
        console.log("influencer update file key error", error);
        res.status(500).json({ error: "Internal server error" })
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

        const data = await Job.findOne({
            customId: jobId,
            owner: influencer._id,
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
            { expiresIn: 60 * 5 }// expires in 5 hours. 
        )

        return res.status(200).json({ url })

    } catch (error) {
        console.log("download presigned error", error);
        res.status(500).json(error)
    }
}
)

router.get("/checkAuthorized", influencerMiddleware, async (req, res) => {
    try {

        const influencer = res.locals.influencerDocument;

        if (influencer.googleAccessToken && influencer.refreshAccessToken) {
            return res.status(200).json({ message: "authorized" })
        }

        res.status(403).json({ error: "not authorised" })

    } catch (error) {
        console.log("influencer check authorized error", error);
        res.status(500).json({ error: "Internal server error" })
    }
});


router.put("/uploadToYoutube", influencerMiddleware, async (req, res) => {
    const Bucket = process.env.AWS_BUCKET;
    let session;
    try {
        const { key, jobId, title, description, categoryId } = req.body;

        // Validate request body
        if (!key || !jobId || !title || !description || !categoryId) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const influencer = res.locals.influencerDocument;

        // Find the job
        const job = await Job.findOne({ customId: jobId, owner: influencer._id });
        if (!job) {
            return res.status(400).json({ error: "No owned job with provided job id" });
        }

        // Check if the file is in final files list
        const finalFile = job.finalFiles.find(file => file.key === key);
        if (!finalFile) {
            return res.status(400).json({ error: "Provided file not in final files list" });
        }

        const expiry = new Date(influencer.googleAccessTokenExpiry).getTime();
        const present = new Date().getTime();
        let accessToken = influencer.googleAccessToken;

        if (expiry <= present + 5 * 60 * 1000) { // 5 minutes till access token expires
            try {
                const user = new UserRefreshClient(
                    process.env.GOOGLE_CLIENT_ID,
                    process.env.GOOGLE_CLIENT_SECRET,
                    influencer.googleRefreshToken
                );

                const { credentials } = await user.refreshAccessToken(); // obtain new tokens

                session = await mongoose.startSession()

                if (!session) {
                    return res.status(500).json({ error: "Error initiaing a DB session" })
                }
                session.startTransaction();

                influencer.googleAccessToken = credentials.access_token;
                influencer.googleAccessTokenExpiry = new Date(credentials.expiry_date);
                influencer.googleAccessScope = credentials.scope;

                await influencer.save({ session });

                await session.commitTransaction();
                session.endSession();


                accessToken = credentials.access_token;
            } catch (error) {
                console.error("Influencer google authorization refresh token error", error);
                if (session) {
                    session.endSession();
                    session.abortTransaction();
                }
                return res.status(500).json({ error: "Internal server error" });

            } finally {
                if (session) {
                    session.endSession()
                }
            }
        }
        console.log("accessToken")
        console.log(accessToken)
        // Calling AWS Lambda
        const jwtToken = jwt.sign(
            { email: influencer.email.trim(), role: "influencer" },
            process.env.AWS_JWT_SECRET,
            { expiresIn: JWT_LIFE }
        );
        console.log("jwtToken")
        console.log(jwtToken)
        console.log("Bucket", Bucket);
        console.log("key", key)


        const params = {
            FunctionName: 'videoForge_upload_youtube', // Replace with your Lambda function name
            InvocationType: 'RequestResponse',
            Payload: JSON.stringify({
                youtube_access_token: accessToken,
                s3_bucket_name: Bucket,
                s3_file_key: key,
                jwt_token: jwtToken,
                title,
                description,
                categoryId
            })
        };


        console.log(params);
        const command = new InvokeCommand(params);
        const result = await lambdaClient.send(command);
        console.log("Result", result);
        const payload = JSON.parse(Buffer.from(result.Payload).toString());
        console.log("payload", payload)
        session = await mongoose.startSession();
        session.startTransaction();

        job.Stage = "uploaded";
        await job.save({ session });

        await session.commitTransaction();
        session.endSession()
        return res.status(200).json(payload);

    } catch (error) {
        console.error("Influencer upload to youtube key error", error);
        if (session) {
            session.endSession();
            session.abortTransaction();
        }
        return res.status(500).json({ error: "Internal server error" });
    } finally {
        if (session) {
            session.endSession()
        }
    }
});
router.post("/auth/google", influencerMiddleware, async (req, res) => {
    let session;
    try {
        const { tokens } = await oAuth2ClientGoogle.getToken(req.body.code);

        console.log(tokens);

        const influencer = res.locals.influencerDocument;

        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiaing a DB session" })
        }

        session.startTransaction();

        const expiry_date = new Date(tokens.expiry_date)

        influencer.googleAccessToken = tokens.access_token;
        influencer.googleAccessTokenExpiry = expiry_date;
        influencer.googleRefreshToken = tokens.refresh_token;
        influencer.googleAcessScope = tokens.scope;

        await influencer.save();

        session.commitTransaction();
        session.endSession();

        res.status(200).json(tokens);
    } catch (error) {
        console.log("Influencer google authorization error", error);
        res.status(500).json({ error: "Internal server error" });
        if (session) {
            await session.abortTransaction();
            session.endSession();
        }
    } finally {
        if (session)
            session.endSession();
    }
});

router.post('/auth/google/refresh-token', async (req, res) => {

    let session;
    try {
        const user = new UserRefreshClient(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            req.body.refreshToken,
        );
        const { tokens } = await user.refreshAccessToken(); // optain new tokens
        // res.json(tokens);
        console.log(tokens)

        const influencer = res.locals.influencerDocument;
        session = await mongoose.startSession();

        if (!session) {
            return res.status(500).json({ error: "Error initiaing a DB session" })
        }

        const accessToken = getAccessToken(influencer, res, req)

        session.startTransaction();

        const expiry_date = new Date(tokens.expiry_date)

        influencer.googleAccessToken = tokens.access_token;
        influencer.googleAccessTokenExpiry = expiry_date;
        // influencer.googleRefreshToken = tokens.refresh_token;
        influencer.googleAcessScope = tokens.scope;

        await influencer.save();

        session.commitTransaction();
        session.endSession();

        res.status(200).json(tokens);
    } catch (error) {
        console.log("Influencer google authorization error", error);
        res.status(500).json({ error: "Internal server error" });
        if (session) {
            await session.abortTransaction();
            session.endSession();
        }
    } finally {
        if (session)
            session.endSession();
    }

})

module.exports = router;