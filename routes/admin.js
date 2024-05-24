const { Router } = require('express');
const adminMiddleware = require('../middleware/admin');
const { Admin, User, Influencer, Job } = require('../db/index');
const jwt = require("jsonwebtoken");
const zod = require("zod");
const bcrypt = require("bcrypt");
const { JWT_LIFE, DOMAIN } = require('../config')

const mongoose = require("mongoose")
const router = Router();
const emailSchema = zod.string().email();

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

        if (!verifyEmail(email.trim())) {
            return res.status(400).json({ error: "Invalid email provided" })
        }

        const salt = await bcrypt.genSalt(10);
        const encryptedPassword = await bcrypt.hash(password.trim(), salt);

        session = await mongoose.startSesson();
        await session.startTransaction();

        await Admin.create({
            username: username.trim(),
            email: email.trim(),
            encryptedPassword: encryptedPassword
        })

        await session.commitTransaction();
        session.endSession();
        res.status(200).json({ message: "Admin created successfully" })
    } catch (error) {
        if (error.code == 11000) {
            res.status(409).json({ error: "Email already exists" })

        } else {
            console.error("Error signing up admin:", error);
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
        const admin = await Admin.findOne({
            email: email.trim()
        });

        if (!admin) {
            return res.status(401).json({
                error: "user not found"
            })
        }

        if (admin.suspended) {
            return res.status(403).json({
                error: "Admin suspended",
                errorReason: admin.SuspensionReason
            })
        }
        const match = await bcrypt.compare(password.trim(), admin.encryptedPassword);

        if (!match) {
            return res.status(401).json({
                error: "Incorrect password"
            })
        }

        const token = jwt.sign({
            email: email.trim(),
            role: "admin",
        },
            process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        res.cookie("token", token, {
            maxAge: 3600000, // 6 hours
            httpOnly: true,
            //secure:true ,  //To be uncommented when out of localhost,
            sameSite: "lax"
        })

        res.cookie("role", "admin", {
            maxAge: 3600000, // 6 hours
            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: "lax",

        })

        res.cookie('id', admin.customId, {
            maxAge: 3600000, // 6 hours
            // httpOnly: true,
            // secure:true ,  To be uncommented when out of localhost,
            sameSite: "lax",

        })

        res.status(200).json({ message: "admin logged in" })


    } catch (err) {
        console.log("Admin Sign in error", err);
        return res.status(500).json({ error: "Internal server error" })
    }
});

// To get specific admin
router.get("/admin/:adminId", adminMiddleware, async (req, res) => {
    try {
        const adminId = req.params.adminId;
        if (!adminId) {
            return res.status(400).json({ error: "Admin id not provided" })
        }
        const data = await Admin.findOne({ customId: adminId.trim() }).select('-encryptedPassword ');

        if (data) {
            return res.status(200).json({
                data: data
            })
        }
        else {
            return res.status(404).json({
                error: "Admin not found"
            })
        }
    }
    catch (error) {
        console.log("Admin get admin error", error)
        res.status(500).json({ error: "Unable to fetch influencer" });
    }
});

// TODO: Add pagination
//  Get all admins
router.get("/admins", adminMiddleware, async (req, res) => {
    try {
        const data = await Admin.find({}).select('-encryptedPassword ');

        if (data.length > 0) {
            return res.status(200).json({
                data: data
            })
        }
        else {
            return res.status(404).json({
                error: "No Admins found"
            })
        }
    }
    catch (error) {
        console.log("Admin get admins error", error)
        res.status(500).json({ error: "Unable to fetch admins" });
    }
})

// TODO: Test suspend all scenarios
// Suspend entity
router.put("/suspend/:type", adminMiddleware, async (req, res) => {
    let session;
    try {
        const type = req.params.type;

        if (!type) {
            return res.status(400).json({ error: "incorret path" })

        }

        if (!(type.trim() === "user" || type.trim() === "influencer" || type.trim() === "job" || type.trim() === "admin")) {
            return res.status(400).json({ error: "incorret path" })
        }

        const { userId, reason } = req.body;
        if (!userId || !reason) {
            return res.status(400).json({ error: "Invalid input" })
        }
        let Model;
        switch (type.trim()) {
            case "user":
                Model = User;
                break;
            case "influencer":
                Model = Influencer;
                break;
            case "job":
                Model = Job;
                break;
            case "admin":
                Model = Admin;
                break;
            default:
                break;
        }

        const entity = await Model.findOne({ customId: userId.trim() }).select('-encryptedPassword -Youtube_api -X_api -Instagram_api -Facebook_api');

        if (!entity) {
            return res.status(404).json({
                error: `${type} not found`
            })
        }

        if (entity.suspended) {
            return res.status(200).json({ message: `${type} already suspended` })
        }

        session = await mongoose.startSession();
        session.startTransaction();

        entity.suspended = true;
        entity.suspendedOn = new Date();
        entity.SuspensionReason = reason;

        if (type.trim() === "job") {
            entity.Stage = "suspended"
        }

        await entity.save();

        await session.commitTransaction();
        session.endSession();
        return res.status(200).json({
            message: `${type} suspended`
        });

    }
    catch (error) {
        console.log(`Admin suspend ${type} error`, error)
        res.status(500).json({ error: `Unable to suspend ${type}` });
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

// TODO: Test reinstate all scenarios
// reinstate entity
router.put("/reinstate/:type", adminMiddleware, async (req, res) => {
    let session;
    try {
        const type = req.params.type;

        if (!type) {
            return res.status(400).json({ error: "incorret path" })

        }

        if (!(type.trim() === "user" || type.trim() === "influencer" || type.trim() === "job" || type.trim() === "admin")) {
            return res.status(400).json({ error: "incorret path" })
        }

        const { userId } = req.body;
        if (!userId) {
            return res.status(400).json({ error: "Invalid input" })
        }
        let Model;
        switch (type.trim()) {
            case "user":
                Model = User;
                break;
            case "influencer":
                Model = Influencer;
                break;
            case "job":
                Model = Job;
                break;
            case "admin":
                Model = Admin;
                break;
            default:
                break;
        }

        const entity = await Model.findOne({ customId: userId }).select('-encryptedPassword -Youtube_api -X_api -Instagram_api -Facebook_api');

        if (!entity) {
            return res.status(404).json({
                error: `${type} not found`
            })
        }

        if (!entity.suspended) {
            return res.status(400).json({ error: `${type} not suspended,cannot reinstate` })
        }

        session = await mongoose.startSession();
        session.startTransaction();

        entity.suspended = false;

        await entity.save();

        await session.commitTransaction();
        session.endSession();
        return res.status(200).json({
            message: `${type} reinstated`
        });

    }
    catch (error) {
        console.log(`Admin reinstate ${type} error`, error)
        res.status(500).json({ error: `Unable to reinstate ${type}` });
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

module.exports = router;