const { Router } = require('express');
const adminMiddleware = require('../middleware/admin');
const { Admin, User, Influencer, Job } = require('../db/index');
const jwt = require("jsonwebtoken");
const zod = require("zod");
const bcrypt = require("bcrypt");
const { JWT_LIFE } = require('../config')

const router = Router();
const emailSchema = zod.string().email();

function verifyEmail(email) {
    const response = emailSchema.safeParse(email);
    return response.success;
}

router.post("/Signup", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
        return res.status(400).json({ error: "missing inputs" })

    if (!verifyEmail(email)) {
        return res.status(400).json({ error: "Invalid email provided" })
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const encryptedPassword = await bcrypt.hash(password, salt);

        await Admin.create({
            username: username,
            email: email,
            encryptedPassword: encryptedPassword
        })
        res.status(200).json({ message: "Admin created successfully" })
    } catch (error) {
        if (error.code == 11000) {
            res.status(409).json({ message: "Email already exists" })
        } else {
            console.error("Error signing up admin:", error);
            res.status(500).json({ error: "Internal server error" });
        }
    }
});

router.post("/SignIn", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ error: "missing inputs" });

    try {
        const admin = await Admin.findOne({
            email
        });

        if (!admin) {
            return res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        if (admin.suspended) {
            return res.status(403).json({
                error: "Admin suspended",
                errorReason: admin.SuspensionReason
            })
        }
        const match = await bcrypt.compare(password, admin.encryptedPassword);

        if (!match) {
            return res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        const token = jwt.sign({
            email: email,
            role: "admin",
        },
            process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        return res.status(200).json({
            token: token
        })


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
        const data = await Admin.findOne({ customId: adminId }).select('-encryptedPassword ');

        if (data) {
            return res.status(200).json({
                data: data
            })
        }
        else {
            return res.status(404).json({
                message: "Admin not found"
            })
        }
    }
    catch (error) {
        console.log("Admin get admin error", error)
        res.status(500).json({ error: "Unable to fetch influencer" });
    }
});

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
                message: "No Admins found"
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
    try {
        const type = req.params.type;

        if (!(type === "user" || type === "influencer" || type === "job" || type === "admin")) {
            return res.status(400).json({ message: "incorret path" })
        }

        const { userId, reason } = req.body;
        if (!userId || !reason) {
            return res.status(400).json({ error: "Invalid input" })
        }
        let Model;
        switch (type) {
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

        const entity = await Model.findOne({ customId: userId }).select('-encryptedPassword ');

        if (!entity) {
            return res.status(404).json({
                message: `${type} not found`
            })
        }

        if (entity.suspended) {
            return res.status(200).json({ message: `${type} already suspended` })
        }

        entity.suspended = true;
        entity.suspendedOn = new Date();
        entity.SuspensionReason = reason;

        if (type === "job") {
            entity.Stage = "suspended"
        }

        await entity.save();

        return res.status(200).json({
            message: `${type} suspended`
        });

    }
    catch (error) {
        console.log(`Admin suspend ${type} error`, error)
        res.status(500).json({ error: `Unable to suspend ${type}` });
    }
});

// TODO: Test reinstate all scenarios
// reinstate entity
router.put("/reinstate/:type", adminMiddleware, async (req, res) => {
    try {
        const type = req.params.type;

        if (!(type === "user" || type === "influencer" || type === "job" || type === "admin")) {
            return res.status(400).json({ message: "incorret path" })
        }

        const { userId } = req.body;
        if (!userId) {
            return res.status(400).json({ error: "Invalid input" })
        }
        let Model;
        switch (type) {
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

        const entity = await Model.findOne({ customId: userId }).select('-encryptedPassword ');

        if (!entity) {
            return res.status(404).json({
                message: `${type} not found`
            })
        }

        if (!entity.suspended) {
            return res.status(400).json({ message: `${type} not suspended,cannot reinstate` })
        }

        entity.suspended = false;

        await entity.save();

        return res.status(200).json({
            message: `${type} reinstated`
        });

    }
    catch (error) {
        console.log(`Admin reinstate ${type} error`, error)
        res.status(500).json({ error: `Unable to reinstate ${type}` });
    }
});

module.exports = router;