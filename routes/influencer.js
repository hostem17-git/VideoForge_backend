const { Router } = require('express');
const influencerMiddleware = require('../middleware/influencer');
const { Influencer } = require('../db/index');
const jwt = require("jsonwebtoken");
const zod = require("zod");
const bcrypt = require("bcrypt");

const router = Router();
const emailSchema = zod.string().email();

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

        await Influencer.create({
            username: username,
            email: email,
            encryptedPassword: encryptedPassword
        })
        res.status(200).json({ message: "Influencer created successfully" })
    } catch (error) {
        if (error.code == 11000) {
            res.status(409).json({ message: "Email already exists" })
        } else {
            console.error("Error signing up influencer:", error);
            res.status(500).json({ error: "Internal server error" });
        }
    }
});


// TODO: test token expiry
router.post("/SignIn", async (req, res) => {
    const { email, password } = req.body;

    try {
        const influencer = await Influencer.findOne({
            email
        });

        if (!influencer) {
            res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        const match = await bcrypt.compare(password, influencer.encryptedPassword);

        if (!match) {
            res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        const token = jwt.sign({
            email: email,
            role: "influencer"
        }, process.env.JWT_SECRET,
            { expiresIn: JWT_LIFE }
        )

        res.status(200).json({
            token: token
        })


    } catch (err) {
        console.log("Influencer Sign in error", err);
        res.status(500).json({ error: "Internal server error" })
    }



})

// TODO: test populate
// To get specific user
router.get("/user/:userId", influencerMiddleware, async (req, res) => {
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
        console.log("Admin get user error", error)
        res.status(500).json({ error: "Unable to fetch user" });
    }
});

// TODO: test populate
//  Get all users
router.get("/users", influencerMiddleware, async (req, res) => {

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
        console.log("Admin get users error", error)
        res.status(500).json({ error: "Unable to fetch users" });
    }

});


module.exports = router;