const { Router } = require('express');
const userMiddleware = require('../middleware/user');
const { User } = require('../db/index');
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

        await User.create({
            username: username,
            email: email,
            encryptedPassword: encryptedPassword
        })
        res.status(200).json({ message: "User created successfully" })
    } catch (error) {
        if (error.code == 11000) {
            res.status(409).json({ message: "Email already exists" })
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
            res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        const match = await bcrypt.compare(password, user.encryptedPassword);

        if (!match) {
            res.status(401).json({
                message: "Incorrect credentials"
            })
        }

        const token = jwt.sign({
            email: email,
            role: "user"
        },process.env.JWT_SECRET)

        res.status(200).json({
            token: token
        })


    } catch (err) {
        console.log("User Sign in error", err);
        res.status(500).json({ error: "Internal server error" })
    }



})

module.exports = router;