const { Router } = require('express');
const adminMiddleware = require('../middleware/admin');
const { Admin } = require('../db/index');
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
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    const salt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(password, salt);

    if (verifyEmail(email)) {
        try {
            await Admin.create({
                username: username,
                email: email,
                encryptedPassword: encryptedPassword
            })
            res.status(200).json({ message: "Admin created successfully" })
        } catch (e) {
            if (e.code == 11000) {
                res.status(409).json({ message: "email already exists" })
            }
        }
    }
    else {
        res.status(400).json({ error: "Invalid inputs provided" })
    }


})

router.post("/SignIn", async (req, res) => {
    const email = req.body.email;
    const encryptedPassword = req.body.encryptedPassword;

    const admin = Admin.findOne({
        email, encryptedPassword
    });
    if (admin) {
        const token = jwt.sign({
            email: email,
            role: "admin"
        })

        res.status(200).json({
            token: token
        })
    } else {
        res.status(401).json({
            message: "Incorrect credentials"
        })
    }

})

module.exports = router;