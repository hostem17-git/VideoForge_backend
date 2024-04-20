const { Router } = require('express');
const userMiddleware = require('../middleware/user');
const { User } = require('../db/index');
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
            return res.status(401).json({
                message: "Incorrect credentials"
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
                message: "Incorrect credentials"
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


module.exports = router;