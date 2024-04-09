// Video editors
const jwt = require("jsonwebtoken");
const { User } = require("../db");

async function userMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer")) {
        return res.status(401).json({ error: "Authorization token missing" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);
        if (decodedValue && decodedValue.role === "user") {
            const user = await User.findOne({ email: decodedValue.email }).select('-encryptedPassword');
            if (!user.suspended) {
                res.locals.userDocument = user;
                return next();
            }
            return res.status(403).json({
                error: "User suspended",
                errorReason: user.SuspensionReason
            })
        }
        return res.status(403).json({ error: "Unauthorized" })
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "authorization token expired" })
        }
        console.log("User JWT verification error", error)
        res.status(401).json({ error: "Invalid inputs" })
    }
}

module.exports = userMiddleware;