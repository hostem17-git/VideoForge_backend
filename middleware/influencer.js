const jwt = require("jsonwebtoken");
const { Influencer } = require("../db");

async function influencerMiddleware(req, res, next) {

    try {
        const cookie = req.cookies;
        if (!cookie || !cookie.token) {
            return res.status(401).json({ error: "Authorization token missing" });
        }
        const token = cookie.token

        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);
        if (decodedValue && decodedValue.role === "influencer") {
            const influencer = await Influencer.findOne({ email: decodedValue.email }).select('-encryptedPassword -Youtube_api -X_api -Instagram_api -Facebook_api -createdJobs')
            if (!influencer.suspended) {
                res.locals.influencerDocument = influencer;
                return next();
            }
            return res.status(403).json({
                error: "User suspended",
                errorReason: influencer.SuspensionReason
            })
        }
        return res.status(403).json({ error: "Unauthorized" })
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "authorization token expired" })
        }
        console.log("Influencer JWT verification error", error)

        res.status(401).json({ error: "Invalid token" })
    }
}

module.exports = influencerMiddleware;