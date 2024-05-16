const jwt = require("jsonwebtoken");
const { Admin } = require("../db");

async function adminMiddleware(req, res, next) {

    try {
        const cookie = req.cookies;
        if (!cookie || !cookie.token) {
            return res.status(401).json({ error: "Authorization token missing" });
        }
        const token = cookie.token

        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);
        if (decodedValue && decodedValue.role === "admin") {
            const admin = await Admin.findOne({ email: decodedValue.email });
            if (!admin.suspended) {
                return next();
            }
            else {
                return res.status(403).json({
                    error: "User suspended",
                    errorReason: admin.SuspensionReason
                })
            }
        }
        return res.status(403).json({ error: "Unauthorized" })
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "authorization token expired" })
        }
        console.log("admin JWT verification error", error)
        res.status(401).json({ error: "Invalid inputs" })
    }
}

module.exports = adminMiddleware;