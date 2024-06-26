const jwt = require("jsonwebtoken");

// middleware to be used for shared paths - common paths for all user personas 
function sharedAccessMiddleware(req, res, next) {
        try {
        const cookie = req.cookies;
        if (!cookie || !cookie.token) {
            return res.status(401).json({ error: "Authorization token missing" });
        }
        const token = cookie.token

        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);

        if (decodedValue) {
            return next();
        }
        return res.status(403).json({ error: "Unauthorized" })
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "authorization token expired" })
        }
        console.log("shared JWT verification error", error)
        res.status(401).json({ error: "Invalid token" })
    }
}

module.exports = sharedAccessMiddleware 