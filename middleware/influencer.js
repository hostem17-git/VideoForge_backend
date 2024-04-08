const jwt = require("jsonwebtoken");

function adminMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: "Authorization token missing" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);
        if (decodedValue && decodedValue.role === "influencer") {
            return next();
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

module.exports = adminMiddleware;