const jwt = require("jsonwebtoken");

function adminMiddleware(req, res, next) {
    console.log("in Admin middlewate")
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer")) {
        return res.status(401).json({ error: "Authorization token missing" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);
        console.log("-----------------");
        console.log(decodedValue);
        console.log("-----------------")

        if (decodedValue && decodedValue.role === "admin") {
            return next();
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