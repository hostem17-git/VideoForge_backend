const express = require('express');
const jwt = require("jsonwebtoken")
require('dotenv').config();

const bodyParser = require('body-parser');
const adminRouter = require("./routes/admin");
const userRouter = require("./routes/user");
const influencerRouter = require("./routes/influencer");

const app = express()
app.use(bodyParser.json());
app.use("/admin", adminRouter);
app.use("/user", userRouter);
app.use("/influencer", influencerRouter);


app.get("/userValidation/:token", (req, res) => {

    try {
        const token = req.params.token;
        if (!token) {
            res.status(400).json({ error: "Token missing" });
        }
        const decodedValue = jwt.verify(token, process.env.JWT_SECRET);
        if (decodedValue) {
            res.status(200).json({
                userValid: true,
                role: decodedValue.role
            })
        }
        return res.status(403).json({
            userValid: true,
            error: "Unauthorized"
        })
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "authorization token expired" })
        }
        console.log("admin JWT verification error", error)
        res.status(401).json({ error: "Invalid inputs" })
    }
})

const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});