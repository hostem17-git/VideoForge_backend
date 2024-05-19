const express = require('express');
const jwt = require("jsonwebtoken")
const cors = require("cors")
const cookieParser = require("cookie-parser");
require('dotenv').config();

const bodyParser = require('body-parser');
const adminRouter = require("./routes/admin");
const userRouter = require("./routes/user");
const influencerRouter = require("./routes/influencer");
const sharedRouter = require("./routes/shared");

const corsOptions = {
    origin: 'http://localhost:5173', // Allow requests from this origin
    methods: ['GET', 'POST', 'PUT'],       // Allow these HTTP methods
    // allowedHeaders: ['Content-Type'], // Allow these headers
    credentials: true
}

const app = express()
app.use(cookieParser());

app.use(bodyParser.json());
app.use(cors(corsOptions))
app.use("/api/v1/admin", adminRouter);
app.use("/api/v1/user", userRouter);
app.use("/api/v1/influencer", influencerRouter);
app.use("/api/v1/shared", sharedRouter);

app.all("*", (req, res) => {
    console.log("hit")
    res.status(404).json({ "error": "Resource not found" });
})

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});