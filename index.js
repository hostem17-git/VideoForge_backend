const express = require('express');
const jwt = require("jsonwebtoken")
require('dotenv').config();

const bodyParser = require('body-parser');
const adminRouter = require("./routes/admin");
const userRouter = require("./routes/user");
const influencerRouter = require("./routes/influencer");
const sharedRouter = require("./routes/shared");

const app = express()
app.use(bodyParser.json());
app.use("/api/v1/admin", adminRouter);
app.use("/api/v1/user", userRouter);
app.use("/api/v1/influencer", influencerRouter);
app.use("/api/v1/shared", sharedRouter);


const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});