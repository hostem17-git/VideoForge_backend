const express = require('express');
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


const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});