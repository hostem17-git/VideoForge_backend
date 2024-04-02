const express = require('express');
require('dotenv').config();

const bodyParser = require('body-parser');
const app = express()

const adminRouter = require("./routes/admin");
const userRouter = require("./routes/user");
const influencerRouter = require("./routes/influencer");

const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});