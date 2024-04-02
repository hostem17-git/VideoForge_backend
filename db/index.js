const { default: mongoose } = require("mongoose");

// Create and export db schemas
mongoose.connect(process.env.MONGODB_URL_DEV);

// Admin Schemna 
const AdminSchema = new mongoose.Schema({
 u
})