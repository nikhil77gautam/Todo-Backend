const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  otpcode: {
    type: String,
    required: true,
  },
});

module.exports = mongoose.model("OTP", otpSchema);
