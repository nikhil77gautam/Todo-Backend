const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: String,
  email: {
    type: String,
    Unique: true,
  },
  emailVerified: {
    type: Boolean,
    default: false,
    required: true,
  },
  password: String,
});

module.exports = mongoose.model("UserTodos", UserSchema);
