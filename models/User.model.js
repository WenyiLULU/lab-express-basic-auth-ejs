const { Schema, model } = require("mongoose");

// TODO: Please make sure you edit the user model to whatever makes sense in this case
const userSchema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: String,
  email: {
    type: String,
    required: true,
    unique: true,
    match:[/^\S+@\S+\.\S+$/, 'Please use a valid email address.'],
  }
});

const User = model("User", userSchema);

module.exports = User;
