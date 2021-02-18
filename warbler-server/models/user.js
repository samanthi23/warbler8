const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  profileImageUrl: {
    type: String
  }
});

// add hooks
// to handle errors use a try/catch block
// parameter that is passed to this function
// which in middleware is next

// wait for the password to hash
// then sets password to the hashed password
// then it will save that specific document
userSchema.pre("save", async function(next) {
  try {
    if (!this.isModified("password")) {
      return next();
      // move on, go ahead and save it now
    }
    // create a hashedPassword
    // this password
    // await, asynchornous function,
    // so wait until it finishes
    let hashedPassword = await bcrypt.hash(this.password, 10);
    // once it is finished set
    this.password = hashedPassword;
    // middleware, return next
    return next();
  } catch (err) {
    // goes to our error handler
    return next(err);
  }
});

// helper function for our user.js
// instance method
// async when to move on to the next piece

// added a pre-save hook

// the second thing we did was build
// a password comparison function
// to make sure users have put in successfully the right password
userSchema.methods.comparePassword = async function(candidatePassword, next) {
  // try catch to handle any kind of error
  try {
    let isMatch = await bcrypt.compare(candidatePassword, this.password);
    return isMatch;
  } catch (err) {
    return next(err);
  }
};

// the next step is adding some routes and testing them

const User = mongoose.model("User", userSchema);

module.exports = User;
