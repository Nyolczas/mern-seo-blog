const mongoose = require('mongoose');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      trim: true,
      required: true,
      max: 32,
      unique: true,
      index: true,
      lowercase: true,
    },
    name: {
      type: String,
      trim: true,
      required: true,
      max: 32,
    },
    email: {
      type: String,
      trim: true,
      required: true,
      unique: true,
      lowercase: true,
      max: 32,
    },
    profile: {
      type: String,
      required: true,
    },
    hashed_password: {
      type: String,
      require: true,
    },
    salt: String,
    about: {
      type: String,
    },
    role: {
      type: Number,
      trim: true,
    },
    photo: {
      data: Buffer,
      contentType: String,
    },
    resetPasswordLink: {
      data: String,
      default: '',
    },
  },
  { timestamp: true }
);

userSchema
  .virtual('password')
  .set(function (password) {
    // create a temporary variable _password
    this._password = password;
    //generate salt
    this.salt = this.maheSalt();
    // encrypt Password
    this.hashed_password = this.encryptPassword(password);
  })
  .get();

userSchema.methods = {
  authenticate: function (plainText) {
    return this.encryptPassword(plainText) === this.hased_password;
  },

  encryptPassword: function (password) {
    if (!password) return '';
    try {
      return crypto
        .createHmac('sha1', this.salt)
        .update(password)
        .digest('hex');
    } catch (e) {
      return '';
    }
  },

  makeSalt: function () {
    return Math.round(new Date().valueOf() * Math.random()) + '';
  },
};

module.exports = mongoose.model('User', userSchema);
