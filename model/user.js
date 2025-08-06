// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  userId:    { type: String, required: true, unique: true },
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true, lowercase: true },
  password:  { type: String, required: true },
  phone:     { type: String, required: true, unique: true },
  address:  { type: String, default: '' },

  // OTP support
  otpCode:      String,
  otpExpiresAt: Date,
  otpVerified:  { type: Boolean, default: false },

  // New profile fields
  countryId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Country',
    required: function () { return this.otpVerified; }
  },
  country: {
    type: String,
    required: function () { return this.otpVerified; }
  },
  callingId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Country',
    required: function () { return this.otpVerified; }
  },
  callingcode: {
    type: String,
    required: function () { return this.otpVerified; }
  },
  bio: {
    type: String,
    default: ''
  },
  gender: {
    type: Number,
    enum: [0, 1, 2],
    required: function () { return this.otpVerified; }
  },
  passwordResetCode:      String,
  passwordResetExpiresAt: Date,
  passwordResetVerified:  { type: Boolean, default: false }
}, { timestamps: true });

// Hash password
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
