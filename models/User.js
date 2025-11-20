const mongoose = require('mongoose');

/**
 * User Schema for tracking phishing platform activity
 * Stores username and array of click events with metadata
 */
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  clicks: [{
    timestamp: { type: Date, default: Date.now },
    ip: String,
    userAgent: String,
    host: String,
    referer: String
  }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
