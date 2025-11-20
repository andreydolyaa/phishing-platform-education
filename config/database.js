const mongoose = require('mongoose');

/**
 * Connects to MongoDB database
 * @returns {Promise<void>}
 */
async function connectDatabase() {
  const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/usersDB';

  try {
    await mongoose.connect(MONGO_URI);
    console.log('MongoDB connected');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    throw err;
  }
}

module.exports = { connectDatabase };
