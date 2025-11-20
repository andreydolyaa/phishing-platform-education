const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { timingSafeCompare } = require('../utils/crypto');

/**
 * Display all captured users
 * Protected by secret key query parameter
 * Renders EJS template with user data
 */
router.get('/users', async (req, res) => {
  const { key } = req.query;

  // Validate secret key
  if (!timingSafeCompare(key, process.env.SECRET_KEY)) {
    return res.status(403).send('Forbidden: Invalid or missing key');
  }

  try {
    const users = await User.find().sort({ createdAt: -1 });
    console.log('Fetched users list - count:', users.length);
    res.render('users', { users });
  } catch (err) {
    console.error('Error fetching users');
    res.status(500).send('An error occurred while processing your request');
  }
});

/**
 * Delete all users from database
 * Protected by secret key query parameter
 * Use for training session reset
 */
router.get('/delete-all', async (req, res) => {
  try {
    const { key } = req.query;

    // Validate secret key
    if (!timingSafeCompare(key, process.env.SECRET_KEY)) {
      console.warn('Unauthorized delete-all attempt from IP:', req.ip);
      return res.status(403).send('Forbidden: Invalid or missing key');
    }

    const result = await User.deleteMany({});
    console.log('All users deleted - count:', result.deletedCount);
    res.send(`Successfully deleted ${result.deletedCount} users`);
  } catch (err) {
    console.error('Error deleting users');
    res.status(500).send('An error occurred while processing your request');
  }
});

module.exports = router;
