const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { validateToken } = require('../utils/crypto');

/**
 * Track user via secure token
 * Public endpoint that logs click data and redirects to target site
 */
router.get('/t/:token', async (req, res) => {
  try {
    const { token } = req.params;

    // Validate and decode token
    const validation = validateToken(token);
    if (!validation.valid) {
      console.warn('Invalid token attempt from IP:', req.ip);
      return res.status(403).send('Invalid tracking link');
    }

    const username = validation.username;

    // Capture user data
    const clickData = {
      timestamp: new Date(),
      ip: req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      host: req.headers.host,
      referer: req.headers.referer || req.headers.referrer
    };

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      // Add new click with data
      existingUser.clicks.push(clickData);
      await existingUser.save();
      console.log('User re-captured via token - Total clicks:', existingUser.clicks.length);
      return res.redirect('https://buyme.co.il');
    }

    // Create new user with first click data
    const newUser = new User({
      username,
      clicks: [clickData]
    });
    await newUser.save();
    console.log('New user captured via token');
    res.redirect('https://buyme.co.il');
  } catch (err) {
    console.error('Error in token tracking endpoint');
    res.status(500).send('An error occurred while processing your request');
  }
});

module.exports = router;
