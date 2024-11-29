// routes/userRoutes.js

const express = require('express');
const bcrypt = require('bcryptjs'); // Using bcryptjs
const User = require('../models/User'); // Make sure to create a User model as well

const router = express.Router();

// Registration route
router.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error });
  }
});

// Login route
router.post('/login', async (req, res) => {
  try {
    // Sanitize user input
    const sanitizedUsername = sanitize(req.body.username);
    const sanitizedPassword = sanitize(req.body.password);

    // Use parameterized query for secure lookup
    const user = await User.findOne({ username: sanitizedUsername });

    if (user && (await bcrypt.compare(sanitizedPassword, user.password))) {
      return res.status(200).json({ message: 'Login successful!' });
    }

    res.status(401).json({ message: 'Invalid username or password.' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

module.exports = router;
