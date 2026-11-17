const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const prisma = require('../db/prisma');

const INVALID_CREDENTIALS_MSG = 'Invalid email or password';

/**
 * POST /signup
 * Register a new user
 */
async function signup(req, res) {
  try {
    const { email, password, name } = req.body || {};

    // Validate email and password are provided as strings
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Email and password are required and must be strings'
      });
    }

    // Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail) {
      return res.status(400).json({
        error: 'Email cannot be empty'
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({
        error: 'Password must be at least 6 characters long'
      });
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (existingUser) {
      return res.status(409).json({
        error: 'Email is already registered'
      });
    }

    // Hash password with salt rounds = 10
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user in database
    const newUser = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        name: typeof name === 'string' && name.trim().length > 0 ? name.trim() : null
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true
      }
    });

    // Generate JWT token (expires in 1 hour)
    const token = jwt.sign(
      {
        id: newUser.id,
        email: newUser.email,
        jti: crypto.randomUUID()
      },
      process.env.JWTSECRET,
      { expiresIn: '1h' }
    );

    return res.status(201).json({
      message: 'User registered successfully',
      user: newUser,
      token
    });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({
        error: 'Email is already registered'
      });
    }
    return res.status(500).json({
      error: 'An unexpected server error occurred'
    });
  }
}

/**
 * POST /login
 * Authenticate user and return JWT
 */
async function login(req, res) {
  try {
    const { email, password } = req.body || {};

    // Validate fields as strings
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Email and password are required and must be strings'
      });
    }

    // Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail || !password) {
      return res.status(400).json({
        error: 'Email and password cannot be empty'
      });
    }

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    // Use same generic message for unknown email and incorrect password
    if (!user) {
      return res.status(401).json({
        error: INVALID_CREDENTIALS_MSG
      });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        error: INVALID_CREDENTIALS_MSG
      });
    }

    // Generate JWT token (expires in 1 hour)
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        jti: crypto.randomUUID()
      },
      process.env.JWTSECRET,
      { expiresIn: '1h' }
    );

    return res.status(200).json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt
      },
      token
    });
  } catch (err) {
    return res.status(500).json({
      error: 'An unexpected server error occurred'
    });
  }
}

module.exports = {
  signup,
  login
};
