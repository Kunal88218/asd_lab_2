const prisma = require('../db/prisma');

/**
 * GET /me
 * Protected endpoint returning current user profile
 */
async function getMe(req, res) {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt
    });
  } catch (err) {
    return res.status(500).json({ error: 'An unexpected server error occurred' });
  }
}

/**
 * GET /dashboard
 * Protected endpoint returning personalized greeting
 */
async function getDashboard(req, res) {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        email: true,
        name: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const displayName = (user.name && user.name.trim().length > 0) ? user.name.trim() : user.email;

    return res.status(200).json({
      message: `Welcome, ${displayName}!`
    });
  } catch (err) {
    return res.status(500).json({ error: 'An unexpected server error occurred' });
  }
}

module.exports = {
  getMe,
  getDashboard
};
