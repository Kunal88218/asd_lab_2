const express = require('express');
const router = express.Router();
const requireAuth = require('../middleware/requireAuth');
const { getMe, getDashboard } = require('../controllers/userController');

router.get('/me', requireAuth, getMe);
router.get('/dashboard', requireAuth, getDashboard);

module.exports = router;
