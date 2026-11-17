require('dotenv').config();
const express = require('express');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

// Validate required environment variables on startup
const requiredEnv = ['DATABASE_URL', 'JWTSECRET'];
const missingEnv = requiredEnv.filter(varName => !process.env[varName] || !process.env[varName].trim());

if (missingEnv.length > 0) {
  console.error(`FATAL: Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware for parsing JSON bodies
app.use(express.json());

// Handle malformed JSON body
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed JSON payload' });
  }
  next();
});

// Root / health route
app.get('/', (req, res) => {
  res.json({ message: 'User Authentication API is running' });
});

// Mount routes
app.use(authRoutes);
app.use(userRoutes);

// Optional /api prefix alias for convenience
app.use('/api', authRoutes);
app.use('/api', userRoutes);

// 404 handler for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

let server;
if (require.main === module) {
  server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

module.exports = { app, server };
