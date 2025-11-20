require('dotenv').config();
const { createApp } = require('./config/app');
const { connectDatabase } = require('./config/database');
const adminRoutes = require('./routes/admin.routes');
const trackingRoutes = require('./routes/tracking.routes');
const usersRoutes = require('./routes/users.routes');

const PORT = process.env.PORT || 3000;

/**
 * Initialize and start the server
 */
async function startServer() {
  try {
    // Connect to database
    await connectDatabase();

    // Create Express app with middleware
    const app = createApp();

    // Register routes
    app.use('/', adminRoutes);
    app.use('/', trackingRoutes);
    app.use('/', usersRoutes);

    // Start server
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

// Start the server
startServer();
