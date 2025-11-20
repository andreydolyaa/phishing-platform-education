const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');

/**
 * Configures and returns an Express application with middleware
 * @returns {express.Application} Configured Express app
 */
function createApp() {
  const app = express();

  // Security middleware (COMPLETELY DISABLED for HTTP testing)
  // app.use(helmet({
  //   crossOriginOpenerPolicy: false,
  //   crossOriginEmbedderPolicy: false,
  //   originAgentCluster: false,
  //   hsts: false, // Disable HSTS to allow HTTP (not forcing HTTPS)
  //   contentSecurityPolicy: {
  //     directives: {
  //       defaultSrc: ["'self'"],
  //       styleSrc: ["'self'", "'unsafe-inline'"],
  //       scriptSrc: ["'self'", "'unsafe-inline'"],
  //       scriptSrcAttr: ["'unsafe-inline'"],
  //     }
  //   }
  // }));

  // CORS configuration
  app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    credentials: true
  }));

  // Body parsing middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // View engine configuration
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '../views'));

  return app;
}

module.exports = { createApp };
