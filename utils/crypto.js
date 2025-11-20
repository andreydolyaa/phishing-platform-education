const crypto = require('crypto');

/**
 * Performs timing-safe comparison of two strings to prevent timing attacks
 * @param {string} a - First string to compare
 * @param {string} b - Second string to compare
 * @returns {boolean} True if strings match, false otherwise
 */
function timingSafeCompare(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generates a secure token for a username using HMAC
 * @param {string} username - The username to generate token for
 * @returns {string} Base64url encoded token
 */
function generateToken(username) {
  const hmac = crypto.createHmac('sha256', process.env.SECRET_KEY);
  hmac.update(username);
  const signature = hmac.digest('hex');
  const token = Buffer.from(`${username}:${signature}`).toString('base64url');
  return token;
}

/**
 * Validates and decodes a token
 * @param {string} token - The token to validate
 * @returns {Object} Object with valid flag and username or error message
 */
function validateToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    const [username, signature] = decoded.split(':');

    if (!username || !signature) {
      return { valid: false, error: 'Invalid token format' };
    }

    // Recalculate HMAC
    const hmac = crypto.createHmac('sha256', process.env.SECRET_KEY);
    hmac.update(username);
    const expectedSignature = hmac.digest('hex');

    // Timing-safe comparison
    if (!timingSafeCompare(signature, expectedSignature)) {
      return { valid: false, error: 'Invalid token signature' };
    }

    return { valid: true, username };
  } catch (err) {
    return { valid: false, error: 'Token decode failed' };
  }
}

module.exports = {
  timingSafeCompare,
  generateToken,
  validateToken
};
