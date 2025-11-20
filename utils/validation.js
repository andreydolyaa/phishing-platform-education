/**
 * Validates username input
 * @param {string} username - The username to validate
 * @returns {Object} Object with valid flag and optional error message
 */
function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required' };
  }
  if (username.length > 100) {
    return { valid: false, error: 'Username too long (max 100 characters)' };
  }
  if (username.length < 1) {
    return { valid: false, error: 'Username too short' };
  }
  // Allow most characters for phishing simulation
  return { valid: true };
}

module.exports = {
  validateUsername
};
