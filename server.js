require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

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
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true
}));

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/usersDB';
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  clicks: [{
    timestamp: { type: Date, default: Date.now },
    ip: String,
    userAgent: String,
    host: String,
    referer: String
  }],
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Timing-safe key comparison
function timingSafeCompare(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Input validation helper
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

// Generate secure token for username
function generateToken(username) {
  const hmac = crypto.createHmac('sha256', process.env.SECRET_KEY);
  hmac.update(username);
  const signature = hmac.digest('hex');
  const token = Buffer.from(`${username}:${signature}`).toString('base64url');
  return token;
}

// Validate and decode token
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

// Admin page for generating links
app.get('/admin', (req, res) => {
  const { key } = req.query;

  // Validate secret key
  if (!timingSafeCompare(key, process.env.SECRET_KEY)) {
    return res.status(403).send('Forbidden: Invalid or missing key');
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin - Link Generator</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: 'Courier New', monospace;
          background: #000;
          color: #00ff00;
          min-height: 100vh;
          padding: 40px 20px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .container {
          max-width: 900px;
          width: 100%;
        }
        h1 {
          font-size: 2em;
          color: #ff0000;
          text-align: center;
          margin-bottom: 10px;
          text-shadow: 0 0 20px #ff0000;
        }
        .subtitle {
          text-align: center;
          color: #00ff00;
          margin-bottom: 40px;
          letter-spacing: 2px;
          text-transform: uppercase;
          font-size: 0.9em;
        }
        .panel {
          background: #151515;
          border: 2px solid #00ff00;
          padding: 30px;
          box-shadow: 0 0 30px rgba(0, 255, 0, 0.3);
        }
        label {
          display: block;
          font-size: 0.8em;
          color: #888;
          margin-bottom: 8px;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        input {
          width: 100%;
          padding: 12px;
          background: #000;
          border: 2px solid #00ff00;
          color: #00ff00;
          font-size: 0.95em;
          font-family: 'Courier New', monospace;
        }
        input:focus {
          outline: none;
          border-color: #ff0000;
          box-shadow: 0 0 10px rgba(255, 0, 0, 0.5);
        }
        button {
          width: 100%;
          padding: 12px;
          background: #ff0000;
          border: none;
          color: #000;
          font-size: 0.9em;
          font-weight: bold;
          font-family: 'Courier New', monospace;
          cursor: pointer;
          margin-top: 20px;
          text-transform: uppercase;
          letter-spacing: 2px;
        }
        button:hover {
          background: #00ff00;
          box-shadow: 0 0 20px rgba(0, 255, 0, 0.7);
        }
        #result {
          margin-top: 24px;
          padding: 18px;
          background: #000;
          border: 2px solid #ff0000;
          display: none;
        }
        #result.show { display: block; }
        .result-label {
          font-size: 0.75em;
          color: #888;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-bottom: 10px;
        }
        .result-value {
          font-family: 'Courier New', monospace;
          color: #00ff00;
          word-wrap: break-word;
          word-break: break-all;
          font-size: 0.8em;
          margin-bottom: 12px;
        }
        .result-value a {
          color: #00ff00;
          text-decoration: none;
        }
        .copy-btn {
          width: auto;
          padding: 6px 14px;
          font-size: 0.75em;
          margin-top: 0;
          background: #0a0a0a;
          border: 1px solid #00ff00;
          color: #00ff00;
        }
        .copy-btn:hover {
          background: #00ff00;
          color: #000;
        }
        .tabs {
          display: flex;
          gap: 10px;
          margin-bottom: 30px;
          border-bottom: 2px solid #222;
        }
        .tab {
          padding: 10px 20px;
          background: transparent;
          border: none;
          color: #666;
          cursor: pointer;
          font-family: 'Courier New', monospace;
          font-size: 0.9em;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-top: 0;
          width: auto;
        }
        .tab.active {
          color: #00ff00;
          border-bottom: 2px solid #00ff00;
        }
        .tab:hover {
          color: #00ff00;
          box-shadow: none;
        }
        .tab-content {
          display: none;
        }
        .tab-content.active {
          display: block;
        }
        textarea {
          width: 100%;
          padding: 12px;
          background: #000;
          border: 2px solid #00ff00;
          color: #00ff00;
          font-size: 0.9em;
          font-family: 'Courier New', monospace;
          resize: vertical;
          min-height: 200px;
        }
        textarea:focus {
          outline: none;
          border-color: #ff0000;
          box-shadow: 0 0 10px rgba(255, 0, 0, 0.5);
        }
        #bulkResult {
          margin-top: 24px;
          padding: 18px;
          background: #000;
          border: 2px solid #ff0000;
          display: none;
          max-height: 500px;
          overflow-y: auto;
        }
        #bulkResult.show { display: block; }
        .bulk-item {
          margin-bottom: 15px;
          padding-bottom: 15px;
          border-bottom: 1px solid #222;
        }
        .bulk-item:last-child {
          border-bottom: none;
        }
        .bulk-username {
          color: #ff0000;
          font-weight: bold;
          margin-bottom: 5px;
        }
        .bulk-link {
          color: #00ff00;
          font-size: 0.8em;
          word-wrap: break-word;
          word-break: break-all;
          flex: 1;
        }
        .bulk-item-content {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .bulk-item-copy {
          width: auto;
          padding: 4px 10px;
          font-size: 0.7em;
          margin-top: 0;
          background: #0a0a0a;
          border: 1px solid #00ff00;
          color: #00ff00;
          flex-shrink: 0;
        }
        .bulk-item-copy:hover {
          background: #00ff00;
          color: #000;
        }
        .action-buttons {
          display: flex;
          gap: 10px;
          margin-top: 10px;
        }
        .action-buttons button {
          flex: 1;
        }
        #arrayOutput {
          margin-top: 15px;
          padding: 12px;
          background: #0a0a0a;
          border: 1px solid #00ff00;
          color: #00ff00;
          font-size: 0.75em;
          max-height: 300px;
          overflow-y: auto;
          word-wrap: break-word;
          white-space: pre-wrap;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🎣 ADMIN PANEL</h1>
        <p class="subtitle">Link Generator</p>

        <div class="tabs">
          <button class="tab active" onclick="switchTab('single')">Single User</button>
          <button class="tab" onclick="switchTab('bulk')">Bulk Generate</button>
        </div>

        <div class="panel">
          <!-- Single User Tab -->
          <div id="single-tab" class="tab-content active">
            <label for="username">Target Username</label>
            <input type="text" id="username" placeholder="john.doe@company.com" autofocus />
            <button onclick="generateLink()">Generate Link</button>

            <div id="result">
              <div class="result-label">Generated Link</div>
              <div class="result-value"><a href="#" id="linkUrl" target="_blank"></a></div>
              <button class="copy-btn" onclick="copyToClipboard('linkUrl')">Copy to Clipboard</button>
            </div>
          </div>

          <!-- Bulk Tab -->
          <div id="bulk-tab" class="tab-content">
            <label for="usernames">Target Usernames (one per line)</label>
            <textarea id="usernames" placeholder="john.doe@company.com&#10;jane.smith@company.com&#10;bob.jones@company.com"></textarea>
            <button onclick="generateBulkLinks()">Generate All Links</button>

            <div id="bulkResult">
              <div class="result-label">Generated Links (<span id="linkCount">0</span>)</div>
              <div id="bulkLinkList"></div>
              <div class="action-buttons">
                <button class="copy-btn" onclick="copyAllLinksText()">Copy All Links</button>
                <button class="copy-btn" onclick="copyArrayOutput()">Copy Array JSON</button>
                <button class="copy-btn" onclick="downloadLinks()">Download as TXT</button>
              </div>
              <div class="result-label" style="margin-top: 20px;">Array Output (JSON)</div>
              <div id="arrayOutput"></div>
            </div>
          </div>
        </div>
      </div>

      <script>
        let bulkLinksArray = [];

        function switchTab(tab) {
          // Update tabs
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

          if (tab === 'single') {
            document.querySelector('.tab:nth-child(1)').classList.add('active');
            document.getElementById('single-tab').classList.add('active');
          } else {
            document.querySelector('.tab:nth-child(2)').classList.add('active');
            document.getElementById('bulk-tab').classList.add('active');
          }
        }

        function generateLink() {
          const username = document.getElementById('username').value.trim();
          if (!username) {
            alert('Please enter a username');
            return;
          }

          const url = 'https://' + window.location.host + '/generate-link?username=' + encodeURIComponent(username) + '&key=${key}';
          fetch(url)
            .then(r => r.json())
            .then(data => {
              const linkEl = document.getElementById('linkUrl');
              linkEl.textContent = data.url;
              linkEl.href = data.url;
              document.getElementById('result').classList.add('show');
            })
            .catch(err => alert('Error: ' + err));
        }

        function copyToClipboard(elementId) {
          const element = document.getElementById(elementId);
          const text = element.textContent || element.innerText;
          
          // Try modern clipboard API first
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
              showCopySuccess(event.target);
            }).catch(err => {
              console.error('Clipboard API failed:', err);
              fallbackCopy(text, event.target);
            });
          } else {
            fallbackCopy(text, event.target);
          }
        }

        function fallbackCopy(text, button) {
          const textarea = document.createElement('textarea');
          textarea.value = text;
          textarea.style.position = 'fixed';
          textarea.style.opacity = '0';
          document.body.appendChild(textarea);
          textarea.select();
          try {
            document.execCommand('copy');
            showCopySuccess(button);
          } catch (err) {
            console.error('Fallback copy failed:', err);
            alert('Copy failed: ' + err.message);
          }
          document.body.removeChild(textarea);
        }

        function showCopySuccess(button) {
          if (!button) return;
          const originalText = button.textContent;
          button.textContent = '✓ COPIED!';
          setTimeout(() => {
            button.textContent = originalText;
          }, 2000);
        }

        async function generateBulkLinks() {
          const textarea = document.getElementById('usernames').value;
          const usernames = textarea.split('\\n')
            .map(u => u.trim())
            .filter(u => u.length > 0);

          if (usernames.length === 0) {
            alert('Please enter at least one username');
            return;
          }

          bulkLinksArray = [];
          const listEl = document.getElementById('bulkLinkList');
          listEl.innerHTML = '<div style="color: #888; text-align: center; padding: 20px;">Generating links...</div>';
          document.getElementById('bulkResult').classList.add('show');

          for (const username of usernames) {
            try {
              const url = 'https://' + window.location.host + '/generate-link?username=' + encodeURIComponent(username) + '&key=${key}';
              const response = await fetch(url);
              const data = await response.json();
              bulkLinksArray.push({ username: username, url: data.url });
            } catch (err) {
              console.error('Error generating link for ' + username, err);
            }
          }

          // Display results
          listEl.innerHTML = bulkLinksArray.map((item, index) => \`
            <div class="bulk-item">
              <div class="bulk-username">\${item.username}</div>
              <div class="bulk-item-content">
                <div class="bulk-link">\${item.url}</div>
                <button class="bulk-item-copy" onclick="copyIndividualLink(\${index})">Copy</button>
              </div>
            </div>
          \`).join('');

          // Display array output
          const arrayOutputEl = document.getElementById('arrayOutput');
          arrayOutputEl.textContent = JSON.stringify(bulkLinksArray, null, 2);

          document.getElementById('linkCount').textContent = bulkLinksArray.length;
        }

        function copyAllLinksText() {
          const text = bulkLinksArray.map(item => item.url).join('\\n');
          
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
              showCopySuccess(event.target);
            }).catch(err => {
              console.error('Clipboard API failed:', err);
              fallbackCopy(text, event.target);
            });
          } else {
            fallbackCopy(text, event.target);
          }
        }

        function copyArrayOutput() {
          const arrayText = JSON.stringify(bulkLinksArray, null, 2);
          
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(arrayText).then(() => {
              showCopySuccess(event.target);
            }).catch(err => {
              console.error('Clipboard API failed:', err);
              fallbackCopy(arrayText, event.target);
            });
          } else {
            fallbackCopy(arrayText, event.target);
          }
        }

        function copyIndividualLink(index) {
          const link = bulkLinksArray[index].url;
          
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(link).then(() => {
              const btn = event.target;
              const originalText = btn.textContent;
              btn.textContent = '✓';
              setTimeout(() => {
                btn.textContent = originalText;
              }, 1500);
            }).catch(err => {
              console.error('Clipboard API failed:', err);
              fallbackCopy(link, event.target);
            });
          } else {
            fallbackCopy(link, event.target);
          }
        }

        function downloadLinks() {
          const text = bulkLinksArray.map(item => \`\${item.username}: \${item.url}\`).join('\\n');
          const blob = new Blob([text], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'phishing-links-' + new Date().toISOString().split('T')[0] + '.txt';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        }

        document.getElementById('username').addEventListener('keypress', function(e) {
          if (e.key === 'Enter') generateLink();
        });
      </script>
    </body>
    </html>
  `);
});

// Generate tracking link (protected endpoint)
app.get('/generate-link', (req, res) => {
  try {
    const { username, key } = req.query;

    // Validate secret key
    if (!timingSafeCompare(key, process.env.SECRET_KEY)) {
      return res.status(403).json({ error: 'Invalid or missing key' });
    }

    // Validate username
    const validation = validateUsername(username);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const token = generateToken(username.trim());
    const url = `${req.protocol}://${req.get('host')}/t/${token}`;

    res.json({ token, url, username: username.trim() });
  } catch (err) {
    console.error('Error generating link');
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Track user via secure token (public endpoint)
app.get('/t/:token', async (req, res) => {
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
      return res.redirect('/users');
    }

    // Create new user with first click data
    const newUser = new User({
      username,
      clicks: [clickData]
    });
    await newUser.save();
    console.log('New user captured via token');
    res.redirect('/users');
  } catch (err) {
    console.error('Error in token tracking endpoint');
    res.status(500).send('An error occurred while processing your request');
  }
});

// HTML page to list all users (publicly accessible for training demo)
app.get('/users', async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    console.log('Fetched users list - count:', users.length);
    res.render('users', { users });
  } catch (err) {
    console.error('Error fetching users');
    res.status(500).send('An error occurred while processing your request');
  }
});

// Delete all users (protected with key parameter)
app.get('/delete-all', async (req, res) => {
  try {
    const { key } = req.query;

    // Validate secret key
    if (!timingSafeCompare(key, process.env.SECRET_KEY)) {
      console.warn('Unauthorized delete-all attempt from IP:', req.ip);
      return res.status(403).send('Forbidden: Invalid or missing key');
    }

    const result = await User.deleteMany({});
    console.log('All users deleted - count:', result.deletedCount);
    res.send(`Successfully deleted ${result.deletedCount} users`);
  } catch (err) {
    console.error('Error deleting users');
    res.status(500).send('An error occurred while processing your request');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
