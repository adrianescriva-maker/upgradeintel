const express = require('express');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));

const oauthClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

async function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Non authentifié' });
  try {
    const ticket = await oauthClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload.email.endsWith('@axeptio.eu')) {
      return res.status(403).json({ error: 'Accès restreint aux emails @axeptio.eu' });
    }
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;
  try {
    const ticket = await oauthClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload.email.endsWith('@axeptio.eu')) {
      return res.status(403).json({ error: 'Accès restreint aux emails @axeptio.eu' });
    }
    res.json({ token: credential, email: payload.email, name: payload.name, picture: payload.picture });
  } catch (e) {
    res.status(401).json({ error: 'Authentification Google échouée' });
  }
});

app.use('/api/stripe', requireAuth, async (req, res) => {
  const path = req.url;
  const stripeUrl = `https://api.stripe.com${path}`;
  try {
    const response = await fetch(stripeUrl, {
      method: req.method,
      headers: {
        'Authorization': 'Basic ' + Buffer.from(process.env.STRIPE_SECRET_KEY + ':').toString('base64'),
      },
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.use('/api/axeptio', requireAuth, async (req, res) => {
  const path = req.url;
  const axeptioUrl = `https://api.axept.io${path}`;
  try {
    const response = await fetch(axeptioUrl, {
      headers: {
        'Authorization': `Bearer ${process.env.AXEPTIO_TOKEN}`,
      },
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = app;
