// Intentionally vulnerable JavaScript API file for testing Vibe Coding Guard
// DO NOT use this code in production

const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const app = express();

// HIGH: CORS wildcard
app.use(cors());

// HIGH: Another CORS wildcard pattern
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

// HIGH: SSRF via template literal
app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  const response = await fetch(`https://api.example.com/${url}`);
  const data = await response.json();
  res.json(data);
});

// HIGH: SSRF via string concatenation with axios
app.get('/fetch', async (req, res) => {
  const endpoint = req.query.endpoint;
  const response = await axios.get("https://api.example.com/" + endpoint);
  res.json(response.data);
});

// HIGH: API key in URL
function callExternalApi() {
  return fetch("https://api.service.com/v1/data?api_key=sk_live_abc123def456ghi789");
}

// MEDIUM: POST route without auth middleware
app.post('/items', (req, res) => {
  const item = req.body;
  res.json({ status: 'created' });
});

// MEDIUM: Express without helmet (detected at app level)
// (No helmet import/usage above)

// MEDIUM: Express without rate limiting (detected at app level)
// (No rate-limit import/usage above)

// MEDIUM: Verbose error - returning exception details
app.get('/data', async (req, res) => {
  try {
    const result = await doSomething();
    res.json(result);
  } catch (e) {
    res.json({ error: e.message, stack: e.stack });
  }
});

// MEDIUM: Open redirect
app.get('/redirect', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});

// LOW: fetch without timeout/AbortController
async function fetchData() {
  const response = await fetch('https://api.example.com/data');
  return response.json();
}

// LOW: express.json() without body size limit
app.use(express.json());
app.use(express.urlencoded());
