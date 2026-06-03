// Intentionally vulnerable JavaScript file for testing Vibe Coding Guard
// DO NOT use this code in production

const { exec } = require('child_process');
const crypto = require('crypto');

// HIGH: eval usage
const userInput = getUserInput();
const result = eval(userInput);

// HIGH: innerHTML XSS
const element = document.getElementById('output');
element.innerHTML = userInput;

// HIGH: document.write XSS
document.write('<div>' + userInput + '</div>');

// HIGH: new Function injection
const fn = new Function('return ' + userInput);

// HIGH: command injection via exec
const filename = getUserInput();
exec('cat ' + filename, (error, stdout) => {
  console.log(stdout);
});

// HIGH: hardcoded secrets
const apiKey = "sk-1234567890abcdef1234567890abcdef";
const password = "SuperSecretPassword123!";

// MEDIUM: dangerouslySetInnerHTML (React)
function MyComponent({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// MEDIUM: prototype pollution
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key]; // vulnerable to __proto__ pollution
  }
}
obj.__proto__.isAdmin = true;

// MEDIUM: SSL bypass
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });

// MEDIUM: weak crypto
const hash = crypto.createHash('md5').update('data').digest('hex');
const hash2 = crypto.createHash('sha1').update('data').digest('hex');
