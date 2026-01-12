// Test file with intentional security vulnerabilities for CI/CD testing
// This file is used to test the armis-cli scan failure behavior

const express = require('express');
const app = express();

// CRITICAL: SQL Injection vulnerability
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// CRITICAL: Command Injection vulnerability
app.get('/exec', (req, res) => {
  const cmd = req.query.cmd;
  require('child_process').exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

// CRITICAL: Hardcoded credentials
const AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE";
const DB_PASSWORD = "super_secret_password_123";

// CRITICAL: Insecure deserialization
app.post('/deserialize', (req, res) => {
  const obj = eval(req.body.data);
  res.json(obj);
});

// CRITICAL: Path traversal vulnerability
app.get('/file', (req, res) => {
  const filename = req.query.name;
  res.sendFile(__dirname + '/' + filename);
});

app.listen(3000);
