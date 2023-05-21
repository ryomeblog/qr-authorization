// Import necessary packages
const express = require('express');
const passport = require('passport');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
require('dotenv').config();

// Store users and refresh tokens in-memory
const users = {};
const refreshTokens = {};

// Define local strategy for passport.js
passport.use(new LocalStrategy((username, password, done) => {
  const user = users[username]; // find user by username
  if (!user) return done(null, false); // user not found

  // Verify TOTP
  const verified = speakeasy.totp.verify({
    secret: user.secret.base32,
    encoding: 'base32',
    token: password,
  });

  if (!verified) return done(null, false); // invalid TOTP
  return done(null, user);
}));

// Serialize and deserialize user for session management
passport.serializeUser((user, done) => {
  done(null, user.username);
});
passport.deserializeUser((username, done) => {
  done(null, users[username]);
});

const app = express();

// Set up middleware
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) {
    return res.status(403).json({ message: 'No token provided.' });
  }

  const bearerToken = bearerHeader.split('Bearer ')[1];

  jwt.verify(bearerToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Failed to authenticate token.' });
    } else {
      req.user = decoded;
      next();
    }
  });
};

// Registration route, uses speakeasy to generate TOTP secret and QR code
app.get('/register', (req, res) => {
  const secret = speakeasy.generateSecret({ length: 20, name: `QRLogin(${req.query.username})` });
  QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
    users[req.query.username] = { username: req.query.username, secret: secret };
    res.send(`<h1>Register</h1><img src="${data_url}">`);
  });
});

// Login route, uses passport for authentication and JWT for session management
app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(400).json({ message: 'Something is not right', user: user });
    }

    req.login(user, { session: false }, (err) => {
      if (err) {
        res.send(err);
      }

      // Create and send token and refresh token
      const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1h' });
      const refreshToken = jwt.sign(user, process.env.JWT_SECRET);
      refreshTokens[refreshToken] = req.query.username;
      return res.json({
        "token_type": "Bearer",
        "expires_in": "3600",
        "refresh_token": refreshToken,
        "access_token": token,
      });
    });
  })(req, res);
});

// Verify JWT token route
app.post('/verify', (req, res) => {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) {
    return res.status(403).json({ message: 'No token provided.' });
  }

  const bearerToken = bearerHeader.split('Bearer ')[1];

  jwt.verify(bearerToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Failed to authenticate token.' });
    } else {
      return res.json({ message: 'Token is valid.' });
    }
  });
});

// Refresh JWT token route
app.post('/refresh', (req, res) => {
  const refreshToken = req.headers['refresh_token'];
  if (!refreshToken || !(refreshToken in refreshTokens)) {
    return res.status(403).json({ message: 'Refresh token is not valid.' });
  }

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Refresh token is not valid.' });
    }

    if(refreshTokens[refreshToken].username !== user.username){
      return res.status(403).json({ message: 'Refresh token is not valid.' });
    }

    // Create and send new token and refresh token
    const newToken = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1h' });
    const newRefreshToken = jwt.sign(user, process.env.JWT_SECRET);
    delete refreshTokens[refreshToken];
    refreshTokens[newRefreshToken] = user.username;
    return res.json({
      "token_type": "Bearer",
      "expires_in": "3600",
      "refresh_token": newRefreshToken,
      "access_token": newToken,
    });
  });
});

// Get user info route, protected by JWT
app.get('/user', verifyToken, (req, res) => {
  if (!req.user) {
    return res.status(404).json({ message: 'User not found.' });
  }
  return res.json(req.user);
});

// Start the server
app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
