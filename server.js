// Importing necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin SDK
const serviceAccount = require('./serviceAccountKey.json'); // Make sure to replace with your actual service account file
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

// Initialize Express app
const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key', // You should replace this with a value from an environment variable for security
  resave: false,
  saveUninitialized: true
}));

// Static files middleware
app.use(express.static(path.join(__dirname, 'public')));

// Routes to serve HTML files
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route to handle the signup form submission
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user already exists
    const userSnapshot = await db.collection('users').doc(email).get();
    if (userSnapshot.exists) {
      return res.status(400).send('User already exists');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to Firestore
    await db.collection('users').doc(email).set({
      email,
      password: hashedPassword
    });

    res.send('User registered successfully');
  } catch (error) {
    res.status(500).send('Error registering user: ' + error.message);
  }
});

// Route to handle the login form submission
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Fetch user from Firestore
    const userSnapshot = await db.collection('users').doc(email).get();
    if (!userSnapshot.exists) {
      return res.status(400).send('User does not exist');
    }

    const userData = userSnapshot.data();

    // Compare passwords
    const isMatch = await bcrypt.compare(password, userData.password);
    if (!isMatch) {
      return res.status(400).send('Invalid credentials');
    }

    // Save user session and redirect to dashboard
    req.session.user = email;
    res.redirect('/dashboard');
  } catch (error) {
    res.status(500).send('Error logging in: ' + error.message);
  }
});

// Route to serve the dashboard (protected route)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('You need to login first');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});