/**
 * מגישים: אחמד שלאעטה 212811244, באסל חמזה 214048019  , נרמין עראידה 212845762
 * GitHub: ( https://github.com/Ahmadsh64/ex1b.git )
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3000;

// Middleware setup
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded form data
app.use(express.static('public')); // Serve static files from 'public' directory
app.use(fileUpload()); // Enable file uploads
app.set('view engine', 'ejs'); // Set EJS as the template engine
app.set('views', path.join(__dirname, 'views')); // Set the views directory

// Session configuration
app.use(session({
  secret: 'my_secret_key',
  resave: false,
  saveUninitialized: true
}));

// Create the uploads directory if it does not exist
const uploadDir = path.join(__dirname, 'uploads'); 
app.use('/uploads', express.static(uploadDir));

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Create (or open) the SQLite database
const db = new sqlite3.Database('./db/users.db', (err) => {
  if (err) console.error(err.message);
  console.log('Connected to the users database.');
});

// Create the users table if it does not exist
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  firstname TEXT,
  lastname TEXT,
  email TEXT,
  birthdate TEXT,
  profile_pic TEXT
)`);

// Home page route - only accessible if logged in
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('home', { user: req.session.user });
});

// Registration page
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Logout route - destroy the session
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Handle registration form submission
app.post('/register', async (req, res) => {
  const { username, password, firstname, lastname, email, birthdate } = req.body;
  let profile_pic = null;

  // Save uploaded profile picture if provided
  if (req.files && req.files.profile_pic) {
    let file = req.files.profile_pic;
    const filename = Date.now() + path.extname(file.name);
    const filepath = path.join(uploadDir, filename);
    await file.mv(filepath);
    profile_pic = filename;
  }

  // Hash the password before storing
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (username, password, firstname, lastname, email, birthdate, profile_pic) 
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [username, hashedPassword, firstname, lastname, email, birthdate, profile_pic],
    function (err) {
      if (err) {
        console.error(err);
        return res.render('register', { error: 'Username already exists.' });
      }
      res.redirect('/login');
    });
});

// Handle login form submission
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    // Compare provided password with hashed password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    // Save user session and redirect to home
    req.session.user = user;
    res.redirect('/');
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
