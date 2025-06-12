const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3000;

// הגדרות middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// הגדרת session
app.use(session({
  secret: 'my_secret_key',
  resave: false,
  saveUninitialized: true
}));

// יצירת תיקייה להעלאות אם לא קיימת
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// הגדרת multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// פתיחת / יצירת בסיס הנתונים
const db = new sqlite3.Database('./db/users.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the users database.');
});

// יצירת טבלה אם לא קיימת
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

// דף הבית (רק אם מחובר)
app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('home', { user: req.session.user });
});

// דף הרשמה
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// דף התחברות
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// יציאה
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// תהליך הרשמה
app.post('/register', upload.single('profile_pic'), async (req, res) => {
  const { username, password, firstname, lastname, email, birthdate } = req.body;
  let profile_pic = null;

  if (req.file) {
    profile_pic = req.file.filename;
  }

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

// תהליך התחברות
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render('login', { error: 'Invalid username or password.' });
    }

    req.session.user = user;
    res.redirect('/');
  });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
