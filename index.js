const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const app = express();

// Konfigurasi database
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',  // ganti dengan username MySQL Anda
    password: '',  // ganti dengan password MySQL Anda
    database: 'health_check'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL');
});

// Security middleware
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Session configuration
app.use(session({
    secret: 'health-check-secret-key-2025', // In production, use environment variable
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true in production with HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Setup EJS dan body-parser
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'view'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));  // untuk file statis seperti CSS

// Route utama
app.get('/', (req, res) => {
    res.render('index');
});

// Route login
app.get('/login', (req, res) => {
    res.render('login');
});

// Route register
app.get('/register', (req, res) => {
    res.render('register');
});

// Route halaman utama (protected)
app.get('/halaman-utama', requireAuth, (req, res) => {
    res.render('halaman_utama', { userName: req.session.userName });
});

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

// POST route for login with validation and authentication
app.post('/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('login', { errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const sql = 'SELECT id, name, email, password FROM users WHERE email = ?';
        db.query(sql, [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.render('login', { errors: [{ msg: 'Database error' }] });
            }

            if (results.length === 0) {
                return res.render('login', { errors: [{ msg: 'Email atau password salah' }] });
            }

            const user = results[0];
            const isValidPassword = await bcrypt.compare(password, user.password);

            if (!isValidPassword) {
                return res.render('login', { errors: [{ msg: 'Email atau password salah' }] });
            }

            // Set session
            req.session.userId = user.id;
            req.session.userName = user.name;

            res.redirect('/halaman-utama');
        });
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { errors: [{ msg: 'Terjadi kesalahan sistem' }] });
    }
});

// POST route for register with validation and password hashing
app.post('/register', [
    body('name').trim().isLength({ min: 2, max: 255 }),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('confirm_password').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Konfirmasi password tidak cocok');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('register', { errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
        // Check if email already exists
        const checkSql = 'SELECT id FROM users WHERE email = ?';
        db.query(checkSql, [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.render('register', { errors: [{ msg: 'Database error' }] });
            }

            if (results.length > 0) {
                return res.render('register', { errors: [{ msg: 'Email sudah terdaftar' }] });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user
            const insertSql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
            db.query(insertSql, [name, email, hashedPassword], (err, result) => {
                if (err) {
                    console.error('Insert error:', err);
                    return res.render('register', { errors: [{ msg: 'Gagal mendaftarkan akun' }] });
                }

                res.redirect('/login');
            });
        });
    } catch (error) {
        console.error('Register error:', error);
        res.render('register', { errors: [{ msg: 'Terjadi kesalahan sistem' }] });
    }
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/');
    });
});

// Route untuk input dan cek berat badan ideal + tekanan darah
app.get('/check-weight-blood', (req, res) => {
    res.render('check-weight-blood');
});

app.post('/check-weight-blood', (req, res) => {
    const { name, age, height, weight, systolic, diastolic } = req.body;
    
    // Hitung BMI dan kategori berat badan ideal
    const heightM = height / 100;
    const bmi = (weight / (heightM * heightM)).toFixed(2);
    let weightCategory = '';
    if (bmi < 18.5) weightCategory = 'Underweight';
    else if (bmi < 25) weightCategory = 'Normal';
    else if (bmi < 30) weightCategory = 'Overweight';
    else weightCategory = 'Obese';

    // Kategori tekanan darah
    let bloodCategory = '';
    if (systolic < 120 && diastolic < 80) bloodCategory = 'Normal';
    else if (systolic < 130 && diastolic < 80) bloodCategory = 'Elevated';
    else if (systolic < 140 || diastolic < 90) bloodCategory = 'High Blood Pressure Stage 1';
    else bloodCategory = 'High Blood Pressure Stage 2';

    // Simpan ke database
    const sql = 'INSERT INTO health_data (name, age, height, weight, systolic, diastolic) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, age, height, weight, systolic, diastolic], (err) => {
        if (err) throw err;
    });

    // Render hasil
    res.render('result-weight-blood', { name, bmi, weightCategory, systolic, diastolic, bloodCategory });
});

// Route untuk input dan cek SpO2
app.get('/check-spo2', (req, res) => {
    res.render('check-spo2');
});

app.post('/check-spo2', (req, res) => {
    const { name, age, spo2 } = req.body;
    
    // Kategori SpO2
    let spo2Category = '';
    if (spo2 >= 95) spo2Category = 'Normal';
    else if (spo2 >= 90) spo2Category = 'Low (Perlu perhatian)';
    else spo2Category = 'Very Low (Segera konsultasi dokter)';

    // Simpan ke database
    const sql = 'INSERT INTO health_data (name, age, spo2) VALUES (?, ?, ?)';
    db.query(sql, [name, age, spo2], (err) => {
        if (err) throw err;
    });

    // Render hasil
    res.render('result-spo2', { name, spo2, spo2Category });
});

// Jalankan server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});