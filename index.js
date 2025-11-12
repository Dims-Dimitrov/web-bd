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

// Function to determine BMI category based on age
function getBMICategory(bmi, age) {
    // Untuk anak-anak dan remaja (<18 tahun)
    if (age < 18) {
        // BMI persentil untuk anak-anak dan remaja (simplifikasi)
        // Dalam aplikasi nyata, Anda akan menggunakan tabel persentil yang lebih akurat
        if (bmi < 14) return 'Underweight (Kurus)';
        else if (bmi < 18) return 'Normal';
        else if (bmi < 22) return 'Overweight (Berlebih)';
        else return 'Obese (Obesitas)';
    }
    // Untuk dewasa (18-65 tahun)
    else if (age >= 18 && age <= 65) {
        if (bmi < 18.5) return 'Underweight (Kurus)';
        else if (bmi < 25) return 'Normal';
        else if (bmi < 30) return 'Overweight (Berlebih)';
        else return 'Obese (Obesitas)';
    }
    // Untuk lansia (>65 tahun)
    else {
        // Untuk lansia, sedikit penyesuaian pada kategori BMI
        if (bmi < 22) return 'Underweight (Kurus)';
        else if (bmi < 27) return 'Normal';
        else if (bmi < 32) return 'Overweight (Berlebih)';
        else return 'Obese (Obesitas)';
    }
}

// Function to determine blood pressure category
function getBloodPressureCategory(systolic, diastolic) {
    if (systolic < 120 && diastolic < 80) return 'Normal';
    else if (systolic < 130 && diastolic < 80) return 'Elevated (Tinggi)';
    else if (systolic < 140 || diastolic < 90) return 'High Blood Pressure Stage 1 (Hipertensi Tingkat 1)';
    else if (systolic < 180 || diastolic < 120) return 'High Blood Pressure Stage 2 (Hipertensi Tingkat 2)';
    else return 'Hypertensive Crisis (Krisis Hipertensi - Segera cari bantuan medis)';
}

// Function to determine SpO2 category
function getSpO2Category(spo2) {
    if (spo2 >= 95) return 'Normal';
    else if (spo2 >= 90) return 'Low (Perlu perhatian)';
    else return 'Very Low (Segera konsultasi dokter)';
}

// Route untuk input dan cek berat badan ideal
app.get('/check-weight', (req, res) => {
    res.render('check-weight');
});

app.post('/check-weight', (req, res) => {
    const { name, age, height, weight } = req.body;
    
    // Hitung BMI dan kategori berat badan ideal berdasarkan umur
    const heightM = height / 100;
    const bmi = (weight / (heightM * heightM)).toFixed(2);
    const weightCategory = getBMICategory(parseFloat(bmi), parseInt(age));

    // Simpan ke database
    const sql = 'INSERT INTO weight_data (name, age, height, weight, bmi, weight_category) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, age, height, weight, bmi, weightCategory], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.render('check-weight', { errors: [{ msg: 'Gagal menyimpan data' }] });
        }
    });

    // Render hasil
    res.render('result-weight', { 
        name, 
        age,
        bmi, 
        weightCategory
    });
});

// Route untuk input dan cek tekanan darah dan SpO2
app.get('/check-vitals', (req, res) => {
    res.render('check-vitals');
});

app.post('/check-vitals', (req, res) => {
    const { name, age, systolic, diastolic, spo2 } = req.body;
    
    // Kategori tekanan darah
    const bloodCategory = getBloodPressureCategory(parseInt(systolic), parseInt(diastolic));
    
    // Kategori SpO2
    const spo2Category = getSpO2Category(parseInt(spo2));

    // Simpan ke database
    const sql = 'INSERT INTO vitals_data (name, age, systolic, diastolic, blood_category, spo2, spo2_category) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, age, systolic, diastolic, bloodCategory, spo2, spo2Category], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.render('check-vitals', { errors: [{ msg: 'Gagal menyimpan data' }] });
        }
    });

    // Render hasil
    res.render('result-vitals', { 
        name, 
        age,
        systolic, 
        diastolic, 
        bloodCategory,
        spo2,
        spo2Category
    });
});

// Jalankan server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});