const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const validator = require('validator');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { ifError } = require('assert');
const { log } = require('console');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://127.0.0.1:5500',
    credentials: true
}));
app.use(cookieParser());

//sql connection
dotenv.config();


const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

pool.getConnection((err, res) => {
    if (err) {
        console.error('Hiba az sql csatlakozáskor!');
        return;
    }

    console.log('Sikeres csatlakozik az adatbázihoz!');

    // egy lekérdezés az adatbásis muködéséről
    res.query((err, res) => {
        if (err) {
            console.error('Hiba az sql csatlakozáskor!');
        } else {
            console.log('Müködik :D');
        }
    });
});

//JWT
const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
    const token = req.cookies.auth_token;
    if (!token) {
        return res.status(403).json({ error: 'Nincs token' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Van token, csak épp nem érvényes' });
        }
        req.user = user;
        next();
    });
}

//register
app.post('/api/register', (req, res) => {
    const { email, username, password } = req.body;
    const errors = [];

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Az e-mail cím nem létezik!' });
    }

    if (validator.isEmpty(username)) {
        errors.push({ error: 'Töltsd ki a név mezőt!' });
    }

    if (!validator.isLength(password, { min: 6 })) {
        errors.push({ error: 'A jelszónak legalább 6 karakternek kell lennie!' });
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba a hashelés során' });
        }

        const sql = 'INSERT INTO users(user_id, email, username, password, profile_picture) VALUES(NULL, ?, ?, ?, "default.png")';

        pool.query(sql, [email, username, hash], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Az e-mail már foglalt!' });
            }
            res.status(201).json({ message: 'Sikeres regisztráció! ' });
        });
    });
});

//login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const errors = [];

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Add meg az e-mail címet! ' });
    }

    if (validator.isEmpty(password)) {
        errors.push({ error: 'Add meg a jelszót!' });
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    const sql = 'SELECT * FROM users WHERE email LIKE ?';
    pool.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba az SQL-ben!' });
        }

        if (result.length === 0) {
            return res.status(404).json({ error: 'A felhasználó nem találató!' });
        }

        const user = result[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (isMatch) {
                const token = jwt.sign({ id: user.user_id }, JWT_SECRET, { expiresIn: '1y' });

                res.cookie('auth_token', token, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'none',
                    maxAge: 1000 * 60 * 60 * 24 * 30 * 12
                });

                return res.status(200).json({ message: 'Sikeres bejelentkezés!' });
            } else {
                return res.status(401).json({ error: 'Az e-mail cím vagy a jelszó nem egyezik!' });
            }
        });
    });
});


//logout
app.post('/api/logout',authenticateToken, (req, res) => {
    res.clearCookie('auth_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'none'
    });
    return res.status(200).json({ message: 'Sikeres kijelentkezés!' });
});

//profile
app.get('/api/profile', (req, res) => {
    const user_id = req.user.id;
    const username = req.body.name;
})

app.get('/api/products',authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM `products`'
    pool.query(sql,(err,res) => {
        if(res) => {
            
        } else   {
            return res.status(500).json({ error: 'Nincsen termék!' });
        }
    })
    

})


app.listen(process.env.PORT, process.env.HOSTNAME, () => {
    console.log(`IP: http://${process.env.HOSTNAME}:${process.env.PORT}`);
});