var express = require('express');
var mysql = require('mysql');
var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');
var app = express();
var port = 3000;

// Configurare parser pentru datele JSON
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configurare conexiune la baza de date MySQL
var db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Schimbă username-ul și parola după configurarea ta
    password: 'password',
    database: 'motoshop_db'
});

// Conectare la baza de date MySQL
db.connect(function(err) {
    if (err) {
        throw err;
    }
    console.log('Conectat la baza de date MySQL');
});

// Ruta pentru înregistrare (register)
app.post('/register', function(req, res) {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    // Hash parola înainte de a o salva în baza de date
    bcrypt.hash(password, 10, function(err, hash) {
        if (err) {
            console.log(err);
            res.status(500).send('Eroare la înregistrare');
        } else {
            var user = { username: username, email: email, password: hash };
            // Adăugare utilizator în baza de date
            db.query('INSERT INTO users SET ?', user, function(err, result) {
                if (err) {
                    console.log(err);
                    res.status(500).send('Eroare la înregistrare');
                } else {
                    console.log('Utilizator înregistrat cu succes');
                    res.status(200).send('Utilizator înregistrat cu succes');
                }
            });
        }
    });
});

// Ruta pentru autentificare (login)
app.post('/login', function(req, res) {
    var username = req.body.username;
    var password = req.body.password;

    // Cautare utilizator în baza de date
    db.query('SELECT * FROM users WHERE username = ?', username, function(err, result) {
        if (err) {
            console.log(err);
            res.status(500).send('Eroare la autentificare');
        } else {
            if (result.length > 0) {
                var hashedPassword = result[0].password;

                // Comparare parola introdusă cu parola hash stocată
                bcrypt.compare(password, hashedPassword, function(err, match) {
                    if (err) {
                        console.log(err);
                        res.status(500).send('Eroare la autentificare');
                    } else if (match) {
                        console.log('Autentificare reușită');
                        res.status(200).send('Autentificare reușită');
                    } else {
                        console.log('Autentificare eșuată. Parolă incorectă.');
                        res.status(401).send('Autentificare eșuată. Parolă incorectă.');
                    }
                });
            } else {
                console.log('Autentificare eșuată. Utilizator inexistent.');
                res.status(401).send('Autentificare eșuată. Utilizator inexistent.');
            }
        }
    });
});

// Pornire server
app.listen(port, function() {
    console.log("Serverul ascultă la http://localhost:${port}");
});
