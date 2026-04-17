import express from 'express';
import bcrypt from 'bcrypt';
import Database from 'better-sqlite3';
import expressSession from 'express-session';
import betterSqlite3Session from 'express-session-better-sqlite3';
import db from './db.mjs';
import xss from 'xss';

const app = express();

// TODO fix to protect against XSS


// Create sqlite database to store sessions 
const sessDb = new Database('session.db');

// create an object for creating the session store
// SqliteStore is similar in concept to a class
const SqliteStore = betterSqlite3Session(expressSession, sessDb);

app.use(expressSession({
    store: new SqliteStore(), 
    secret: 'BinnieAndClyde', 
    resave: true, 
    saveUninitialized: false, 
    rolling: true, 
    unset: 'destroy', 
    proxy: true, 
    cookie: { 
        maxAge: 600000, // 600000 ms = 10 mins expiry time
        httpOnly: false // allow client-side code to access the cookie, otherwise it's kept to the HTTP messages
    }
}));

app.use(express.static('public'));
app.use(express.urlencoded({extended: false}));

app.set('view engine' , 'ejs');

// TODO signup with bcrypt
app.post('/signup', async (req, res) => {
    try {
        const hashedPass = await bcrypt.hash(req.body.password, 10);
        const stmt = db.prepare('INSERT INTO ht_users (username, password, balance) VALUES (?, ?, 0)');
        stmt.run(req.body.username, hashedPass);
        res.render('main', { msg: "Signup successful!" });
    } catch(e) {
        res.render('main', { msg: xss(e.message) });
    }
});

app.post('/login', async (req, res) => {
    let msg = "";
    try {
        const stmt = db.prepare('SELECT * FROM ht_users WHERE username=?');
        const results = stmt.all(req.body.username);

        if(results.length > 0) {
            const match = await bcrypt.compare(req.body.password, results[0].password);
            if(match) {
                req.session.username = results[0].username;
                res.redirect('/');
                return;
            } else {
                msg = "Invalid login";
            }
        } else {
            msg = "Invalid login";
        }
    } catch(e) {
        msg = xss(`Internal error: ${e}`);
    }
    res.render('main', { msg: msg, username: req.session.username });
});


// Middleware to add login message to all requests
app.use((req, res, next) => {
    if(req.session.username) {
        const stmt = db.prepare('SELECT * FROM ht_users WHERE username=?');
        const row = stmt.get(req.session.username);
        req.userStatus = `Your credit card is ${row.creditcard} and your balance is ${row.balance.toFixed(2)}, please spend away...`;
    } 
    next();
});


app.use('/buy', (req, res, next) => {
    if(req.session.username) {
        next();
    } else {
        res.render('main', { msg: 'Cannot buy song as you are not logged in' } );
    }
});

app.get('/', (req, res) => {
    res.render('main', { msg: xss(req.userStatus), username: xss(req.session.username) });
});

app.get(['/search', '/artist/:artist'], (req, res) => {
    try {
        const stmt = db.prepare('SELECT * FROM wadsongs WHERE artist=?');
        const results = stmt.all(req.params.artist || req.query.artist);

        const safeResults = results.map(row => ({
            ...row,
            artist: xss(row.artist),
            title: xss(row.title)
        }));

        res.render('main', {
            results: safeResults,
            msg: xss(req.userStatus),
            username: xss(req.session.username)
        });
    } catch(e) {
        res.render('main', {
            msg: xss(e.message),
            username: xss(req.session.username)
        });
    }
});

app.post('/buy', (req, res) => {
    try {
        const stmt = db.prepare('SELECT * FROM wadsongs WHERE id=?');
        const result = stmt.get(req.body.id);
        if(result) {
            const stmt2 = db.prepare('UPDATE wadsongs SET quantity=quantity+1 WHERE id=?');
            stmt2.run(req.body.id);
            const stmt3 = db.prepare('UPDATE ht_users SET balance=balance-? WHERE username=?');
            stmt3.run(result.price, req.session.username);
        }
        res.render('main', { msg: `${xss(req.userStatus)}<br />You are buying the song with ID ${xss(req.body.id)}`, username: xss(req.session.username) });
    } catch(e) {    
        res.render('main', {  msg: e.message, username: req.session.username } );
    } 
});



app.post('/setcookie', (req, res) => {
    res.set('Set-Cookie', req.body.cookie);
    res.send(`Cookie set: ${req.body.cookie}`);
});

app.all('/logout', (req, res) => {
    req.session = null;
    res.redirect('/');
});

app.listen(3000);
