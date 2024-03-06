const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const port = 3000;
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';
const SESSION_SECRET = 'secret';
const SESSION_EXPIRY = '1h';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key) {
        this.#sessions[key] = true;
        this.#storeSessions();
    }

    init(res, payload) {
        const token = jwt.sign(payload, SESSION_SECRET, { expiresIn: SESSION_EXPIRY });
        this.set(token);
        return token;
    }

    destroy(req) {
        delete this.#sessions[req.token];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let token = req.get(SESSION_KEY)?.split(' ')[1];

    if (token) {
        try {
            currentSession = jwt.verify(token, SESSION_SECRET);
        } catch (err) {
            // Invalid token, session not authenticated
        }
    }

    req.session = currentSession;
    req.sessionId = token;

    next();
});

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req);
    res.redirect('/');
});

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
]

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => user.login === login && user.password === password);

    if (user) {
        const payload = { username: user.username, login: user.login };
        const token = sessions.init(res, payload);
        res.json({ token });
    } else {
        res.status(401).send();
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
