const fs = require('fs')
const https = require('https')
const path = require('path')
const express = require('express')
const helmet = require('helmet')
const passport = require('passport')
const { Strategy } = require('passport-google-oauth20')
const cookieSession = require('cookie-session')

require('dotenv').config()

const PORT = 3000

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2
}

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
}

function verifyCallback(accessToken, refreshToken, profile, done) {
    // console.log("Google profile", profile)
    done(null, profile)
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback))

//save session to cookie
passport.serializeUser((user, done) => {
    done(null, user.id)
})

//read session from cookie
passport.deserializeUser((obj, done) => {
    done(null, obj)
    // UserActivation.findById(id).then(user => {
    //     done(null, user)
    // })
})

const app = express()

app.use(helmet())

app.use(cookieSession({
    name: 'session',
    maxAge: 1000 * 60 * 60 * 24,
    keys: [config.COOKIE_KEY_2, config.COOKIE_KEY_1]
}))

app.use(passport.initialize())
app.use(passport.session())

function checkLoggedIn(req, res, next) {
    console.log('current user is: ', req.user)
    const isLoggedIn = req.isAuthenticated() && req.user
    if (!isLoggedIn) {
        res.status(401).send('Not logged in!')
    }
    next()
}

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email']
}))

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
}), (req, res) => {
    // console.log("Google called us back!")
})

app.get('/auth/logout', (req, res) => {
    req.logOut()
    return res.redirect('/')
})

app.get('/secret', checkLoggedIn, (req, res) => { 
    res.send('your secret value is: 69')
})

app.get('/failure', (req, res) => {
    return res.send('Failed to authenticate..')
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})