require('dotenv').config()
const express = require('express')
const path = require('node:path')
const { Pool } = require('pg')
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcryptjs')
const port = 3000

//POOL
const pool = new Pool({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DB,
  password: process.env.PASSWORD,
  port: process.env.PORT,
})
pool.connect()

const app = express()

//CONFIG
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }))
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

//PASSPORT
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      )
      const user = rows[0]

      if (!user) {
        return done(null, false, { message: 'Incorrect username' })
      }
      const match = await bcrypt.compare(password, user.password)
      if (!match) {
        return done(null, false, { message: 'Incorrect password' })
      }
      return done(null, user)
    } catch (err) {
      return done(err)
    }
  })
)

passport.serializeUser((user, done) => done(null, user.id))
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id])
    const user = rows[0]
    done(null, user)
  } catch (error) {
    done(error)
  }
})

//REQ USER
app.use((req, res, next) => {
  res.locals.user = req.user
  next()
})

//ROUTES
app.get('/', (req, res) => {
  res.render('login')
})

app.get('/register', (req, res) => {
  res.render('register')
})

app.get('/home', (req, res) => {
  res.render('home')
})

app.get('/logout', (req, res, next) => {
  req.logout((error) => {
    if (error) {
      return next(error)
    }
    res.redirect('/')
  })
})

app.post(
  '/',
  passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/',
  })
)

app.post('/register', async (req, res, next) => {
  try {
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return next(err)
      } else {
        await pool.query(
          'INSERT INTO users (username, password) VALUES ($1, $2)',
          [req.body.username, hashedPassword]
        )
        res.redirect('/home')
      }
    })
  } catch (error) {
    return next(error)
  }
})

//SERVER
app.listen(port, () =>
  console.log(`Server running on http://localhost:${port}`)
)
