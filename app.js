require('dotenv').config()
const express = require('express')
const { body, validationResult } = require('express-validator')
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

//VALIDATORS
const loginValidator = [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 4 }).trim().escape(),
]

const registerValidator = [
  body('username')
    .isLength({ min: 3 })
    .trim()
    .escape()
    .withMessage('Username must be at least 3 characters long'),
  body('password')
    .isLength({ min: 4 })
    .withMessage('Password must be at least 4 characters long')
    .trim()
    .escape()
    .withMessage('Password must be at least 4 characters long'),
  body('confirmPassword')
    .isLength({ min: 4 })
    .trim()
    .escape()
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match')
      }
      return true
    })
    .withMessage('Passwords do not match'),
]

const messageValidator = [
  body('title')
    .isLength({ min: 3 })
    .trim()
    .escape()
    .withMessage('Title must be at least 3 characters long'),
  body('content')
    .isLength({ min: 3 })
    .trim()
    .escape()
    .withMessage('Content must be at least 3 characters long'),
]

const codeValidator = [body('code').trim().escape()]

//APP
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
  res.render('register', { errors: [] })
})

app.get('/home', async (req, res) => {
  try {
    const messages = await pool.query('SELECT * FROM messages;')
    res.render('home', { errors: [], messages: messages.rows })
  } catch (error) {
    res.render('home', { errors: [error.message], messages: [] })
  }
})

app.get('/message', (req, res) => {
  res.render('message', { errors: [] })
})

app.get('/club', (req, res) => {
  res.render('club', { errors: [] })
})

app.get('/admin', (req, res) => {
  res.render('admin', { errors: [] })
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
  loginValidator,
  (req, res, next) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.render('login', { errors: errors.array() })
    }
    next()
  },
  passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/',
  })
)

app.post('/register', registerValidator, async (req, res, next) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.render('register', {
      errors: errors.array(),
    })
  }
  try {
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return next(err)
      } else {
        await pool.query(
          'INSERT INTO users (username, password) VALUES ($1, $2)',
          [req.body.username, hashedPassword]
        )
        res.redirect('/')
      }
    })
  } catch (error) {
    return next(error)
  }
})

app.post('/message', messageValidator, async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.render('message', {
      errors: errors.array(),
    })
  }
  const title = req.body.title
  const message = req.body.content
  let author = ''
  try {
    const result = await pool.query(
      'SELECT (username) FROM users WHERE id = $1',
      [req.user.id]
    )
    author = result.rows[0].username
  } catch (error) {
    res.render('message', { errors: [error] })
  }
  try {
    const userId = req.user.id
    await pool.query(
      'INSERT INTO messages (user_id, title, message, author) VALUES ($1, $2, $3, $4)',
      [userId, title, message, author]
    )
    res.redirect('/home')
  } catch (error) {
    res.render('message', { errors: [error] })
  }
})

app.post('/club', codeValidator, async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.render('club', {
      errors: errors.array(),
    })
  }
  const code = req.body.code
  if (code === process.env.CLUBCODE) {
    try {
      await pool.query('UPDATE users SET member = true WHERE id = $1', [
        req.user.id,
      ])
      res.redirect('/home')
    } catch (error) {
      res.render('club', { errors: [error.message] })
    }
  } else {
    res.render('club', { errors: ['Invalid code'] })
  }
})

app.post('/admin', codeValidator, async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.render('admin', {
      errors: errors.array(),
    })
  }
  const code = req.body.code
  if (code === process.env.ADMINCODE) {
    try {
      await pool.query('UPDATE users SET admin = true WHERE id = $1', [
        req.user.id,
      ])
      res.redirect('/home')
    } catch (error) {
      res.render('admin', { errors: [error.message] })
    }
  } else {
    res.render('admin', { errors: ['Invalid code'] })
  }
})

app.post('/delete', async (req, res) => {
  const id = req.body.id
  try {
    await pool.query('DELETE FROM messages WHERE id = $1', [id])
    res.redirect('/home')
  } catch (error) {
    res.render('home', { errors: [error.message] })
  }
})

//SERVER
app.listen(port, () =>
  console.log(`Server running on http://localhost:${port}`)
)
