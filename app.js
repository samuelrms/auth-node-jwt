require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json())

const User = require('./models/User')

app.get('/', (_, res) => {
  res.status(200).json({
    msg: "Welcome to Node auth JWT"
  })
})

app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmpassword, cpf } = req.body

  if (!name) res.status(422).json({ msg: 'Name required' })
  if (!email) res.status(422).json({ msg: 'Email required' })
  if (!password) res.status(422).json({ msg: 'Password required' })
  if (!cpf) res.status(422).json({ msg: 'CPF required' })
  if (password !== confirmpassword) res.status(422).json({ msg: 'Passwords do not match' })

  const userExists = await User.findOne({ cpf: cpf })
  if (userExists) res.status(422).json({ msg: 'CPF already registered' })

  const salt = await bcrypt.genSalt(18)
  const passwordHash = await bcrypt.hash(password, salt)

  const user = new User({
    name,
    email,
    password: passwordHash,
    cpf
  })

  try {
    await user.save()
    res.status(201).json({ msg: 'Created user' })
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: 'Internal error' })
  }
})

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email) res.status(422).json({ msg: 'Email required' })
  if (!password) res.status(422).json({ msg: 'Password required' })

  const user = await User.findOne({ email: email })
  if (!user) res.status(404).json({ msg: 'User does not exist' })

  const checkPassword = await bcrypt.compare(password, user.password)
  if (!checkPassword) res.status(422).json({ msg: 'Invalid password' })

  try {
    const secret = process.env.SECRET
    const token = jwt.sign({
      id: user._id
    }, secret)

    res.status(200).json({ msg: 'User logged', token })

  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: 'Internal error' })
  }
})

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.g4pmvs2.mongodb.net/?retryWrites=true&w=majority`).then(() => {
  app.listen(8080)
  console.log('Connected to the database');
}).catch((err) => console.log(err))

