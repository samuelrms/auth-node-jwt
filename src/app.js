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

app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  const user = await User.findById(id, "-password");
  if (!user) res.status(404).json({ msg: "Usuário não encontrado!" });

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) res.status(401).json({ msg: 'Access denied' })

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret)

    next()
  } catch (err) {
    console.log(err);
    res.status(400).json({ msg: 'Invalid Token' })
  }
}

app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmpassword, cpf } = req.body

  if (!name) res.status(422).json({ msg: 'Name required' })
  if (!email) res.status(422).json({ msg: 'Email required' })
  if (!password) res.status(422).json({ msg: 'Password required' })
  if (password.length < 8) res.status(422).json({ msg: 'The password must have at least 8 characters' })
  if (!cpf) res.status(422).json({ msg: 'CPF required' })
  if (password !== confirmpassword) res.status(422).json({ msg: 'Passwords do not match' })

  const userExistsTriggedCpf = await User.findOne({ cpf: cpf })
  if (userExistsTriggedCpf) res.status(422).json({ msg: 'CPF already registered' })
  const userExistsTriggedEmail = await User.findOne({ email: email })
  if (userExistsTriggedEmail) res.status(422).json({ msg: 'Email already registered' })

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