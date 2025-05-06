require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const path = require('path');
const Joi = require('joi');

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000;

const PORT = process.env.PORT || 3000;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const { database } = require('./connection');
const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');

app.use(session({
  secret: node_session_secret,
  saveUninitialized: false,
  resave: true,
  store: MongoStore.create({
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
    crypto: {
      secret: mongodb_session_secret
    }
  }),
  cookie: { maxAge: expireTime }
}));

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.sendFile(path.join(__dirname, "pages", "index.html"));
  } else {
    res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <form action="/members">
        <button type="submit">Go to Members Area</button>
      </form>
      <form action="/logout">
        <button type="submit">Logout</button>
      </form>
    `);
    
  }
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "pages", "signup.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "pages", "login.html"));
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/');
    return;
  }
  const images = ["1.jpg", "2.jpg", "3.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];
  res.send(`
    <h1>Hello, ${req.session.name}</h1>
    <img src="/images/${randomImage}" alt="Member image" style="max-width:500px;">
    <form action="/logout" method="GET">
      <button type="submit">Logout</button>
    </form>
  `);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const validation = schema.validate({ name, email, password });
  if (validation.error) {
    const missingField = validation.error.details[0].context.key;

    let message = "Please fill out all fields.";
    if (missingField === "name") message = "Please provide your name.";
    else if (missingField === "email") message = "Please provide your email address.";
    else if (missingField === "password") message = "Please provide a password.";

    res.send(`
      <p>${message}</p>
      <a href="/signup">Try again</a>
    `);
    return;
  }

  const existingUser = await userCollection.findOne({ email });
  if (existingUser) {
    res.send("Email already registered. <a href='/signup'>Try again</a>");
    return;
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;

  res.redirect("/members");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validation = schema.validate({ email, password });
  if (validation.error) {
    const missingField = validation.error.details[0].context.key;
    let message = "Missing required field.";
    if (missingField === "email") message = "Please enter your email.";
    else if (missingField === "password") message = "Please enter your password.";

    res.send(`
      <p>${message}</p>
      <a href="/login">Try again</a>
    `);
    return;
  }

  const user = await userCollection.findOne({ email });
  if (!user) {
    res.send("Invalid email. <a href='/login'>Try again</a>");
    return;
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    res.send("Invalid password. <a href='/login'>Try again</a>");
    return;
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;

  res.redirect("/members");
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'pages', '404.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});