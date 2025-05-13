require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const path = require('path');
const Joi = require('joi');
const mongoose = require('mongoose');
const User = require('./models/user');
const { requireAuth, requireAdmin } = require('./middleware/auth');

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000;

const PORT = process.env.PORT || 3000;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const app = express();

mongoose.connect(`mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`);

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: node_session_secret,
  saveUninitialized: false,
  resave: true,
  store: MongoStore.create({
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
    crypto: { secret: mongodb_session_secret }
  }),
  cookie: { maxAge: expireTime }
}));

app.get("/", (req, res) => {
  res.render("home", { name: req.session.name });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/members", requireAuth, (req, res) => {
  res.render("members", { name: req.session.name });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log("Error destroying session:", err);
      return res.status(500).send("Could not log out.");
    }
    res.redirect("/");
  });
});

app.post("/signup", async (req, res) => {
  const { name, email, password, user_type } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    user_type: Joi.string().valid("user", "admin").required()
  });

  const validation = schema.validate({ name, email, password, user_type });
  if (validation.error) {
    const missingField = validation.error.details[0].context.key;

    let message = "Please fill out all fields.";
    if (missingField === "name") message = "Name is required.";
    else if (missingField === "email") message = "Please provide an email address.";
    else if (missingField === "password") message = "Please enter a password.";

    return res.send(`
    <p>${message}</p>
    <a href="/signup">Try again</a>
  `);
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.render("signup", { message: "Email already registered." });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const user = await User.create({ name, email, password: hashedPassword, user_type });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.user_type = user.user_type;

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
    return res.send(`<p>${message}</p><a href="/login">Try again</a>`);
  }

  const user = await User.findOne({ email });
  const passwordMatch = user && await bcrypt.compare(password, user.password);

  if (!user || !passwordMatch) {
    return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
  }
  
  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;
  req.session.user_type = user.user_type;

  res.redirect("/members");
});

app.get("/admin", requireAuth, async (req, res) => {
  if (req.session.user_type !== "admin") return res.status(403).render("403");
  const users = await User.find();
  res.render("admin", { users, currentEmail: req.session.email });
});

app.get("/admin/promote/:email", requireAdmin, async (req, res) => {
  await User.updateOne({ email: req.params.email }, { $set: { user_type: "admin" } });
  res.redirect("/admin");
});

app.get("/admin/demote/:email", requireAdmin, async (req, res) => {
  await User.updateOne({ email: req.params.email }, { $set: { user_type: "user" } });
  res.redirect("/admin");
});

app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});