require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 8040;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
  if (req.session.authenticated) {
      return true;
  }
  return false;
}

function sessionValidation(req,res,next) {
  if (isValidSession(req)) {
      next();
  }
  else {
      res.redirect('/login');
  }
}

function isAdmin(req) {
  if (req.session.user_type == "admin") {
      return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
      res.status(403);
      res.render("errorMessage", {error: "Not Authorized"});
      return;
  }
  else {
      next();
  }
}

app.get('/', (req,res) => {
  const username = req.session.username;
    if(!req.session.authenticated){
      res.render("index");
    }else {
      res.render("index1", {username});
    }
});

app.get('/createUser', (req,res) => {
    res.render("createUser");
});


app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/submitUser', async (req,res) => {
    var email = req.body.email;
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.object(
		{
      email: Joi.string().email().required(),
			username: Joi.string().alphanum().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({email, username, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/createUser");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({email: email, username: username, password: hashedPassword, user_type: "user"});
	console.log("Inserted user");
  console.log(req.session.username);
  req.session.authenticated = true;
  req.session.username = username;
  res.redirect("/members");
});

app.post('/loggingin', async (req,res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);

  if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/login");
      return;
  }

  const result = await userCollection.find({email: email})
    .project({email: 1, password: 1, username: 1, user_type: 1, _id: 1})
    .toArray();

  console.log(result);
  if (result.length != 1) {
      console.log("user not found");
      res.redirect("/login");
      return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
      console.log("correct password");
      req.session.authenticated = true;
      req.session.email = email;
      req.session.cookie.maxAge = expireTime;
      req.session.username = result[0].username;
      req.session.user_type = result[0].user_type;
      res.redirect('/members');
      return;
  }
  else {
      res.render("invalidPassword");
      console.log("incorrect password");
      return;
  }
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
});

app.use(express.static('public'));

app.get('/members', (req,res) => {
  if (!req.session.authenticated) {
      res.redirect('/login');
  } else {
    const username = req.session.username;
    var imageIndex = Math.floor(Math.random() * 3) + 1;
    const imagePath = `Cute${imageIndex}.gif`;
    res.render("members", {username, imagePath});
  }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
  const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();

  res.render("admin", {users: result});
});

app.post('/promote', sessionValidation, adminAuthorization, async (req, res) => {
  const username = req.session.username;
  const result = await userCollection.updateOne({username: username}, {$set: {user_type: 'admin'}});

  if (result.modifiedCount == 1) {
    console.log(`Promoted user ${username}`);
  }
  else {
    console.log(`Failed to promote user ${username}`);
  }
  res.redirect('/admin');
});

app.post('/demote', sessionValidation, adminAuthorization, async (req, res) => {
  const username = req.session.username;
  const result = await userCollection.updateOne({username: username}, {$set: {user_type: 'user'}});

  if (result.modifiedCount == 1) {
    console.log(`Demoted user ${username}`);
  }
  else {
    console.log(`Failed to demote user ${username}`);
  }

  res.redirect('/admin');
});

app.get('/logout', (req,res) => {
	req.session.destroy();
  res.redirect('/');
});

app.get('/cuteGif', (req,res) => {
  res.render("cuteGif");
});

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 