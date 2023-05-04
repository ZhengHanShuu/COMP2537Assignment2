require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

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

app.get('/', (req,res) => {
    var html = `
      <form method='get'>
        <div>
          <button formaction='/createUser'>Sign Up</button>
        </div>
        <div>
          <button formaction='/login'>Log In</button>
        </div>
      </form>
    `;
    var html1 = `
    <h1>Hello, ${req.session.username}!</h1>
    <form method = 'get'>
    <div>
        <button formaction='/members'>Members Area</button>
    </div>
    <div>
        <button formaction='/logout'>Log Out</button>
    </div>
    </form>
    `
    if(!req.session.authenticated){
      res.send(html);
    }else {
      res.send(html1);
    }
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/createUser', (req,res) => {
    var html = `
    <h1>Create User</h1>
    <form method="POST" action="/submitUser">
      <label for="name">Name:</label>
      <input type="text" name="username" id="name" required><br>
      <label for="email">Email:</label>
      <input type="email" name="email" id="email" required><br>
      <label for="password">Password:</label>
      <input type="password" name="password" id="password" required><br>
      <input type="submit" value="Submit">
    </form>
  `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    <h1>Log In</h1>
    <form method="POST" action="/loggingin">
      <label for="email">Email:</label>
      <input type="email" name="email" id="email" required><br>
      <label for="password">Password:</label>
      <input type="password" name="password" id="password" required><br>
      <input type="submit" value="Submit">
    </form>
  `;
    res.send(html);
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
	
	await userCollection.insertOne({email: email, username: username, password: hashedPassword});
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
    .project({email: 1, password: 1, username: 1, _id: 1})
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
      res.redirect('/members');
      return;
  }
  else {
      var html = `
      invalid password!
      <a href= "/login">try again</a>
      `;
      res.send(html);
      console.log("incorrect password");
      return;
  }
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    <a href="/logout">Log Out</a>
    `;
    res.send(html);
});

app.use(express.static('public'));

app.get('/members', (req,res) => {
  if (!req.session.authenticated) {
      res.redirect('/login');
  } else {
    var username = req.session.username;
    var imageIndex = Math.floor(Math.random() * 2) + 1;
    var imagePath = `Cute${imageIndex}.gif`;
    var html = `
    <h1>Hello, ${username}!</h1>
    <img src="${imagePath}">
    <a href="/logout">logout</a>
    `;
    res.send(html);
  }
});

app.get('/logout', (req,res) => {
	req.session.destroy();
  res.redirect('/');
});

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 