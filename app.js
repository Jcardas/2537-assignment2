require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3340;

const app = express();

const Joi = require("joi");

app.set('view engine', 'ejs');

const expireTime = 1000 * 60 * 60; // 1 hour

app.use(express.urlencoded({ extended: true })); // Middleware to parse form data

app.use(express.static('public'));

app.use(session({
	secret: process.env.NODE_SESSION_SECRET,
	resave: false,
	saveUninitialized: false,
	cookie: { maxAge: expireTime },
	store: MongoStore.create({
		mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true`,
		crypto: {
			secret: process.env.MONGODB_SESSION_SECRET
		},
		ttl: 60 * 60 // 1 hour in seconds
	})
}));

// Name Variable
let name = '';
// Middleware to set the name variable
app.use((req, res, next) => {
	if (req.session.user) {
		name = req.session.user.name;
	} else {
		name = '';
	}
	res.locals.name = name; // Pass the name variable to all views
	next();
});

// Home page
app.get('/', (req, res) => {
	const title = "Home";
	if (req.session.user) {
		const greeting = `Hello, ${req.session.user.name}!`;
		res.render('home', { name: req.session.user.name, greeting, title });
	} else {
		res.render('home', { title });
	}
});

// Sign up page
app.get('/signup', (req, res) => {
	res.render('signup', { title: "Signup" });
});

app.post('/signup', async (req, res) => {
	const { name, email, password } = req.body;
	// Joi schema for validation
	const schema = Joi.object({
		name: Joi.string().trim().min(1).max(100).required().messages({
			'string.empty': 'Name is required',
			'any.required': 'Name is required'
		}),
		email: Joi.string().trim().email().required().messages({
			'string.email': 'Email must be valid',
			'string.empty': 'Email is required',
			'any.required': 'Email is required'
		}),
		password: Joi.string().min(6).max(100).required().messages({
			'string.empty': 'Password is required',
			'any.required': 'Password is required',
			'string.min': 'Password must be at least 6 characters'
		})
	});
	const { error } = schema.validate({ name, email, password }, { abortEarly: false });
	if (error) {
		const errorMessages = error.details.map(d => `<li>${d.message}</li>`).join('');
		return res.status(400).send(`<h1>Signup Error</h1><ul>${errorMessages}</ul><a href='/signup'>Back to Sign Up</a>`);
	}

	// Connect to MongoDB
	const { database } = require('./databaseConnection');
	try {
		await database.connect();
		const db = database.db(process.env.MONGODB_DATABASE);
		// Check if user already exists
		const existingUser = await db.collection('users').findOne({ email });
		if (existingUser) {
			return res.status(400).send(`<h1>Error: Email already registered!</h1><a href='/signup'>Back to Sign Up</a>`);
		}
		// Hash the password
		const hashedPassword = await bcrypt.hash(password, saltRounds);
		// Insert user
		await db.collection('users').insertOne({
			name,
			email,
			password: hashedPassword,
			user_type: 'user' // Default user type
		});
		// Create session
		req.session.user = { name, email };
		res.redirect('/members');
	} catch (err) {
		console.error(err);
		res.status(500).send('<h1>Internal Server Error</h1>');
	}
});

// Login page
app.get('/login', (req, res) => {
	res.render('login', { title: "Login" });
});

app.post('/login', async (req, res) => {
	const { email, password } = req.body;
	// Joi schema for validation
	const schema = Joi.object({
		email: Joi.string().email().required(),
		password: Joi.string().min(6).max(100).required()
	});
	const validation = schema.validate({ email, password });
	if (validation.error) {
		return res.status(400).send(`<h1>Error: Invalid input!</h1><a href='/login'>Back to Login</a>`);
	}
	// Connect to MongoDB
	const { database } = require('./databaseConnection');
	try {
		await database.connect();
		const db = database.db(process.env.MONGODB_DATABASE);
		// Find user
		const user = await db.collection('users').findOne({ email });
		if (!user) {
			return res.status(400).send(`<h1>Error: User not found!</h1><a href='/login'>Back to Login</a>`);
		}
		// Check password
		const match = await bcrypt.compare(password, user.password);
		if (!match) {
			return res.status(400).send(`<h1>Error: Incorrect password!</h1><a href='/login'>Back to Login</a>`);
		}
		// Create session
		req.session.user = { name: user.name, email };
		res.redirect('/members');
	} catch (err) {
		console.error(err);
		res.status(500).send('<h1>Internal Server Error</h1>');
	}
});

// Members page
app.get('/members', (req, res) => {
	if (!req.session.user) {
		return res.redirect('/');
	}
	const images = ['/images/image1.jpg', '/images/image2.jpg', '/images/image3.jpg'];
	const randomImage = images[Math.floor(Math.random() * images.length)];
	const greeting = `Hello, ${req.session.user.name}!`;
	res.render('members', { name: req.session.user.name, randomImage, greeting, title: "Members" });
});

// Logout
app.get('/logout', (req, res) => {
	req.session.destroy(err => {
		if (err) {
			return res.status(500).send('<h1>Internal Server Error</h1>');
		}
		res.redirect('/');
	});
});

// About page
app.get('/about', (req, res) => {
	const title = "About";
	res.render('about', { title });
});

// Admin page
app.get('/admin', async (req, res) => {
	try {
		await database.connect();
		const db = database.db(process.env.MONGODB_DATABASE);

		// Check if the user is logged in and is an admin
		const user = await db.collection('users').findOne({ email: req.session.user?.email });
		if (!user) {
			return res.redirect('/login'); // Redirect to login if user isn't logged in
		}
		if (user.user_type !== 'admin') {
			return res.status(403).send(`<h1>Forbidden: You do not have access to this page</h1><a href='/'>Return to Home</a>`); // Display 403 if not an admin
		}

		// Fetch all users from the database
		const users = await db.collection('users').find({}).toArray();
		res.render('admin', { title: "Admin", users }); // Pass the users array to the template
	} catch (err) {
		console.error(err);
		res.status(500).send('<h1>Internal Server Error</h1>');
	}
});

// Promote user to admin
app.post('/admin/promote/:id', async (req, res) => {
	const userId = req.params.id;
	const { database } = require('./databaseConnection');
	try {
		await database.connect();
		const db = database.db(process.env.MONGODB_DATABASE);
		// Update user role to admin
		await db.collection('users').updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'admin' } });
		res.redirect('/admin');
	} catch (err) {
		console.error(err);
		res.status(500).send('<h1>Internal Server Error</h1>');
	}
});

// Demote user from admin
app.post('/admin/demote/:id', async (req, res) => {
	const userId = req.params.id;
	const { database } = require('./databaseConnection');
	try {
		await database.connect();
		const db = database.db(process.env.MONGODB_DATABASE);
		// Update user role to user
		await db.collection('users').updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'user' } });
		res.redirect('/admin');
	} catch (err) {
		console.error(err);
		res.status(500).send('<h1>Internal Server Error</h1>');
	}
});

// Error handling middleware
app.use((err, req, res, next) => {
	console.error(err.stack);
	res.status(500).send('<h1>Internal Server Error</h1>');
});

// 404 Not Found
app.use((req, res) => {
	res.status(404).render('404', { title: "404 Not Found" });
});

// Connect to database
const { database } = require('./databaseConnection');
database.connect()
	.then(() => {
		console.log('Connected to MongoDB');
	})
	.catch(err => {
		console.error('Failed to connect to MongoDB', err);
	});

// Start the server
app.listen(port, () => {
	console.log(`Server is running on port ${port}`);
});

async function getUsersFromDB() {
	const { database } = require('./databaseConnection');
	try {
		await database.connect();
		const db = database.db(process.env.MONGODB_DATABASE);
		const users = await db.collection('users').find({}).toArray();
		return users;
	} catch (err) {
		console.error(err);
		return [];
	}
}

