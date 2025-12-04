<img width="498" height="103" alt="image" src="https://github.com/user-attachments/assets/38f3794e-58c4-4b3d-a31e-4ef089121296" />

# Per Scholas Software Engineer Bootcamp LAB 14.2

## Do you want to get **_free_** tech training from Per Scholas?

## [Click Here to find out how!](https://perscholas.referralrock.com/l/7MIDHLPB/)

---

![screenshot of server.js](image.png)

# Lab 14.2

## Secure Record Storage

## Scenario

You have been given a pre-existing “Notes” API. It has full CRUD (Create, Read, Update, Delete) functionality and is protected by authentication middleware, meaning only logged-in users can access the endpoints. However, there’s a significant flaw: any authenticated user can view, update, or delete any note, regardless of who created it.

Your task is to implement authorization logic to ensure that users can only access and manage the notes they personally own.

# Instructions

For this lab, you will be provided with a starter codebase. The starter code contains a simple Express API with user authentication and a /api/notes endpoint.

# Task 1: Associate Notes with Users

Update the Note Model: Add a new field to the Note schema (models/Note.js). This field should be named user (or owner) and should store the ObjectId of the user who created the note. It should be a required reference to the User model.

---

// Example snippet for the Note schema

---

```js
user: {
  type: Schema.Types.ObjectId,
  ref: 'User',
  required: true,
}
```

Modify the “Create Note” Route: In your notes route file (routes/api/notes.js), find the POST / route. When a new note is created, you must associate it with the currently logged-in user. The authenticated user’s data should be available on req.user from the authentication middleware. Save the user’s \_id to the new note’s user field.

# Task 2: Implement Ownership-Based Authorization

Filter “Get All Notes”: Modify the GET / route. Instead of returning all notes in the database, it should now only return the notes where the user field matches the \_id of the currently authenticated user (req.user.\_id).

## Secure “Update Note”: Modify the PUT /:id route.

Before updating a note, you must first find the note by its ID. Then, check if the user field on that note matches the authenticated user’s \_id.

If they match, proceed with the update.
If they do not match, return a 403 Forbidden status with an error message like "User is not authorized to update this note."
Secure “Delete Note”: Modify the DELETE /:id route. Similar to the update route, you must check for ownership before deleting a note.

## Find the note by its ID.

If the user is the owner, delete the note.
If the user is not the owner, return a 403 Forbidden status with an appropriate error message.
(Optional) Secure “Get Single Note”: If you have a GET /:id route, apply the same ownership check there as well.

## Acceptance Criteria

The Note model includes a required user field referencing the User model.
The POST /api/notes route correctly assigns the logged-in user’s ID to the new note.
The GET /api/notes route only returns notes created by the currently logged-in user.
The PUT /api/notes/:id and DELETE /api/notes/:id routes prevent users from modifying or deleting notes they do not own, returning a 403 status code.
The API functions correctly for all valid requests.

# Submission

Submit a link to your completed GitHub repository.
Your submission should be based on the provided starter code.

# Grading

This lab is worth 50 points.

# Starter Code

You will be provided with a starter codebase for this lab. Below are the contents of the files you will need. Create these files in your local project directory.

```js
********************************************************************************
.gitignore
********************************************************************************
node_modules
.env

********************************************************************************
.env.example
********************************************************************************
# Replace with your MongoDB Atlas connection string
MONGO_URI=mongodb://127.0.0.1:27017/notesdb

# Choose a long, random string for your JWT secret
JWT_SECRET=yoursupersecretjwttoken

**********************************************************************************
server.js
**********************************************************************************

const express = require('express');
const path = require('path');
const db = require('./config/connection');
const routes = require('./routes');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// if we're in production, serve client/build as static assets
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
}

app.use(routes);

db.once('open', () => {
  app.listen(PORT, () => console.log(`🌍 Now listening on localhost:${PORT}`));
});

********************************************************************************
config/connection.js
********************************************************************************

const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

module.exports = mongoose.connection;

********************************************************************************
models/User.js
********************************************************************************

const { Schema, model } = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: [/.+@.+\..+/, 'Must use a valid email address'],
  },
  password: {
    type: String,
    required: true,
    minlength: 5,
  },
});

// hash user password
userSchema.pre('save', async function (next) {
  if (this.isNew || this.isModified('password')) {
    const saltRounds = 10;
    this.password = await bcrypt.hash(this.password, saltRounds);
  }

  next();
});

// custom method to compare and validate password for logging in
userSchema.methods.isCorrectPassword = async function (password) {
  return bcrypt.compare(password, this.password);
};

const User = model('User', userSchema);

module.exports = User;

********************************************************************************
models/Note.js
********************************************************************************

const { Schema, model } = require('mongoose');

// This is the model you will be modifying
const noteSchema = new Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  content: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Note = model('Note', noteSchema);

module.exports = Note;

********************************************************************************
utils/auth.js
********************************************************************************

const jwt = require('jsonwebtoken');

const secret = process.env.JWT_SECRET;
const expiration = '2h';

module.exports = {
  authMiddleware: function (req, res, next) {
    let token = req.body.token || req.query.token || req.headers.authorization;

    if (req.headers.authorization) {
      token = token.split(' ').pop().trim();
    }

    if (!token) {
      return res.status(401).json({ message: 'You must be logged in to do that.' });
    }

    try {
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      req.user = data;
    } catch {
      console.log('Invalid token');
      return res.status(401).json({ message: 'Invalid token.' });
    }

    next();
  },
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };

    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
};

********************************************************************************
routes/index.js
********************************************************************************

const router = require('express').Router();
const apiRoutes = require('./api');

router.use('/api', apiRoutes);

router.use((req, res) => {
  res.status(404).send('<h1>😝 404 Error!</h1>');
});

module.exports = router;
routes/api/index.js

const router = require('express').Router();
const userRoutes = require('./userRoutes');
const noteRoutes = require('./noteRoutes');

router.use('/users', userRoutes);
router.use('/notes', noteRoutes);

module.exports = router;
routes/api/userRoutes.js

const router = require('express').Router();
const { User } = require('../../models');
const { signToken } = require('../../utils/auth');

// POST /api/users/register - Create a new user
router.post('/register', async (req, res) => {
  try {
    const user = await User.create(req.body);
    const token = signToken(user);
    res.status(201).json({ token, user });
  } catch (err) {
    res.status(400).json(err);
  }
});

// POST /api/users/login - Authenticate a user and return a token
router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return res.status(400).json({ message: "Can't find this user" });
  }

  const correctPw = await user.isCorrectPassword(req.body.password);

  if (!correctPw) {
    return res.status(400).json({ message: 'Wrong password!' });
  }

  const token = signToken(user);
  res.json({ token, user });
});

module.exports = router;

********************************************************************************
routes/api/noteRoutes.js
********************************************************************************

const router = require('express').Router();
const { Note } = require('../../models');
const { authMiddleware } = require('../../utils/auth');

// Apply authMiddleware to all routes in this file
router.use(authMiddleware);

// GET /api/notes - Get all notes for the logged-in user
// THIS IS THE ROUTE THAT CURRENTLY HAS THE FLAW
router.get('/', async (req, res) => {
  // This currently finds all notes in the database.
  // It should only find notes owned by the logged in user.
  try {
    const notes = await Note.find({});
    res.json(notes);
  } catch (err) {
    res.status(500).json(err);
  }
});

// POST /api/notes - Create a new note
router.post('/', async (req, res) => {
  try {
    const note = await Note.create({
      ...req.body,
      // The user ID needs to be added here
    });
    res.status(201).json(note);
  } catch (err) {
    res.status(400).json(err);
  }
});

// PUT /api/notes/:id - Update a note
router.put('/:id', async (req, res) => {
  try {
    // This needs an authorization check
    const note = await Note.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!note) {
      return res.status(404).json({ message: 'No note found with this id!' });
    }
    res.json(note);
  } catch (err) {
    res.status(500).json(err);
  }
});

// DELETE /api/notes/:id - Delete a note
router.delete('/:id', async (req, res) => {
  try {
    // This needs an authorization check
    const note = await Note.findByIdAndDelete(req.params.id);
    if (!note) {
      return res.status(404).json({ message: 'No note found with this id!' });
    }
    res.json({ message: 'Note deleted!' });
  } catch (err) {
    res.status(500).json(err);
  }
});

module.exports = router;
```
