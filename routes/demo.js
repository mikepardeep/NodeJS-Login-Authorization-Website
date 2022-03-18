const express = require('express');
const bcrypt = require('bcryptjs');

const db = require('../data/database');

const router = express.Router();

router.get('/', function (req, res) {
  res.render('welcome');
});

router.get('/signup', function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: '',
      confirmEmail: '',
      password: ''
    };
  }

  req.session.inputData = null;

  res.render('signup', { inputData: sessionInputData});
});

router.get('/login', function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: '',
      password: ''
    };
  }
  req.session.inputData = null;
  res.render('login', {inputData: sessionInputData});
});

router.post('/signup', async function (req, res) {
  //get the data from the form in signup.ejs
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData['confirm-email']; //disallowed the - in dot notation
  const enteredPassword = userData.password;

  //condition the signup input data.
  if (!enteredEmail || 
    !enteredConfirmEmail || 
    !enteredPassword || 
    enteredPassword.trim() < 6 || 
    enteredEmail !== enteredConfirmEmail || 
    !enteredEmail.includes('@')
  ){
      
    req.session.inputData = {
      hasError: true,
      message: 'Invalid input - please check your data.',
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };
    req.session.save(function(){
      //return res.render
      res.redirect('/signup');
    })
    return;
    
  }
  
  //find for existing users in the database
  const existingUser = await db.getDb().collection('users').findOne({email: enteredEmail})

  //condition if existing user in the database
  if (existingUser){
    req.session.inputData = {
      hasError: true,
      message: 'User Exists Already',
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };
    req.session.save(function(){
      return res.redirect('/signup');
    })
    return;
    
  }

  //hashed password
  const hashedPassword = await bcrypt.hash(enteredPassword,12);

  //user object to be inserted as document in the database
  const user = {
    email: enteredEmail,
    password: hashedPassword,
  };

  //access to the database (user database created automatically)
  await db.getDb().collection('users').insertOne(user);

  //redirect to the login page
  res.redirect('/login');

});

router.post('/login', async function (req, res) {
  //data retrieved from the form
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredPassword = userData.password;

  //query for checking existing users
  const existingUser = await db.getDb().collection('users').findOne({email: enteredEmail});

  //condition for users
  if (!existingUser) {
    req.session.inputData = {
      hasError: true,
      message: 'Could not you log in - please check your credential',
      email: enteredEmail,
      password: enteredPassword,
    };
    req.session.save(function(){
      res.redirect('/login');
    });
    return;
   
  }

  //check the unhash value to the hash value
  const passwordsAreEqual = await bcrypt.compare(enteredPassword, existingUser.password)

  //if password not equal
  if (!passwordsAreEqual){
    req.session.inputData = {
      hasError: true,
      message: 'Could not log you in - please check your credentials',
      email: enteredEmail,
      password: enteredPassword,
    };
    req.session.save(function(){
      res.redirect('/login');
    });

    return;
  }

  //add data to the session
  req.session.user = {id: existingUser._id , email: existingUser.email };
  req.session.isAuthenticated = true;
  req.session.save(function() {
    //Now the password and email is correct
    res.redirect('/profile');
  });

});

router.get('/admin', async function (req, res) {
  //check the user "ticket"
  if (!req.session.isAuthenticated){ //if (!req.session.user)
    return res.status(401).render('401');
  }

  const user = await db.getDb().collection('users').findOne({_id:req.session.user.id});

  if(!user || !user.isAdmin) {
     res.status(403).render('403');
  }

  res.render('admin');

});

router.get('/profile', function (req, res) {
  //check the user "ticket"
  if (!req.session.isAuthenticated){ //if (!req.session.user)
    return res.status(401).render('401');
  }

  res.render('profile');

});

router.post('/logout', function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect('/');
});

module.exports = router;
