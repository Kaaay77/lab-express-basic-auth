const router = require("express").Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const User = require('../models/User.model');
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');
const session = require("express-session");

router.get('/sign-up', (req, res, next) => res.render('sign-up'));


router.post('/sign-up',(req, res, next) => {
  const {username, password} = req.body;
  if ( username === "" || password === ""){
    res.render('login', {errorMessage: 'Pon el nombre i la pass, me cago en tooooooo.'});
    return
  }

  bcryptjs
  .genSalt(saltRounds)
  .then(salt => bcryptjs.hash(password, salt))
  .then(contraseñaEncriptada =>{

     return User.create({
      username,
      passwordHash: contraseñaEncriptada
     })
  })
    .then(userFromDB => {
      res.redirect('/login');
    })
    .catch(error => next(error));

  })

router.get('/login', (req, res, next) => res.render('login'));

router.post('/login', (req, res, next) => {
  const {username, password} = req.body;
  console.log('session', req.session)
  if ( username === "" || password === ""){
    res.render('login', {errorMessage: 'Pon el nombre i la pass, me cago en tooooooo.'});
    return
  }

  User.findOne({username})
  .then (user => {
    if (!user) {
      res.render('login', { errorMessage: 'El nombre no esta registrado'
      })
      return;
    } else if (bcryptjs.compareSync(password, user.passwordHash)){

      req.session.currentUser = user;
      res.render('users/user-profile', {user});

    }else {
      res.render('login', { errorMessage: 'Nop, esa contraseña no ;)'});
    }

  })
  .catch(error => next(error));
})

router.get('/main', isLoggedIn, (req, res, next) => {
  
    res.render('users/main', { userInSession: req.session.currentUser });
  });


router.get('/private', isLoggedIn, (req,res,next) =>{

  res.render('users/private', { userInSession: req.session.currentUser });
})

router.get('/userPprofile', isLoggedIn, (req,res,next) =>{

  res.render('users/user-profile', { userInSession: req.session.currentUser });
})
module.exports = router;
