const router = require("express").Router();
const mongoose = require("mongoose");

const User = require("../models/User.model");

const bcryptjs = require("bcryptjs");
const saltRounds = 10;

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/signup", isLoggedOut, (req, res) => {
  res.render("auth/signup");
});

router.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const salt = await bcryptjs.genSaltSync(saltRounds);
    const passwordHashed = await bcryptjs.hashSync(password, salt);
    //if (!email.includes('@')){
    //throw new Error("incorrect email")
    //}
    const newUser = await User.create({
      username,
      email,
      password: passwordHashed,
    });
    //console.log("new user", newUser);
    res.redirect("/login");
  } catch (error) {
    if (error instanceof mongoose.Error.ValidationError) {
      res.status(500).render("auth/signup", { errorMessage: error.message });
    } else if(error.code === 11000){
      res.status(500).render("auth/signup", { errorMessage: "Username and email need to be unique." });
    }else {
      console.log(error);
    }
  }
});

router.get("/login", (req, res) => res.render("auth/login"));

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (email === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, email and password to login.",
    });
    return;
  }
  const userLogged = await User.findOne({ email });
  if (!userLogged) {
    res.render("auth/login", {
      errorMessage: "User does not exist. Try again please",
    });
    return;
  } else if (bcryptjs.compareSync(password, userLogged.password)) {
    //currentUser = userLogged
    console.log("SESSION =====> ", req.session);
    req.session.currentUser = userLogged;
    res.redirect("/user-profile");
    //res.render("users/user-profile", { userLogged });
  } else {
    res.render("auth/login", { errorMessage: "wrong password" });
  }
});

router.get("/user-profile", isLoggedIn, (req, res)=>{
  console.log(req.session)
  res.render("users/user-profile", {userInSession: req.session.currentUser})
});

router.get('/user-profile/main', isLoggedIn, (req,res)=>{
  res.render("users/main")
})
router.get('/user-profile/private', isLoggedIn, (req,res)=>{
  res.render("users/private")
})

router.post('/logout', (req, res)=>{
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
})
module.exports = router;
