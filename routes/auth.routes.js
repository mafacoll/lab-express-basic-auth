const router = require('express').Router();
const UserModel = require('../models/User.model');
const bcrypt = require('bcryptjs');

router.get('/signup',(req,res, next)=>{
    res.render('auth/signup.hbs')
})


router.post('/signup', (req, res, next) =>{
    const {username,password} = req.body

    if(username == '' || password == ''){
        res.render('auth/signup.hbs', {error: 'Please enter all the information'})
        return; 
    }

    let passRegEx = new RegExp(
        "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})"
      );
      if (!passRegEx.test(password)) {
        res.render("auth/signup.hbs", {
          error:
            "Please enter minimum eight characters, at least one uppercase character, one lowercase character, one special character and one number for your password.",
        });
        return;
      }
    

    let salt = bcrypt.genSaltSync(10);
    let hash = bcrypt.hashSync(password, salt);

    UserModel.create({username, password: hash})
    .then(() =>{
        res.redirect('/')
    })
    .catch((err) => {
        if (err.code == 11000) {
          res.render("auth/signup.hbs", {
            error: "Username is taken, please choose another one",
          });
        }
        next(err);
      });
  
})

router.get('/login', (req, res, next) =>{
    res.render('auth/login.hbs')

})

router.post('/login', (req, res, next) => {
    const {username, password} = req.body

    UserModel.find({username})
    .then((usernameResponse) =>{
        if(usernameResponse.length){
            let userObject = usernameResponse[0]
            let isMatching = bcrypt.compareSync(password, userObject.password);
            if(isMatching){
                req.session.myProperty = userObject
                res.redirect('/private')
            }
            else{
                res.render('auth/login.hbs', {error:'Not working, sorry'})
                return;
            }
        }
        else {
            res.res('auth/login.hbs',{error: 'Wrong username'})
            return;
        }
    })
    .catch((error) =>{
        next(error)
    })
})

const checkLogIn = (req, res, next) => {
    if(req.session.myProperty){
        next()
    }
    else {
        res.redirect('/login')
    }
}

router.get('/main', checkLogIn,(req, res, next)=>{
    res.render('main.hbs')
})

router.get('/private', checkLogIn,(req, res, next)=> {
    res.render('private.hbs')
})

module.exports = router;