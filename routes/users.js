var express = require('express');
var router = express.Router();

const bcrypt = require("bcryptjs");

const User_scm = require('../backend/models/user.model');
const userValidator = require( '../backend/validators/userValidator' )


const { serverError, userSessionHandle, userObject, sendEmail, jwtGetByToken, jwtSetToken } = require("../helpers/helpers");

const badCredentials_m = "Пользователя с такими данными не существует";
const success = "Введенные данные верны, доступ разрешен.";
const registered = " зарегестрирован.";
const userUpdated = "Данные пользователя изменены";
const emailConfEr = 'Email verification timeout exceeded ! Please, login and verify your email agin in user settings';
const passChanged = 'Пароль успешно изменен';
const wrongPassword = 'Неверный пароль';



/* Check if User exists in Session*/
router.get('/checkUser', jwtGetByToken, function (req, res) {

  return res.status(200).send({user: req.user});
});

/* Delete User Session*/
router.get('/logOut', jwtGetByToken,  async function (req, res) {

  return res.status(200).send({
    user: null
  });
});

/* Register User*/
router.post('/register', async function (req, res, next) {

  var userEmail = req.fields.email ? req.fields.email : '';
  var firstName = req.fields.firstName ? req.fields.firstName : '';
  var lastName = req.fields.lastName ? req.fields.lastName : '';
  var userPassword = req.fields.password ? req.fields.password : '';
  var password_confirmation = req.fields.password_confirmation ? req.fields.password_confirmation : '';


  let validateMessage = userValidator( userEmail, userPassword, password_confirmation);

  if (validateMessage)
    return res.status(401).json({
      msg: validateMessage
    });



  var check = await User_scm.findOne({
    email: userEmail
  }).catch(error => {
    return serverError(error, res, 'registering the user')
  });

  if (!check) {
    //  ---------- [ variables for email authentication ] -------------
    // var hostName = req.get('x-forwarded-host');
    // var hostName = require("os").hostname();
    var hostName = req.headers.origin;
    var cTime = Date.now() + (1000 * 60 * 15);
    var hash = bcrypt.hashSync(`${ cTime }_${ userEmail }`, 8);
    var link = `${hostName}/email/authentication/${userEmail}/${encodeURIComponent(hash)}`;


    var user = new User_scm({
      email: userEmail,
      password: userPassword,
      firstName: firstName,
      lastName: lastName,
      token: hash,
      timeToken: cTime
    });


    let dataSaved = await user.save();
    if (dataSaved) {

      // -----------[ Handle jwt ]--------------
      userPrepared =  userObject(check)
      let jwt = jwtSetToken({...userPrepared, '_id': user._id }, process.env.SESSION_SECRET_STR);

      //  ---------- [ send email ] -------------
      // var protocol = req.connection.encrypted ? 'https://' : 'http://';
      var html = `<div><p>Пожалуйста, пройдите по ссылке что бы подтвердить свой адрес эл.почты !</p> <a href='${link}'>Нажмите сдесь</a></div>`;

      await sendEmail(hostName, userEmail, 'email confirmation', html).catch(console.error);


      // --------- [ return Response] ---------------
      return res.status(200).json({
        msg: {
          regSuccess: user.email + registered
        },
        user: {...userPrepared, jwt}
      });
    } else
      return serverError(dataSaved, res, 'registering the user')

  } else
    return res.status(401).json({
      msg: {
        errorCred: 'Такой пользователь уже существует. Пожалуйста, введите другой адрес эл.почты !'
      }
    });

});

// Login User -- find the user by his id
router.post('/login', async function (req, res) {

  var userEmail = req.fields.email ? req.fields.email : '';
  var userPassword = req.fields.password ? req.fields.password : '';

  var check = await User_scm.findOne({
    email: userEmail
  }).catch(error => serverError(error, 'login the user'));

  if (!check)
    return res.status(401).send({
      msg: {
        errorCred: badCredentials_m
      }
    });

  check.comparePassword(userPassword, (err, callBack) => {

    if (err) serverError(err, 'at password comparison --at attempt to login');

    if (!callBack) {
      return res.status(401).send({
        msg: {
          errorCred: badCredentials_m
        }
      });
    }

    userPrepared =  userObject(check)
    let jwt = jwtSetToken({...userPrepared, '_id': check._id }, process.env.SESSION_SECRET_STR);

    return res.status(200).send({
      msg: {
        loginSuccess: success
      },
      user: { ...userPrepared,  jwt  },
     
    });

  })
})

/* Update User*/
router.post('/updateUser', jwtGetByToken, async function (req, res) {



  var userEmail = req.fields.email ? req.fields.email : '';
  var firstName = req.fields.firstName ? req.fields.firstName : '';
  var lastName = req.fields.lastName ? req.fields.lastName : '';


  let validateMessage = userValidator( userEmail );
  if (validateMessage)
    return res.status(401).send({
      msg: validateMessage
    });


  var id = req.user._id

  var check = await User_scm.findById(id).catch(error => serverError(error, res, 'updating the user'));

  if (!check)
    return res.status(400).send({
      msg: {
        message: badCredentials_m
      }
    });

  // -----------[ Check and Update Email ]--------------
  if (userEmail && userEmail != check.email) {
    let checkEmail = User_scm.find({
      email: userEmail
    })


    if (checkEmail)
      return res.status(401).send({
        msg: {
          emailErr: 'A user with such email already exists!'
        }
      });
    else {
      check.email = userEmail;
      check.isVerified = false;
    }

  }

  check.firstName = firstName
  check.lastName = lastName

  let dataSaved = await check.save();
  if (dataSaved) {

    userPrepared =  userObject(check)
    let jwt = jwtSetToken({...userPrepared, '_id': check._id }, process.env.SESSION_SECRET_STR);

    return res.status(200).send({
      msg: {
        userUpdated: userUpdated
      },
      user: {...userPrepared, jwt}
    });
  }

  


});


/* [ Change the Password ]*/
router.post('/newPassword', jwtGetByToken, async function (req, res) {
  var oldUserPassword = req.fields.password ? req.fields.password : '';
  var newUserPassword = req.fields.new_assword ? req.fields.new_assword : '';


  // -----------[ Change the Password ]---------------
  if (oldUserPassword && newUserPassword) {

    var id = req.user._id;
    var check = await User_scm.findById(id).catch(error => serverError(error, res, 'updating the user'));

    if (!check) {
      return res.status(401).send({
        msg: {
          message: badCredentials_m
        }
      });
    }


    check.comparePassword(oldUserPassword, async (err, callBack) => {

      if (err)
        return serverError(err, `at password comparison --at updating the user: ${ check.email }`);

      if (!callBack) {
        return res.status(401).send({
          msg: {
            erPassword: wrongPassword
          }
        });
      }

      check.password = newUserPassword;

      var newPasSaved = await check.save()

      if (newPasSaved)
        return res.status(200).send({
          msg: {
            passUpdated: passChanged
          },
          user: userObject(check)
        });
      else
        return serverError(newPasSaved, 'saving updated data of the user');

    });
  } else
    return res.status(401).send({
      msg: {
        erPassword: 'Please fill in all necessary  fields for password changing !'
      }
    });

})

/* Delete User*/
router.post('/deleteUser', jwtGetByToken, async function (req, res) {

  var userEmail = req.fields.email ? req.fields.email : '';
  var userPassword = req.fields.password ? req.fields.password : '';


  var validatePass = userValidator('********', userEmail, userPassword, userPassword);
  if (validatePass)
    return res.status(401).send({
      msg: validatePass
    });

  var id = req.user._id || null;
  var check = await User_scm.findById(id).catch(error => serverError(error, 'deleting the user'));

  if (!check)
    res.status(401).send({
      msg: {
        errorPassword: badCredentials_m
      }
    });


  check.comparePassword(userPassword, (err, callBack) => {
    if (err)
      serverError(err, `at password comparison --at deleting the user: ${ check.email }`);

    if (!callBack || (check.email != userEmail)) {
      return res.status(401).send({
        msg: {
          errorPassword: badCredentials_m
        }
      });
    }

    var deletedUser = check.email;

    check.remove(function (err, check) {

      if (err) return serverError(err, `removing  the user: ${ check.email }`);

      if (check.$isDeleted())
        return res.status(200).send({
          msg: {
            userDeleted: `User ${ deletedUser } has ben deleted.`
          }
        });
      else
        return res.status(400).send({
          msg: {
            message: `Something went wrong at deleting ${ deletedUser } `
          }
        });

    });



  });

});

// send verification link from user settings
router.get('/email/sendVerification', jwtGetByToken, async function (req, res) {

  var userEmail = req.query.email ? req.query.email : '';

  // -----------[ Check and Update Email ]--------------
  if (userEmail) {
    
    var checkEmail = false

    if (userEmail != req.user.email)
      checkEmail = User_scm.find({
        email: userEmail
      })


    if (checkEmail)
      return res.status(401).send({
        msg: {
          emailErr: 'A user with such email already exists!'
        }
      });
    else {
      var check = await User_scm.findById(req.user._id).catch(error => serverError(error, res, 'updating the user'));

      var hostName = req.headers.origin;
      var cTime = Date.now() + (1000 * 60 * 15);
      var hash = bcrypt.hashSync(`${ cTime }_${ userEmail }`, 8);
      var link = `${hostName}/email/authentication/${userEmail}/${encodeURIComponent(hash)}`;

      // var protocol = req.connection.encrypted ? 'https://' : 'http://';
      var html = `<div><p>Please click the link below to confirm your email !</p> <a href='${link}'>Click Here</a></div>`;

      // --- change data in database
      check.token = hash;
      check.timeToken = cTime;
      check.isVerified = false;

      let dataSaved = await check.save();

      if (dataSaved) {
        //  ---------- [ send email confirmation link ] -------------
        await sendEmail(hostName, userEmail, 'email confirmation', html).catch(console.error);

        userPrepared =  userObject(check)
        let jwt = jwtSetToken({...userPrepared, '_id': check._id }, process.env.SESSION_SECRET_STR);

        return res.status(200).send({
          msg: {
            verLinkSend: `Verification link has been sent to ${ check.email }`
          },
          user: {...userPrepared, jwt}
        });
      }
    }

  }
  
})

/* Email Confirmation Check*/
router.get('/email/confirmation', async function (req, res, next) {
  var token = req.query.token ? decodeURIComponent(req.query.token) : '';
  var email = req.query.email ? req.query.email : '';

  if (email && token) {
    var check = await User_scm.findOne({
      email: email
    }).catch(error => serverError(error, 'login the user'));

    if (!check)
      return res.status(401).send({
        msg: {
          errorCred: badCredentials_m
        }
      });

    if (check.token == token && check.email == email) {
      var cTime = Date.now();

      if (cTime <= check.timeToken) {

        check.isVerified = true;
        let dataSaved = await check.save();

        if (dataSaved) {
          
          // -----------[ Create Session ]--------------
          if (!req.session['user']) //  <<<<<<<<<<<<<<---- TO BE DONE
            userSessionHandle(req, res, check);
          else
            req.session['user'] = {
              ...req.session['user'],
              ...{
                isVerified: check.isVerified
              }
            }// >>>>>>>>>> -------

          return res.status(200).send({
            msg: {
              regSuccess: 'success',
              emailConfirmed: 'Эл.почта успешно подтверждена !'
            },
            user: userObject(check)
          });
        }

      } else
        return res.status(401).send({
          msg: {
            timeErr: emailConfEr
          }
        });

    } else {
      return res.status(401).send({
        msg: {
          errorCred: badCredentials_m
        }
      });
    }

  };


  return res.status(401).send({
    msg: {
      errorCred: badCredentials_m
    }
  });
});


module.exports = router;