const nodemailer = require("nodemailer");
var jwt = require('jsonwebtoken');


const jwtSetToken = (object, secret, expires=null ) => {

  // JWT
  if( !expires )
    return jwt.sign( object, secret );

  // JWT - refresh
  return jwt.sign( object, secret, { expiresIn: expires } );
}

const jwtGetByToken = (req, res, next) => {

  const authHeader = req.get('authorization');
  const jwt_static= authHeader && authHeader.split(" ")[0];

  const jwt_refresh = req.cookies.jwt_refresh && req.cookies.jwt_refresh.split(" ")[0]

  if (!jwt_static || !jwt_refresh ) return res.status(401).send({
    user: null
  });

  try{
    jwt.verify( jwt_refresh, process.env.JWT_TOKEN_REFRESH );
  }
  catch(err){
    // not valid token
    return res.status(401).send({
      msg:{ errorCred: 'Session expired' },
      user: null
    });
  }

  jwt.verify( jwt_static, process.env.JWT_TOKEN, (err, user) => {

    if (err) return res.status(401).send({
      msg:{ errorCred: err },
      user: null
    }); // not valid token


    req.user = user
    res.cookie("jwt_refresh", jwt_refresh, {httpOnly: true})

    next();

  })
}

const userObject = (data) => {

  return {
    email: data.email,
    firstName: data.firstName,
    lastName: data.lastName,
    isVerified: data.isVerified
  }
}

const cookieSettings =()=>{
  return  { httpOnly: true, secure:true, sameSite: 'None' }
}

const sendEmail = async function (From, ToEmail, subject, html) {
  // create reusable transporter object using the default SMTP transport
  let transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465, // 587, 465
    secure: true, // true for 465, false for other ports
    auth: {
      user: process.env.CONTACT_EMAIL,
      pass: process.env.CONTACT_EMAIL_PASSWORD,
    }
  });

  // send mail with defined transport object
  let info = await transporter.sendMail({
    from: `${From} <webproto3@gmail.com>`, // sender address
    to: ToEmail, // list of receivers
    subject: subject, // Subject line
    html: html // html body

  });

}

const serverError = function (error, res, at_where = '') {
  // .... to be improved.
  console.error(`-*-something went wrong at ${ at_where } -*-`, error);
  return res.status(500).json({
    msg: {
      server_error: `something went wrong at ${ at_where }`
    }
  });

}

const addTime = (addedTime)=>{
  return Date.now() + addedTime ;
}

module.exports = {
  userObject,
  sendEmail,
  jwtGetByToken,
  jwtSetToken,
  serverError,
  addTime,
  cookieSettings
}