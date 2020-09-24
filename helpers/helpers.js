const nodemailer = require("nodemailer");


const serverError = function (error, res, at_where = '') {
    // .... to be improved.
    console.error(`-*-something went wrong at ${ at_where } -*-`, error);
    return res.status(500).json({
      msg: {
        server_error: `something went wrong at ${ at_where }`
      }
    });

}

const userSessionHandle = (req, res, user) => {
    if (!req.session['user']) {
      req.session['user'] = {
        _id: user._id,
        name: user.name,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified,
      };

      // req.fields.user = { name: user.name, email: user.email };

      // res.cookie('t_user', { name: user.name, email: user.email }, {signed: true} );
    } else {
      res.clearCookie('t_user')
    }

}
const userObject = (data) => {
    var userPrepared = {
      name: data.name,
      email: data.email,
      firstName: data.firstName,
      lastName: data.lastName,
      isVerified: data.isVerified
    };
    return userPrepared
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

module.exports = { serverError, userSessionHandle, userObject, sendEmail }