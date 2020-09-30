
function userValidator ( email, password='********', password_confirmation='********' ){
    let message = {}

    const isEmpty = ( str )=>{ return /^\s*$/.test(str) }


    if ( isEmpty(email) || !email )
        message.emailErr  = 'Email field is empty';

    if (  isEmpty(password) || !password )
        message.errorPassword = 'Password field is empty';


    if ( (password && password.length < 8) && !isEmpty(password) )
        message.errorPassword = 'Password is too short'


    if ( password !== password_confirmation  )
        message.errorPass_confirm = 'Passwords do not match'


    if ( Object.keys(message).length > 0 )
        return message
    else
        return false


};

module.exports = userValidator