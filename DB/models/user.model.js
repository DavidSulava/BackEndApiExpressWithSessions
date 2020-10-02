const mongoose = require('mongoose');
const bcrypt   = require("bcryptjs");

const callsSchema = new mongoose.Schema(
  {
    line_type     : {type : Number,  default : 39762 },
    call_cost     : {type : Number,  default : 0 },
    duration_secs : {type : Number,  default : 0 },
  },
  { timestamps: true }
);

const billsSchema = new mongoose.Schema(
  {
    address   : {type : String,  default : 'Маяковского, 33' },
    total_sum : {type : Number,  default : 0 },
    status    : {type : Boolean, default : false },
  },
  { timestamps: true }
);

const userSchema = new mongoose.Schema(
  {
    email      : {type : String, required: true, trim:true },
    password   : {type : String, required: true, trim:true },
    jwt        : {type : String, default : null },
    jwtRefresh : {type : String, default : null },
    firstName  : {type : String, default : '' },
    lastName   : {type : String, default : '' },
    isVerified : {type : Boolean,default : false },
    token      : {type : String, default : null },
    timeToken  : {type : Number, default : null },
    calls      : [callsSchema],
    bills      : [billsSchema]

  },
  { timestamps: true }
);

  userSchema.pre( 'save', function( next ){
        if ( !this.isModified('password') ) return next();

        const user = this;

        bcrypt.genSalt( 10, function( err, salt ){
              if ( err ){ return next( err ) }

              bcrypt.hash( user.password, salt, function( err, hash ){
                    if( err ){ return next( err ) }

                    user.password = hash;
                    next();
              })
        })
  });

userSchema.methods.comparePassword  = function( str , callback ){
  return callback( null, bcrypt.compareSync( str, this.password ) );
}

const User_scm =  mongoose.model( 'users', userSchema ) ;

module.exports = User_scm;