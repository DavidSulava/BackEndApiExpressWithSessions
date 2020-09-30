var express = require('express');
var router = express.Router();

const {jwtGetByToken } = require("../helpers/helpers");


const User_scm = require('../DB/models/user.model');

/* GET home page. */
router.get('/bills', jwtGetByToken, async function(req, res, next) {


  let query = {};

  let userEmail  = req.user.email;
  let getRequest =  req.query.hasOwnProperty("page") && req.query.page > 0 ? req.query : {...req.query, page: 0  };
  let curentPage = (getRequest.page && getRequest.page > 1) ? getRequest.page : 0;
  let modifuedPage = (curentPage > 2) ? curentPage - 1 : (curentPage == 2)? 1 : curentPage ;
  let perPage    = 5;
  let skipPages  = modifuedPage * perPage;

  let userDb = await User_scm.findOne({
    email: userEmail
  }).catch(error => serverError(error, 'login the user'));

  if(!userDb || !userDb.bills)
    return res.status(401).send({bills: null});

  let total = Math.floor(userDb.bills.length/perPage);

  User_scm.aggregate([
      {'$match':{ email: userEmail }},
      {'$unwind':'$bills'},
      { "$group": { "_id": '$bills'} },
      {$sort:{"_id.total_sum":-1}},
      {'$skip':skipPages},
      {'$limit':perPage},

    ], function(err, result){

      if(err){return(res.send(500, err))}

      return  res.status(200).json({
        bills : result,
        page  : req.query.page,
        totalPages: total,
        params    : getRequest
      });

    });
});

router.get('/calls', jwtGetByToken, async function(req, res, next) {

  let query = {};

  let userEmail  = req.user.email;
  let getRequest =  req.query.hasOwnProperty("page") && req.query.page > 0 ? req.query : {...req.query, page: 0  };
  let curentPage = (getRequest.page && getRequest.page > 1) ? getRequest.page : 0;
  let modifuedPage = (curentPage > 2) ? curentPage - 1 : (curentPage == 2)? 1 : curentPage ;
  let perPage    = 10;
  let skipPages  = modifuedPage * perPage;

  let userDb = await User_scm.findOne({
    email: userEmail
  }).catch(error => serverError(error, 'login the user'));

  if(!userDb || !userDb.bills)
    return res.status(401).send({calls: null});

  let total = Math.floor(userDb.calls.length/perPage);

  User_scm.aggregate([
      {'$match':{ email: userEmail }},
      {'$unwind':'$calls'},
      { "$group": { "_id": '$calls'} },
      {'$skip':skipPages},
      {'$limit':perPage},
      {$sort:{"calls.created":-1},}

    ], function(err, result){

      if(err){return(res.send(500, err))}

      return  res.status(200).json({
        calls : result,
        page  : req.query.page,
        totalPages: total,
        params    : getRequest
      });

    });
});

module.exports = router;
