const mongoose= require('mongoose');

const atlas   = process.env.MONGO_ATLAS_STR;


mongoose.connect( atlas, {useNewUrlParser: true, useUnifiedTopology: true}).catch(error => console.log(error));
var db = mongoose.connection;

module.exports = db;