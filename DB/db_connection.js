const mongoose= require('mongoose');

const atlas   = "mongodb+srv://server:qqqqqqq321~@cluster0-ffo6u.mongodb.net/simpleApp?retryWrites=true&w=majority";


mongoose.connect( atlas, {useNewUrlParser: true, useUnifiedTopology: true}).catch(error => console.log(error));
var db = mongoose.connection;

module.exports = db;