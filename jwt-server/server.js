//=============== Set Up
var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');
var app = express();
var router = express.Router();
var cors  = require('cors');

//=============== Set Up Local
var config = require('./app/config');
var User = require('./app/models/user');
var port = 2000;

app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());

mongoose.connect(config.database, {
  useMongoClient: true
});
app.set('secretKey', config.secret);
app.use(cors());

//============== Router API
router.post('/login', function(req, res){
  User.findOne({
    email: req.body.email
  }, function(err, user){
    if(err) throw err;

    if(!user){
      res.json({ succes: false, message: 'User tidak ada di database' });
    }else {
      //harusnya passwordnya hash
      if (user.password != req.body.password) {
        res.json({ succes: false, message: 'password user salah!' });
      }else {
        //membuat token
        var token = jwt.sign(user, app.get('secretKey'), {
          expiresIn: "2 days"
        });

        //ngirim balik token
        res.json({
          succes : true,
          message: 'token berhasil didapatkan!',
          token  : token
        })
      }
    }
  });
});

router.get('/', function(req, res){
  res.send('ini di route home!');
});

//proteksi route dengan token
router.use(function(req, res, next){
  //mengambil token: req.body.token || req.query.token ||
  var token = req.headers['authorization'];

  //decode token
  if(token){

    jwt.verify(token, app.get('secretKey'), function(err, decoded){
      if(err)
        return res.json({ success: false, message: 'problem dengan token' });
      else {
        req.decoded = decoded;

        //apakah sudah expire
        if(decoded.exp <= Date.now()/1000) {
          return res.status(400).send({
            success:false,
            message:'token sudah expire',
            date   : Date.now()/1000,
            exp    : decoded.exp
          });
        }

        next();
      }
    });

  }else{
    return res.status(403).send({
      success:false,
      message:'token tidak tersedia'
    });
  }

});

router.get('/users', function(req, res){
  User.find({}, function(err, users){
    res.json(users);
  });
});

router.get('/profile', function(req, res){
  res.json(req.decoded._doc);
});


//prefix /api
app.use('/api', router);

app.listen(2000);
