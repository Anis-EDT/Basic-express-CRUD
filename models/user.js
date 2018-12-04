let mongoose = require('mongoose');
let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');
let role=['ADMIN','DELEGATE'];
let userSchema = new mongoose.Schema({
    firstname:{type:String, required: true, minlength: 1, unique:false },
    lastname:{type:String, required: true, minlength: 1, unique:false },
    email:{type:String, required: true, minlength: 1, unique:true },
    password:{type: String, required: true, minlength: 6},
    role:{type: String,enum:role,required: true},
    picture:{type:String },
    birthdate:{type:Date },
    cin:{type:String },
    salary:{type:Number},
    amortization:{type:Number },
    sector:{type:String },
    phone:{type:Number },
    notifID:[{type: String, required: false}],
    cycleon: {type: Boolean, default: false},
    position:{
        lat:{
            type:Number,
            required:false
        },
        lng:{
            type:Number,
            required:false
        }
    },
    tokens:[{
         access:{
              type:String,
             required: true
         },
         token:{
             type:String,
             required: true
         }
    }]
});

userSchema.methods.toJSON = function () {
    let user = this;
    return user.toObject();
};

userSchema.methods.generateAuthToken = function () {
   let user = this;
   let access = 'auth';
   let token = jwt.sign({_id: user._id.toHexString(),access},'sec1993').toString();
   user.tokens.push({access, token});
   return user.save().then(function () {
       return token;
   });
};

userSchema.methods.removeToken = function (token) {
    let user = this;

    return user.update({
        $pull: {
            tokens: {token}
        }
    });
};

userSchema.statics.findByToken = function (token) {
    let User = this;
    let decoded;

    try {
        decoded = jwt.verify(token, 'sec1993');
    } catch (e) {
        return Promise.reject();
    }

    return User.findOne({
        '_id': decoded._id,
        'tokens.token': token,
        'tokens.access': 'auth'
    });
};

userSchema.statics.findByCredentials = function (email, password) {
    let User = this;
    return User.findOne({'email':email,'password':password}).then((user) => {
        if (!user) {
            return Promise.reject();
        }

        return new Promise((resolve, reject) => {
            // Use bcrypt.compare to compare password and user.password
            bcrypt.compare(password, User.password, (res) => {
                if (res) {
                    resolve(user);
                } else {
                    reject();
                }
            });
        });
    });
};
userSchema.statics.findAdmins = function (date) {
  var user = this;
  return user.find({role: "ADMIN"}).then((users) => {
    if (!users) {
      return Promise.reject();
    }
    return Promise.resolve(users);
  });
};

module.exports= mongoose.model('User',userSchema);