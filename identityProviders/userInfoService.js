
var UserSchema = require('../models/user');
var bcrypt = require('bcrypt');
var responseWriter = require('../utility/res');
let auth = require('../authenticate');

class UserInfoService
{
    constructor() {}

    createUserInfo(data, req, res, mongoConnect)
    {
        let Users = mongoConnect.getCollection(req.tenantId, 'User', UserSchema);

        Users.findOne({username: data.email})
            .then(user => {
                if (user) {
                    
                    let token = auth.getAccessToken({
                        _id: user._id,
                        tenantId: req.tenantId,
                        email: user.email,
                        phone: user.phone,
                        roles: user.roles
                      });
                      return responseWriter.response(res, {
                        success: true,
                        accessToken: token.token,
                        expiresIn: auth.tokenExpirity,
                        refreshToken: token.refreshToken
                      }, null, 200);
                } else {
                    let user = new Users({
                        username: data.email,
                        displayName: data.name,
                        email: data.email,
                        phone: "+8801711111111",
                        address: "N/A",
                        active: false
                      });
                    
                    let externalUserPassword = "79c9b4b7-6b1c-4786-a66e-868795adfded";

                    bcrypt.genSalt(10, function (err, salt) {
                        bcrypt.hash(externalUserPassword, salt, function (err, hash) {
                        user.password = hash;
                        user.salt = salt;
                        user.save((err, user) => {
                                if (!user) {
                                    return responseWriter.response(res, null, {
                                    success: false,
                                    message: 'Registration failed!'
                                    }, 403);
                                }
                                
                                let token = auth.getAccessToken({
                                    _id: user._id,
                                    tenantId: req.tenantId,
                                    email: user.email,
                                    phone: user.phone,
                                    roles: user.roles
                                  });
                                  return responseWriter.response(res, {
                                    success: true,
                                    accessToken: token.token,
                                    expiresIn: auth.tokenExpirity,
                                    refreshToken: token.refreshToken
                                  }, null, 200);
                            });
                        });
                    });    
                }
            })
            .catch(err => {
                res.status(500).send({
                    message: err.message || 'Some error occurred while creating the User.'
                });
            });

                     
    }
}

module.exports = UserInfoService;