var express = require('express');
var router = express.Router();
var passport = require('passport');
var bcrypt = require('bcrypt');

var auth = require('../authenticate');
var responseWriter = require('../utility/res');
var mongoConnect = require('../dbConnect');

var UserSchema = require('../models/user');

/**
 * A simple ping url to know the status of the service.
 * @route GET /users/ping
 * @group Ping - service status endpoint
 * @returns {string} 200 - /users ping successful
 */
router.get('/ping',
  (req, res, next) => {
    res.send('/users ping successful');
  })

/**
 * A valid authorization token is mandatory for this endpoint
 * @route GET /users
 * @group Auth - users endpoints
 * @returns {object} 200 - An array of user info
 * @returns {Error}  default - Unexpected error
 * @security JWT
 */
router.get('/', auth.verifyToken, mongoConnect.dbContextAccessor,
  auth.verifyUser, auth.verifyAdmin,
  (req, res, next) => {
    let Users = mongoConnect.getCollection(req.tenantId, 'User', UserSchema);
    Users.find({}, {displayName : 1, email : 1, phone : 1, active: 1})
      .sort({displayName : 1})
      .exec((err, users) => {
        return responseWriter.response(res, null, {
          success: true,
          response: users
        }, 200);
      })
      .catch(err => next(err));
  })
 .post('/setActive', auth.verifyToken, mongoConnect.dbContextAccessor,
  auth.verifyUser, auth.verifyAdmin,
  (req, res, next) => {
    let Users = mongoConnect.getCollection(req.tenantId, 'User', UserSchema);
    Users.findOne({_id: req.body.userId})
      .then(user => {

        if(user === null || typeof(user) === 'undefined')
        {
          return responseWriter.response(res, null, {
            success: false,
          }, 400);
        }

        if(user.roles.includes('admin'))
        {
          return responseWriter.response(res, null, {
            success: false,
            messgae: "Can't change status of admin"
          }, 400);
        }

        user.active = req.body.active;

        user.save()
          .then(saved =>  {
            return responseWriter.response(res, null, {
              success: true,
            }, 200);
          })
          .catch(err => {
            return responseWriter.response(res, null, {
              success: false,
            }, 400);
          });
       
      })
      .catch(err => next(err));
  })

router.all('*', mongoConnect.dbContextInitializer, mongoConnect.dbContextAccessor)
/**
 * A valid authorization token is mandatory for this endpoint
 * @route POST /users/register
 * @group Auth - register an user
 * @param {User.model} user.body.required
 * @returns {object} 200 - A response indication object
 * @returns {Error}  default - Unexpected error
 */
  .post('/register',
    (req, res, next) => {
      let currentUser = req.body;
      if (currentUser === null) {
        responseWriter.response(res, null, {
          success: false,
          message: "User does not exist!"
        }, 404);
        return next();
      }
       
      let Users = mongoConnect.getCollection(req.tenantId, 'User', UserSchema);

      let user = new Users({
        username: req.body.username,
        displayName: req.body.displayName,
        email: req.body.email,
        phone: req.body.phone,
        address: req.body.address,
        active: false
      });

      bcrypt.genSalt(10, function (err, salt) {
        bcrypt.hash(req.body.password, salt, function (err, hash) {
          user.password = hash;
          user.salt = salt;
          user.save((err, user) => {
              if (!user) {
                responseWriter.response(res, null, {
                  success: false,
                  message: 'Registration failed!'
                }, 403);
                return next();
              }
              
              responseWriter.response(res, {
                success: true,
                message: 'Registration successful!'
              }, null, 200);
            });
        });
      });
    })
/**
 * A valid authorization token is mandatory for this endpoint
 * @route POST /users/token
 * @group Auth - generate token
 * @param {TokenParams.model} tokenParams.body.required
 * @returns {object} 200 - A response contains access_token and refresh_token
 * @returns {Error}  default - Unexpected error
 */
  .post('/token', auth.grantTypeValidator,
    (req, res, next) => {
      passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user || req.tenantId === null) {
          responseWriter.response(res, null, {
            success: false, message: "Invalid username or password / Account not active"
          }, 403);

          return next();
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
      })(req, res, next);
    });


/**
 * @typedef User
 * @property {string} email.query.required - username or email - eg: user@domain.com
 * @property {string} username.query.required - user's username.
 * @property {string} password.query.required - user's password.
 * @property {string} address.query.required - address - eg: House 1, Road 3.
 * @property {string} phone.query.required - user's phone number.
 * @property {string} displayName.query.required - users display name.
 */

/**
 * @typedef TokenParams
 * @property {string} username.query.required - user's username.
 * @property {string} password.query.required - user's password.
 * @property {string} grant_type.query.required - grant_type - eg: access_token / refresh_token.
 */


module.exports = router;
