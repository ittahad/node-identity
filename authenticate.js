const passport = require('passport');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const redis = require('redis');
const crypto = require('crypto');

const LocalStrategy = require('passport-local');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const responseWriter = require('./utility/res');
const mongoConnect = require('./dbConnect');
const AppSettings = require(`./config.${process.env.NODE_ENV}`);
const UserSchema = require('./models/user');
const SocialLoginConfigSchema = require('./models/socialloginconfig');

const GithubLogin = require('./identityProviders/githubLogin');
const UserInfoService = require('./identityProviders/userInfoService');
const SocialLoginProvider = require('./identityProviders/socialLoginProvider');

var tokenExpirationInSeconds = 3600;
var refreshTokenExpirationInSeconds = 86400;

var config = new AppSettings();
var redisClient = redis.createClient(config.redisHost);

redisClient.auth(config.redisPass);

exports.localPassport = passport.use(new LocalStrategy({ passReqToCallback:true }, function(req, username, password, done) {
    let User = mongoConnect.getCollection(req.tenantId, 'User', UserSchema);
    User.findOne({username: username})
    .then((user) => {
        if(user.active === true){
            bcrypt.hash(password, user.salt, function(err, hash) {
                if (err) return next(err);
                if(hash !== user.password) {
                    return done(null, false);
                }
                return done(null, user);
            });
        } else {
            return done(null, false);
        }
    });
}));

let options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: config.publicKey
};

exports.jwtPassport = passport.use(new JwtStrategy(options,
    (jwtPayload, done) => {
        let userId = mongoose.Types.ObjectId(jwtPayload._id);
        let Users = mongoConnect.getCollection(jwtPayload.tenantId, 'User', UserSchema);
        Users.findOne({
            _id: userId
        }, (err, user) => {
            if (err) {
                return done(err, false);
            } else if (user) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        });
    }));

exports.getAccessToken = (user) => {
    let key = generateId();
    redisClient.setex(user.tenantId + "_" + key, refreshTokenExpirationInSeconds, JSON.stringify(user));

    let token = jwt.sign(user, config.secretKey, {
        expiresIn: tokenExpirationInSeconds,
        algorithm: 'RS256'
    });

    return {
        token: token,
        refreshToken: key
    };
};

exports.tokenExpirity = tokenExpirationInSeconds;

exports.verifyUser = passport.authenticate('jwt', {
    session: false
});

exports.verifyAdmin = (req, res, next) => {
    var userId = req.user._id;
    if (userId !== null) {
        let Users = mongoConnect.getCollection(req.tenantId, 'User', UserSchema);
        Users.findOne({
                _id: userId
            })
            .then(user => {
                if (user !== null && user.active === true) {
                    let found = user.roles.find(item => item === 'admin');
                    if (found) {
                        next();
                    } else {
                        return responseWriter.response(res, null, {
                            success: false,
                            message: "Admin verification failed!"
                        }, 403);
                    }
                } else {
                    return responseWriter.response(res, null, {
                        success: false,
                        message: "Admin verification failed!"
                    }, 403);
                }
            })
            .catch((err) => next(err));
    }
};

exports.verifyToken = (req, res, next) => {
    let token = this.extractJwtToken(req.headers.authorization);
    if(token === null) {
        responseWriter.response(res, null, {success: false, "response" : "Invalid authentication token"}, 403);
        return new Error("Invalid authentication token");
    }
    let payload = this.getJwtTokenPayload(token);
    req.tenantId = payload.tenantId;
    req.userId = payload._id;
    next();
};

exports.getJwtTokenPayload = (token) => {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const buff = new Buffer.from(base64, 'base64');
    const payloadinit = buff.toString('ascii');
    const payload = JSON.parse(payloadinit);
    return payload;
};

exports.extractJwtToken = (authHeader) => {
    if (authHeader.startsWith("Bearer ") || authHeader.startsWith("bearer ")){
        return authHeader.substring(7, authHeader.length);
    } else {
        return null
    }
}

exports.grantTypeValidator = async (req, res, next) => {
    if(req.body === null || req.body.grant_type === null) {
        let err = new Error("Invalid grant_type parameter");
        responseWriter.response(res, null, {success: false, message: 'Invalid grant_type parameter'}, 403);
        next(err);
    }

    if(req.body.grant_type === 'access_token') {
        next();
    }
    else if(req.body.grant_type === 'refresh_token') {
        let key = req.body.refreshToken;
        redisClient.get(req.tenantId + "_" + key, (err, value) => {
            if (err !== null || value === null) {
                return responseWriter.response(res, null, {
                    success: false,
                    message: 'Invalid refresh token'
                }, 403);
            }
            let user = JSON.parse(value);
            let refreshToken = jwt.sign(user, config.secretKey, {
                expiresIn: tokenExpirationInSeconds,
                algorithm: 'RS256'
            });
            return responseWriter.response(res, {
                success: true,
                accessToken: refreshToken,
                expiresIn: tokenExpirationInSeconds
              }, null, 200);
        });
    }
    else if(req.body.grant_type === 'social_login') {
        
        let collection = mongoConnect.getCollection(req.tenantId, 'SocialLoginConfig', SocialLoginConfigSchema)

        collection.findOne({
            provider: req.body.provider
        }).then(
            async (socialLoginConfig) => {
                if(socialLoginConfig === null) {
                    return responseWriter.response(res, null, {
                        success: false,
                        message: 'Invalid social login provider'
                    }, 403);
                }
                

                var provider = new SocialLoginProvider();

                provider.prepareProvider(req.body.provider, socialLoginConfig);
                var data = await provider.handle(req, res);

                var loginHandler = new UserInfoService();
                loginHandler.createUserInfo(data, req, res, mongoConnect);
            }
        ).catch(
            (err) => {
                return responseWriter.response(res, null, {
                    success: false,
                    message: 'Invalid social login provider'
                }, 403);
            }
        );
    }
    else {
        return responseWriter.response(res, null, {success: false, message: 'Invalid grant_type parameter'}, 403);
    }
};

exports.generateRandomId = generateId = () => {
    const id = crypto.randomBytes(16).toString("hex");
    return id;
}


