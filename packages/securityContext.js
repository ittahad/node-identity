const { Mongoose } = require('mongoose');
const mongoose = new Mongoose();
const passport = require('passport');
const jwt = require("jsonwebtoken");
const responseWriter = require('./res');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const UserSchema = require('./user');

class SecurityContext
{
    constructor(config)
    {
        this.config = config;
        this.dataConnectionPool = {};

        passport.use(new JwtStrategy({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.secretKey
        }, (jwtPayload, done) => {
            let userId = mongoose.Types.ObjectId(jwtPayload._id);
            let Users = this.dataConnectionPool[jwtPayload.tenantId].model('User', UserSchema);
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
    }

    dbContextAccessor = (req, res, next) => {
        const url = this.config.mongoDb(req.tenantId);
        if (!this.dataConnectionPool || !this.dataConnectionPool[req.tenantId]) {
            var dataConnectionMongoose = new Mongoose();
            dataConnectionMongoose.connect(url)
                .then(db => {
                    this.dataConnectionPool[req.tenantId] = dataConnectionMongoose;
                    return next();
                })
                .catch((err) => {
                    next(err);
                });
        } else {
            return next();
        }
    };

    dbNormalContextAccessor = (req, res, dbName, callback) => {
        let url = this.config.mongoDb(dbName);

        let othersDataConnectionMongoose = new Mongoose();
        othersDataConnectionMongoose.connect(url)
            .then(db => {
                callback(req, res, othersDataConnectionMongoose);
            })
            .catch((err) => {
                console.log(err);
                callback(req, res, null);
            });
    };

    dbContextAccessorForHandler = (tenantId, callback) => {
        const url = this.config.mongoDb(tenantId);
        if (!this.dataConnectionPool || !this.dataConnectionPool[tenantId]) {
            var dataConnectionMongoose = new Mongoose();
            dataConnectionMongoose.connect(url)
                .then(db => {
                    this.dataConnectionPool[tenantId] = dataConnectionMongoose;
                    return callback(this, null);
                })
                .catch((err) => {
                    return callback(null, err);
                });
        } else {
            return callback(this, null);
        }
    };

    dbContextAccessorForRabbitMq = (response, callback) => {
        const url = this.config.mongoDb(response.authInfo.tenantId);
        if (!this.dataConnectionPool || !this.dataConnectionPool[response.authInfo.tenantId]) {
            var dataConnectionMongoose = new Mongoose();
            dataConnectionMongoose.connect(url)
                .then(db => {
                    this.dataConnectionPool[response.authInfo.tenantId] = dataConnectionMongoose;
                    return callback(this, null);
                })
                .catch((err) => {
                    return callback(null, err);
                });
        } else {
            return callback(this, null);
        }
    };
    
    dbContextAccessorWithoutContext = (req, res, next) => {
        if(req.query.tenantId === null || req.query.tenantId !== "1AF2380E-B634-49E9-BA1C-9773E6C20D4C")
        {
            var error = new Error("Unauhorized");
            error.staus = 401;
            return next(error);
        }
        const url = this.config.mongoDb(req.query.tenantId);
        if (!this.dataConnectionPool || !this.dataConnectionPool[req.query.tenantId]) {
            var dataConnectionMongoose = new Mongoose();
            dataConnectionMongoose.connect(url)
                .then(db => {
                    this.dataConnectionPool[req.query.tenantId] = dataConnectionMongoose;
                    return next();
                })
                .catch((err) => {
                    next(err);
                });
        } else {
            return next();
        }
    };

    extractJwtToken = (authHeader) => {
        try{
            if (authHeader.startsWith("Bearer ") || authHeader.startsWith("bearer ")){
                return authHeader.substring(7, authHeader.length);
            } else {
                return null
            }
        }
        catch(ex){
            console.log(ex);
            return null;
        }
    }
    
    getJwtTokenPayload = (token) => {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const buff = new Buffer.from(base64, 'base64');
        const payloadinit = buff.toString('ascii');
        const payload = JSON.parse(payloadinit);
        return payload;
    };
    
    verifyToken = (req, res, next) => {
        let token = this.extractJwtToken(req.headers.authorization);
        if (token === null) {
            return responseWriter.response(res, null, {
                success: false,
                "response": "Invalid authentication token"
            }, 403);
        }
        try{
            var payload = jwt.verify(token, this.config.secretKey, { algorithms: ['RS256'] });
            req.tenantId = payload.tenantId;
            req.userId = payload._id;
        } catch(ex) {
            return responseWriter.response(res, null, {
                success: false,
                "response": ex.message
            }, 401);
        }
        next();
    };

    verifyAmqpToken = (receivedMessage, callback) => {
        let token = this.extractJwtToken(receivedMessage.token);
        if (token === null) {
            return responseWriter.response(res, null, {
                success: false,
                "response": "Invalid authentication token"
            }, 403);
        }
        try{
            var payload = jwt.verify(token, this.config.secretKey, { algorithms: ['RS256'] });
            receivedMessage.tenantId = payload.tenantId;
            receivedMessage.userId = payload._id;
        } catch(ex) {
            return responseWriter.response(res, null, {
                success: false,
                "response": ex.message
            }, 401);
        }
        callback(receivedMessage);
    };
    
    verifyAdmin = (req, res, next) => {
        var user = req.user;
        if(user && user.roles.findIndex(role => role === 'admin') !== -1)
            next();
        else{
            return responseWriter.response(res, null, {
                success: false,
                "response": "Admin previledge is required. Access denied"
            }, 403);
        }
    };
    
    verifySocketToken = (socket, callback) => {
        let token = socket.request.headers.bearertoken;
        if (token === null || typeof(token) === 'undefined') {
            return new Error("Unauthorized (token not valid)");
        }
        try{
            var payload = jwt.verify(token, this.config.secretKey, { algorithms: ['RS256'] });
            socket.request.tenantId = payload.tenantId;
            socket.request.userId = payload._id;
            callback(socket);
        } catch(ex) {
            return new Error("Unauthorized (token not valid)");
        }
    };
    
    verifyUser = passport.authenticate('jwt', {
        session: false
    });

    getTenantDataContext = (tenantId) => {
        let connection = this.dataConnectionPool[tenantId];
        return connection;
    };
    
    getCollection = (tenantId, collectionName, collectionSchema) => {
        let connection = this.dataConnectionPool[tenantId];
        return connection.model(collectionName, collectionSchema);
    };
    
    
    ignoreIdsAndRoles = {
        idsAllowedToRead : 0,
        idsAllowedToUpdate : 0, 
        idsAllowedToDelete : 0,
        rolesAllowedToRead : 0,
        rolesAllowedToUpdate : 0,
        rolesAllowedToDelete : 0,
    };
}

module.exports = SecurityContext;