const {
    Mongoose
} = require('mongoose');

const AppSettings = require(`./config.${process.env.NODE_ENV}`);

const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;

var config = new AppSettings();

exports.dataConnectionPool = dataConnectionPool = {};

passport.use(new JwtStrategy({
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: config.secretKey
    },
    (jwtPayload, done) => {
        let userId = mongoose.Types.ObjectId(jwtPayload._id);
        let Users = mongoConnect.dataConnectionPool[jwtPayload.tenantId].model('User', UserSchema);
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

exports.dbContextAccessor = (req, res, next) => {

    const url = config.mongoDb(req.tenantId);

    if (!dataConnectionPool || !dataConnectionPool[req.tenantId]) {
        var dataConnectionMongoose = new Mongoose();
        dataConnectionMongoose.connect(url)
            .then(db => {
                dataConnectionPool[req.tenantId] = dataConnectionMongoose;
                return next();
            })
            .catch((err) => {
                next(err);
            });
    } else {
        return next();
    }
};

exports.verifyUser = passport.authenticate('jwt', {
    session: false
});

exports.verifyToken = (req, res, next) => {
    let token = this.extractJwtToken(req.headers.authorization);
    if (token === null) {
        responseWriter.response(res, null, {
            success: false,
            "response": "Invalid authentication token"
        }, 403);
        return next();
    }
    let payload = this.getJwtTokenPayload(token);
    req.tenantId = payload.tenantId;
    next();
};