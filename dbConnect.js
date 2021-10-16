const {
    Mongoose
} = require('mongoose');

var responseWriter = require('./utility/res');

const AppSettings = require(`./config.${process.env.NODE_ENV}`);
var TenantSchema = require('./models/tenant');

var config = new AppSettings();

exports.dataConnectionPool = dataConnectionPool = {};

exports.getTenantDataContext = (tenantId) => {
    let connection = this.dataConnectionPool[tenantId];
    return connection;
};

exports.getCollection = (tenantId, collectionName, collectionSchema) => {
    let connection = this.dataConnectionPool[tenantId];
    return connection.model(collectionName, collectionSchema);
};

exports.tenantDbConnection = tenantDbConnection = function () {
    let tenantConnectionMongoose = new Mongoose();
    tenantConnectionMongoose.connect(config.mongoTenants);
    return tenantConnectionMongoose;
};

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
    }
    else {
        return next();
    }
};

exports.dbContextInitializer = (req, res, next) => {

    let origin = req.headers.origin;

    if (!origin) {
        return responseWriter.response(res, null, {
            "response": "Invalid database request"
        }, 403);
    }

    let Tenants = tenantDbConnection().model('Tenant', TenantSchema);

    Tenants.findOne({
            origin: origin
        })
        .then((tenant) => {
            req.tenantId = tenant.tenantId;
            return next();
        })
        .catch(err => next(err));
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