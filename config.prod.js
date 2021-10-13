
const fs = require('fs');
function AppSettings() {

    const PRIV_KEY = fs.readFileSync(__dirname + '/private-key.pem', 'utf8');
    const PUB_KEY = fs.readFileSync(__dirname + '/public-key.pem', 'utf8');

    this.secretKey = PRIV_KEY;
    this.publicKey = PUB_KEY;

    this.mongoTenants = 'mongodb://localhost:27017/Tenants';
    this.redisHost = "redis://{{YOUR_CONNECTION_STRING}}";
    this.redisPass = "{{YOUR_CONNECTION_SECRET}}",
    this.mongoDb = (dbName) => {
        return `mongodb://localhost:27017/${dbName}`;
    }
};

module.exports = AppSettings;
