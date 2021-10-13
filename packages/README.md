# Identity Library for App Cloud Platform

This is the library to use security and identity service within the ACP platform.


## Installation

Initialize the Security Context

```javascript
const AppSettings = require(`Your AppSettings File Location`);
const config = new AppSettings();

var SecurityContext = require('libidentity');
const securityContext = new SecurityContext(config);

// Available middlewares sequence
🡣 securityContext.verifyToken
 🡣 securityContext.dbContextAccessor
  🡣 securityContext.verifyUser
   🡣 securityContext.verifyAdmin
```


## Usage
```javascript
// Configuration file

const fs = require('fs');
function AppSettings() {

    const PUB_KEY = fs.readFileSync(__dirname + '/public-key.pem', 'utf8');

    this.secretKey = PUB_KEY;

    this.mongoTenants = '***';
    this.redisHost = "***";
    this.redisPass = "***",
    this.rabbitMqConnection = "***";
    this.mongoDb = (dbName) => {
        return `mongodb://host:port/${dbName}`;
    }
};
module.exports = AppSettings;
```


```javascript
// Express router
router.all('*', securityContext.verifyToken, securityContext.dbContextAccessor, securityContext.verifyUser)
  .post('/action', function(req, res, next) {
    // req object is propagated through all the middlewares above to ensure security
    // Some action goes here
  })
});
```


```javascript
// ACP has support for socket.io also
// Middleware for socket.io connection

securityContext.verifySocketToken

const io = socketio(server);
io.on('connection', (socket) => {
  securityContext.verifySocketToken(socket, (sc) => { ... });
});
```

## License
[MIT](https://choosealicense.com/licenses/mit/)