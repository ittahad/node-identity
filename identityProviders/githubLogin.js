const axios = require('axios');

class GithubLogin
{
    constructor(clientId, clientSecret, redirectUrl) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUrl;
    }

    async getAccessToken(code)
    {
        let axiosConfig = {
            headers: {
                'Accept': 'application/json'
            }
          };

        return new Promise((resolve, reject) => {
            const url = 'https://github.com/login/oauth/access_token';
           
            const data = {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                code: code,
                redirect_uri: this.redirectUri
            };

            axios.post(url, data, axiosConfig)
              .then(function (response) {
                resolve(response);
              })
              .catch(function (error) {
                reject(error);
              });  
        });
    }

    async getUser(bearerToken)
    {
        return new Promise((resolve, reject) => {
            const url = 'https://api.github.com/user';
            
            axios.get(url, {
                headers: {
                    'Accept': 'application/json',
                    'Authorization': 'Bearer ' + bearerToken
                }})
              .then(function (response) {
                resolve(response);
              })
              .catch(function (error) {
                reject(error);
              });  
        });

    }
}

module.exports = GithubLogin;