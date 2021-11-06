const axios = require('axios');

class GoogleLogin
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
            const url = 'https://accounts.google.com/o/oauth2/token';
           
            const data = {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                code: code,
                redirect_uri: this.redirectUri,
                grant_type: "authorization_code"
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
            let url = 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=';
            url += bearerToken;

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