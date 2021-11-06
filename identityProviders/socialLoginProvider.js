
const responseWriter = require('../utility/res');
const GithubLogin = require('./githubLogin');
const GoogleLogin = require('./googleLogin');

class SocialLoginProvider {

    constructor() { }

    prepareProvider(providerName, providerData){
        if(providerName === "github") {
            this.clientLogin = new GithubLogin(providerData.clientId, providerData.clientSecret, providerData.redirectUrl);
        }else if(providerName === "google") {
            this.clientLogin = new GoogleLogin(providerData.clientId, providerData.clientSecret, providerData.redirectUrl);
        }
    }
    
    async handle(req, res) {
        var accessTokenResponse = await this.clientLogin.getAccessToken(req.body.code);
        if (accessTokenResponse.data.access_token === null ||
            typeof (accessTokenResponse.data.access_token) === "undefined") {
            return responseWriter.response(res, {
                success: false,
                data: accessTokenResponse.data
            }, null, 400);
        }

        var userInfoResponse = await this.clientLogin.getUser(accessTokenResponse.data.access_token);
        return userInfoResponse.data;
    }
}

module.exports = SocialLoginProvider;