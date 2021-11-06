const { Mongoose } = require('mongoose');

const mongoose = new Mongoose();
const Schema = mongoose.Schema;

const socialLoginConfigSchema = new Schema({

    clientId: {
        type: String,
        required: true,
    },
    clientSecret: {
        type: String,
        required: true,
    },
    provider: {
        type: String,
        unique: true,
        required: true
    },
    redirectUrl: {
        type: String,
        required: true
    }
});

module.exports = socialLoginConfigSchema;