const { Mongoose } = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const baseProps = require('./base');
const mongoose = new Mongoose();
const Schema = mongoose.Schema;

const userSchema = new Schema({

    displayName: {
        type: String,
        required: true,
    },
    roles: {
        type: [String],
        default: ['appuser']
    },
    email: {
        type: String,
        unique: true,
        required: true
    },
    phone: {
        type: String,
        required: true
    },
    address: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    salt: {
        type: String
    },
    username: {
        type: String,
        required: true
    },
    active: {
        type: Boolean,
        required: true,
        default: false
    }
}, {timestamps: true});

userSchema.add(baseProps);

module.exports = userSchema;