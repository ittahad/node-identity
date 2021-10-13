const mongoose = require("mongoose");

const Schema = mongoose.Schema;

var basePropsSchema = new Schema({
    idsAllowedToRead: {
        type: [String],
        default: ['admin']        
    },
    idsAllowedToUpdate: {
        type: [String],
        default: ['admin']        
    },
    idsAllowedToDelete: {
        type: [String],
        default: ['admin']        
    },
    rolesAllowedToRead: {
        type: [String],
        default: ['admin']        
    },
    rolesAllowedToUpdate: {
        type: [String],
        default: ['admin']        
    },
    rolesAllowedToDelete: {
        type: [String],
        default: ['admin']        
    }
});

module.exports = basePropsSchema;