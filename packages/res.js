
exports.response = (res, obj, err, statusCode) => {
    
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');

    if(err === null) {
        obj.statusCode = statusCode;
        res.json(obj);
    }
    else {
        err.statusCode = statusCode;
        res.json(err);
        
    }
};