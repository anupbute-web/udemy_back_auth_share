const jwt = require('jsonwebtoken');
const {promisify} = require('util');

let jwtSign = promisify(jwt.sign);
let jwtVerify = promisify(jwt.verify);
let jwtDecode = promisify(jwt.decode);

