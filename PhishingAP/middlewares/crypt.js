const Model = require("../models/index");
const Response = require('../lib/Response');
const statusCodes = require("../lib/statusCodes");

const SECRET = 'amazing';
const SECRET_LENGTH = SECRET.length;

const operate = (input) => {
  let result = "";
  for (let i in input) {
    result += String.fromCharCode(input.charCodeAt(i)^SECRET.charCodeAt(i%SECRET_LENGTH));
  }
  return result;
}

const decrypt = (encodedInput) => {  
  let input = Buffer.from(encodedInput, 'base64').toString();
  let dec = operate(input);
  return dec;
}

const encrypt = (input) => {
  let enc = operate(input.toString());
  let b64 = Buffer.from(enc).toString('base64');
  return b64;
}

/**
 * Encryption middleware
 * This middleware encrypts server response before forwarding to client
 * @return                           - Calls the next function on success
 */
const encryptResponse = (input) => {
  let b64 = encrypt(input);
  return {
    "enc_data": b64
  };
}

/**
 * Decryption middleware
 * This middleware decrypts user data after authorization check
 * @return                           - Calls the next function on success
 */
const decryptRequest = function(req, res, next) {
  var r = new Response();
  try {
    req.body = JSON.parse(decrypt(req.body.enc_data));
	  console.error(req.body);
    next();
  } catch(err) {
	  console.error(err);
    r.status = statusCodes.BAD_INPUT;
    r.data = err;
    return res.json(r);
  }
};

const decryptEnc = (enc_data) => {
  let input = Buffer.from(enc_data, 'base64').toString();
  let dec = operate(input);
  const index = dec.indexOf("accessToken")

  return dec.substring(index+14,dec.length-3);
}

module.exports =  {
    encryptResponse,
    decryptRequest,
    decryptEnc
}
