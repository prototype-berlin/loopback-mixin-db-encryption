const crypto = require('crypto');
const debug = require('debug')('loopback:mixins:encryption');

const DEFAULT_ITERATIONS = 10;
const REQUIRED_OPTIONS = ['salt', 'iv', 'password', 'fields'];

module.exports = function (Model, options = {}) {
  debug('Setting up encryption mixin for model %s', Model.modelName);

  Model.getApp((error, app) => {
    if (error) {
      debug(`Error getting app: ${error}`);
    }

    let globalOptions = app.get('encryption') || {};
    options.salt = options.salt || globalOptions.salt;
    options.iv = options.iv || globalOptions.iv;
    options.iterations = options.iterations || globalOptions.iterations || DEFAULT_ITERATIONS;
    options.password = options.password || globalOptions.password;
    options.fields = options.fields || globalOptions.fields;

    // make sure fields is an array
    options.fields = [].concat(options.fields);

    const missingOptions = [];

    REQUIRED_OPTIONS.forEach((requiredOption) => {
      if (!options[requiredOption]) {
        missingOptions.push(requiredOption);
      }
    });

    if (missingOptions.length) {
      const error = `These options are required but mssing: ${missingOptions.join(' ')}`;

      throw new Error(error);
    }
  });
  
  Model.observe('persist', async (context) => {
    encryptOrDecryptValues(context.data, options.fields);
  });

  Model.observe('loaded', async (context) => {
    encryptOrDecryptValues(context.data, options.fields, 'decrypt');
  });

  Model.observe('access', async (context) => {
    encryptOrDecryptValues(context.query, options.fields);
  });

  function encryptOrDecryptValues(object, keysToModify = [], action = 'encrypt') {
    Object.keys(object).forEach((key) => {
      if (isObject(object[key])) {
        encryptOrDecryptValues(object[key], keysToModify, action);

        return;
      }

      if (keysToModify.includes(key)) {
        object[key] = action === 'encrypt' ? encrypt(object[key]) : decrypt(object[key]);
      }
    });
  }

  function isObject(value) {
    return value === Object(value) && typeof value !== 'function';
  }

  function encrypt(stringToEncrypt) {
    try {
      const salt = options.salt;
      const iv = options.iv;
      const iterations = options.iterations;
      const password = options.password;

      const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha512');
      const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
      let encrypted = cipher.update(stringToEncrypt, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      return encrypted;
    } catch (error) {
      console.error('Encryption of string failed');
      console.error(error);

      return stringToEncrypt;
    }
  }

  function decrypt(stringToDecrypt) {
    try {
      const salt = options.salt;
      const iv = options.iv;
      const iterations = options.iterations;
      const password = options.password;

      const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha512');
      const cipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
      let decrypted = cipher.update(stringToDecrypt, 'hex', 'utf8');
      decrypted += cipher.final('utf8');

      return decrypted;
    } catch (error) {
      console.error('Decryption of string failed');
      console.error(error);
      
      return stringToDecrypt;
    }
  }
};
