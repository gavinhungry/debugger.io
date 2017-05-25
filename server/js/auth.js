/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const _ = require('underscore');
  const config = require('config');
  const utils = require('utils');

  const crypto = require('crypto');
  const rethinkdb = require('rethinkdbdash')(config.db);
  const Rudiment = require('rudiment');
  const schema = require('js-schema');
  const scrypt = require('scrypt');
  const validator = require('validator');

  let auth = {};

  let settingsSchema = {
    cdn: ['jsdelivr', 'cdnjs', 'google'],
    layout: ['layout-cols', 'layout-top', 'layout-left'],
    locale: ['en_US'],
    theme: ['dark']
  };

  auth.users = {
    defaultSettings: _.mapObject(settingsSchema, _.first)
  };

  auth.users.crud = new Rudiment({
    db: rethinkdb.table('users'),

    schema: schema({
      username: String,
      email: String,
      settings: settingsSchema,
      hash: String
    }),

    key: 'username',

    in: user => {
      user.settings = _.defaults(user.settings || {}, auth.users.defaultSettings);
      // FIXME: check user._, valid password, valid email, valid username
    },

    out: user => {
      user._ = {};
    }
  });

  let params_p = scrypt.params(config.auth.maxtime);

  /**
   * Generate an SHA-512 hash from a plaintext string
   *
   * @param {String} plaintext - plaintext string to hash
   * @return {String}
   */
  auth.sha512 = plaintext => crypto.createHash('sha512').update(plaintext).digest('hex');

  /**
   * Generate an scrypt salted hash from a plaintext string
   *
   * @param {String} plaintext - plaintext string to hash
   * @return {Promise<String>}
   */
  auth.scrypt = (plaintext = '') => {
    return params_p.then(params => {
      return scrypt.kdf(plaintext, params).then(buf => buf.toString('base64'));
    });
  };

  /**
   * Verify a plaintext string against an scrypt salted hash
   *
   * @param {String} plaintext
   * @param {String} hash - scrypt hash to compare to `plaintext`
   * @return {Promise<Boolean>}
   */
  auth.verifyHash = (plaintext = '', hash = '') => {
    let kdf = new Buffer(hash, 'base64');
    return scrypt.verifyKdf(kdf, plaintext);
  };

  /**
   * Clean up a potential username string
   *
   * @param {String} username
   * @return {String}
   */
  auth.cleanUsername = username =>
    utils.ensure_string(username).toLowerCase().replace(/[^a-z0-9_]/ig, '');

  /**
   * Test for a valid username
   *
   * @param {String} username
   * @return {Boolean}
   */
  auth.isValidUsername = username =>
    auth.cleanUsername(username) === username &&
    username.length >= 3 &&
    username.length <= 64;

  /**
   * Test for a valid email address
   *
   * @param {String} email
   * @return {Boolean}
   */
  auth.isValidEmail = email => validator.isEmail(email);

  /**
   * Test for a valid login (username or email address)
   *
   * @param {String} login
   * @return {Boolean}
   */
  auth.isValidLogin = login => auth.isValidUsername(login) || auth.isValidEmail(login);

  /**
   * Test for a valid password
   *
   * The only requirements for a valid password are that it must contain at
   * least one non-whitespace character, be at least 4 characters and at most
   * 512 characters.  Users are otherwise free to shoot themselves in the foot.
   *
   * @param {String} plaintext
   * @return {Boolean}
   */
  auth.isValidPassword = plaintext => _.isString(plaintext) && /^(?=.*\S).{4,512}$/.test(plaintext);

  /**
   * Get a user from a login (username or email)
   *
   * @param {String} login
   * @return {Promise<Object|null>}
   */
  auth.getUserByLogin = login => {
    if (!auth.isValidLogin(login)) {
      return Promise.reject(new Error('invalid login'));
    }

    return auth.users.crud.find({
      [_.str.include(login, '@') ? 'email' : 'username']: login
    }).then(users => users[0] || null);
  };

  /**
   * Check if any username or email already exists in the database
   *
   * @param {Array<String>} logins
   * @return {Promise<Boolean>} true if any login exists, false otherwise
   */
  auth.loginExists = logins => {
    let users = utils.ensure_array(logins).map(auth.getUserByLogin);
    return Promise.all(users).then(res => !!_.find(res));
  };

  /**
   * Create a new user with a plaintext password
   *
   * @param {Object} user
   * @param {String} user.username - requested username
   * @param {String} user.email - requested email address
   * @param {String} user.password - plaintext password
   * @param {String} user.confirm - plaintext password confirmation
   * @return {Promise} resolves to new user record on success
   */
  auth.createUser = (user = {}) => {
    let username = _.str.clean(user.username);
    let email = _.str.clean(user.email);

    if (!auth.isValidUsername(username)) {
      return Promise.reject(new Error('invalid username'));
    }

    if (!auth.isValidEmail(email)) {
      return Promise.reject(new Error('invalid email'));
    }

    if (user.password !== user.confirm) {
      return Promise.reject(new Error('passwords do not match'));
    }

    if (!auth.isValidPassword(user.password)) {
      throw new Error('invalid password');
    }

    return auth.loginExists([username, email]).then(exists => {
      if (exists) {
        throw new Error('username or email already exists');
      }

      return auth.scrypt(user.password).then(hash => {
        return auth.users.crud.create({
          username: username,
          email: email,
          hash: hash
        });
      });
    });
  };

  return auth;
});
