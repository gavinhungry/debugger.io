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
  auth.isValidEmail = email => _.isString(email) ? validator.isEmail(email) : false;

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
   * Get an unauthenticated user from a login (username or email)
   *
   * @param {String} login
   * @return {Promise<Object>}
   */
  auth.getUnauthenticatedUser = login => {
    if (!auth.isValidLogin(login)) {
      return Promise.reject(new Error('invalid login'));
    }

    return auth.users.crud.find({
      [_.str.include(login, '@') ? 'email' : 'username']: login
    }).then(users => {
      if (!users || !users.length) {
        throw new Error('invalid login');
      }

      return _.first(users);
    });
  };

  /**
   * Check if any username or email already exists in the database
   *
   * @param {Array<String>} logins
   * @return {Promise<Boolean>} true if any login exists, false otherwise
   */
  auth.loginExists = logins => {
    let users = utils.ensure_array(logins).map(auth.getUnauthenticatedUser);
    return Promise.all(users).then(res => !!_.find(res));
  };

  /**
   * Get an authenticated user from a login and password
   *
   * @param {String} login
   * @param {String} password
   * @return {Promise<Object>}
   */
  auth.getAuthenticatedUser = (login, password) => {
    return auth.getUnauthenticatedUser(login).then(user => {
      if (!user) {
        throw new Error('invalid credentials');
      }

      return auth.verifyHash(password, user.hash).then(authenticated => {
        if (!authenticated) {
          throw new Error('invalid credentials');
        }

        return user;
      });
    });
  };

  /**
   * Create a new user with a plaintext password
   *
   * @param {String} username - requested username
   * @param {String} email - requested email address
   * @param {String} password - plaintext password
   * @param {String} confirm - plaintext password confirmation
   * @return {Promise<Object>}
   */
  auth.createUser = (username, email, password, confirm) => {
    username = _.str.clean(username);
    email = _.str.clean(email);

    if (!auth.isValidUsername(username)) {
      return Promise.reject(new Error('invalid username'));
    }

    if (!auth.isValidEmail(email)) {
      return Promise.reject(new Error('invalid email'));
    }

    if (password !== confirm) {
      return Promise.reject(new Error('passwords do not match'));
    }

    if (!auth.isValidPassword(password)) {
      throw new Error('invalid password');
    }

    return auth.loginExists([username, email]).then(exists => {
      if (exists) {
        throw new Error('username or email already exists');
      }

      return auth.scrypt(password).then(hash => {
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
