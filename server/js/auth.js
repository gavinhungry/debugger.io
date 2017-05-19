/*
 * sandbug: An interactive web scripting sandbox
 */

define(function(require) {
  'use strict';

  var _      = require('underscore');
  var config = require('config');
  var utils  = require('utils');

  var crypto        = require('crypto');
  var rethinkdb     = require('rethinkdbdash')(config.db);
  var Rudiment      = require('rudiment');
  var schema        = require('js-schema');
  var scrypt        = require('scrypt');
  var validator     = require('validator');

  // ---

  var auth = {
    users: {}
  };

  var settingsSchema = {
    cdn: ['jsdelivr', 'cdnjs', 'google'],
    layout: ['layout-cols', 'layout-top', 'layout-left'],
    locale: ['en_US'],
    theme: ['dark']
  };

  auth.users.default_settings = _.mapObject(settingsSchema, _.first)

  auth.users.crud = new Rudiment({
    db: rethinkdb.table('users'),

    schema: schema({
      username: String,
      email: String,
      settings: settingsSchema,
      hash: String
    }),

    key: 'username',

    in: function(user) {
      user.settings = _.defaults(user.settings || {}, auth.users.default_settings);
      // FIXME: check user._, valid password, valid email, valid username
    },

    out: function(user) {
      user._ = {};
    }
  });

  var params_p = scrypt.params(config.auth.maxtime);

  /**
   * Hashes a plaintext string with SHA-512
   *
   * @param {String} plaintext - plaintext string to hash
   * @return {String} hex-encoded hash
   */
  auth.sha512 = function(plaintext) {
    return crypto.createHash('sha512').update(plaintext).digest('hex');
  };

  /**
   * Generate an scrypt salted hash from a plaintext string
   *
   * @param {String} plaintext - password to hash
   * @return {Promise}
   */
  auth.generate_hash = function(plaintext) {
    if (!_.isString(plaintext) || !plaintext.length) {
      return Promise.reject();
    }

    return params_p.then(function(params) {
      return scrypt.kdf(plaintext, params).then(function(buf) {
        return buf.toString('base64');
      });
    });
  };

  /**
   * Verify a plaintext string against an scrypt hash
   *
   * @param {String} plaintext - password to check
   * @param {String} hash - scrypt hash to compare to `plaintext`
   * @return {Promise}
   */
  auth.verify_hash = function(plaintext, hash) {
    if (!_.isString(plaintext) || !plaintext.length) {
      return Promise.reject(new Error('No plaintext provided'));
    }

    if (!_.isString(hash) || hash.length !== 128) {
      return Promise.reject(new Error('No hash or invalid hash provided'));
    }

    var kdf = new Buffer(hash, 'base64');
    return scrypt.verifyKdf(kdf, plaintext).then(function(ok) {
      if (!ok) {
        throw new Error(auth.errors.INVALID_PASSWORD);
      }
    });
  };

  /**
   *
   */
  auth.login_exists = function(username, email) {
    return Promise.all([
      auth.get_user_by_login(username),
      auth.get_user_by_login(email)
    ]).then(function(results) {
      return !!_.find(results);
    });
  };

  auth.get_user_by_id = function(id) {
    return auth.users.crud.read(id);
  };

  /**
   *
   */
  auth.get_user_by_login = function(login) {
    var query = {};

    if (_.str.include(login, '@')) {
      if (!auth.is_valid_email(login)) {
        return Promise.reject(auth.errors.INVALID_EMAIL);
      }

      query.email = login;
    } else {
      if (!auth.is_valid_username(login)) {
        return Promise.reject(auth.errors.INVALID_USERNAME);
      }

      query.username = login;
    }

    return auth.users.crud.find(query).then(function(users) {
      return users[0] || null;
    });
  };

  /**
   * Get a user from a login and plaintext password
   *
   * @param {String} login - username or email
   * @param {String} plaintext - password to check
   * @return {Promise}
   */
  auth.get_user_by_login_and_password = function(login, plaintext) {
    return auth.get_user_by_login(login).then(function(user) {
      if (!user) {
        throw new Error(auth.errors.USER_NOT_FOUND);
      }

      if (user.disabled) {
        throw new Error(auth.errors.USER_IS_DISABLED);
      }

      return auth.verify_hash(plaintext, user.hash).then(function() {
        return user;
      });
    });
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
  auth.create_user = function(user = {}) {
    let username = _.str.clean(user.username);
    let email = _.str.clean(user.email);

    if (!auth.is_valid_username(username)) {
      throw new Error('invalid username');
    }

    if (!auth.is_valid_email(email)) {
      throw new Error('invalid email');
    }

    if (user.password !== user.confirm) {
      throw new Error('passwords do not match');
    }

    if (!auth.is_valid_password(user.password)) {
      throw new Error('invalid password');
    }

    return auth.login_exists(username, email).then(function(exists) {
      if (exists) {
        throw new Error('username or email already exists');
      }

      return auth.generate_hash(user.password).then(function(hash) {
        return auth.users.crud.create({
          username: username,
          email: email,
          hash: hash
        });
      });
    });
  };

  /**
   * Change the password for a user
   * @param {String} login - username or email
   * @param {String} current - current plaintext password
   * @param {String} plaintext - new plaintext password
   * @param {String} confirm - new plaintext password confirmation
   * @return {Promise}
   */
  auth.change_password_for_login = function(login, current, plaintext, confirm) {
    return auth.get_user_by_login(login).then(function(user) {
      user._.password = {
        current: current,
        plaintext: plaintext,
        confirm: confirm
      };

      return auth.users.crud.update(user); // FIXME: needs Rudiment support
    });



    username = _.str.clean(username);

    if (!auth.is_valid_username) {
      return Promise.reject(auth.errors.INVALID_USERNAME);
    }

    if (plaintext !== confirm) {
      return Promise.reject(auth.errors.PASSWORDS_DO_NOT_MATCH);
    }

    if (!auth.is_valid_password) {
      return Promise.reject(auth.errors.INVALID_PASSWORD);
    }

    return auth.get_user_by_login_and_password(username, current).then(function(user) {
      return auth.generate_hash(plaintext).then(function(hash) {
        return db.change_password_hash(username, hash);
      });
    });
  };


















  /**
   * Determine if a session timestamp is expired
   *
   * @param {Number | String} timestamp - a Unix timestamp
   * @return {Boolean} true if timestamp is expired, false otherwise
   */
  auth.timestamp_is_expired = function(timestamp) {
    var max = config.auth.hours * 3600;
    var age = utils.timestamp_age(timestamp);

    return age < 0 || age > max;
  };

  /**
   * Clean up a potential username string
   *
   * @param {String} username - a string to treat as username input
   * @return {String} username with only alphanumeric characters and underscores
   */
  auth.sanitize_username = function(username) {
    username = utils.ensure_string(username).toLowerCase();
    return username.replace(/[^a-z0-9_]/ig, '');
  };

  /**
   * Test for a valid username
   *
   * @param {String} username - a string to treat as username input
   * @return {Boolean} true if username is valid, false otherwise
   */
  auth.is_valid_username = function(username) {
    return auth.sanitize_username(username) === username &&
      username.length >= 3 && username.length <= 64;
  };

  /**
   * Test for a valid email address
   *
   * @param {String} email - a string to treat as email address input
   * @return {Boolean} true if email is valid, false otherwise
   */
  auth.is_valid_email = function(email) {
    return validator.isEmail(email);
  };

  /**
   * Test for a valid password
   *
   * The only requirements for a valid password are that it must contain at
   * least one non-whitespace character, be at least 4 characters and at most
   * 1024 characters.  Users are otherwise free to shoot themselves in the foot.
   *
   * @param {String} plaintext - a string to treat as password input
   * @return {Boolean} true if password is valid, false otherwise
   */
  auth.is_valid_password = function(plaintext) {
    return _.isString(plaintext) && /^(?=.*\S).{4,1024}$/.test(plaintext);
  };

  return auth;
});
