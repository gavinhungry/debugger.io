/*
 * sandbug: An interactive web scripting sandbox
 */

define(function(require) {
  'use strict';

  var _      = require('underscore');
  var config = require('config');
  var utils  = require('utils');

  var bodyParser    = require('body-parser');
  var cookieParser  = require('cookie-parser');
  var cookieSession = require('cookie-session');
  var crypto        = require('crypto');
  var db            = require('db');
  var local         = require('passport-local');
  var passport      = require('passport');
  var Q             = require('q');
  var Rudiment      = require('rudiment');
  var schema        = require('js-schema');
  var scrypt        = require('scrypt');
  var seasurf       = require('seasurf');
  var validator     = require('validator');

  var module    = require('module');
  var path      = require('path');
  var __dirname = path.dirname(module.uri);

  // ---

  var auth = {};

  auth.crud = new Rudiment({
    db: db.raw.users,
    key: 'username',

    schema: [schema({
      username: String,
      email: String,
      settings: {
        cdn: ['jsdelivr', 'cdnjs', 'google'],
        layout: ['layout-cols', 'layout-top', 'layout-left'],
        locale: ['en_US'],
        theme: ['dark']
      }
    }), function(user) {
      return auth.is_valid_username(user.username) &&
        auth.is_valid_email(user.email) &&
        _.keys(user.settings).length === 4;
    }],

    out: function(user) {
      delete user._id;
      delete user.hash;
    }
  });

  // scrypt setup
  var params_p = scrypt.params(config.auth.maxtime);

  /**
   * @param {Express} server - Express server to init auth methods on
   */
  auth.init = function(server) {
    passport.serializeUser(function(user, done) {
      var timestamp = utils.timestamp_now();
      var str = _.str.sprintf('%s-%s', timestamp, user._id);

      done(null, str);
    });

    passport.deserializeUser(function(str, done) {
      var split = utils.ensure_string(str).split('-');
      var timestamp = _.first(split);
      var id = _.last(split);

      if (auth.timestamp_is_expired(timestamp)) {
        done(null, false, { msg: 'session expired' });
      } else {

        // find a user for this session
        db.get_user_by_id(id, false).then(function(user) {
          if (user) {
            done(null, user);
          } else {
            done(null, false, { msg: 'invalid login' });
          }
        }, function(err) {
          done(err, false, { msg: 'authentication error' });
        });
      }
    });

    passport.use(new local.Strategy(function(login, plaintext, done) {
      auth.get_user_by_login(login, plaintext).then(function(user) {
        if (user) {
          done(null, user);
        } else {
          done(null, false, { msg: 'invalid login' });
        }
      }, function(err) {
        done(err, false, { msg: 'authentication error' });
      });
    }));

    server.use(bodyParser.json());
    server.use(bodyParser.urlencoded({ extended: true }));
    server.use(cookieParser());
    server.use(cookieSession({
      secret: config.auth.secret,
      key: config.auth.cookie
    }));

    server.use(passport.initialize());
    server.use(passport.session());

    server.use(seasurf({
      paths: ['/api/']
    }));
  };

  auth.authenticate = passport.authenticate('local');

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
   * @return {Promise} to return salted hash
   */
  auth.generate_hash = function(plaintext) {
    if (!_.isString(plaintext) || !plaintext.length) {
      return utils.reject();
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
   * @return {Promise} to return a boolean (true if hash matches)
   */
  auth.verify_hash = function(plaintext, hash) {
    var d = Q.defer();

    if (!_.isString(plaintext) || !plaintext.length) {
      return utils.resolve(false);
    }

    if (!_.isString(hash) || hash.length !== 128) {
      return utils.resolve(false);
    }

    var kdf = new Buffer(hash, 'base64');
    scrypt.verifyKdf(kdf, plaintext).then(function(result) {
      d.resolve(result);
    }, function(err) {
      d.resolve(false);
    });

    return d.promise;
  };

  /**
   * Get a user from a login and plaintext password
   *
   * @param {String} login - username or email
   * @param {String} plaintext - password to check
   * @return {Promise} to return a user or false if no matching user found
   */
  auth.get_user_by_login = function(login, plaintext) {
    return db.get_user_by_login(login, true).then(function(user) {
      if (!user || user.disabled) {
        return false;
      }

      return auth.verify_hash(plaintext, user.hash).then(function(match) {
        delete user.hash;
        return match ? user : false;
      });
    });
  };

  /**
   * Create a new user with a plaintext password
   *
   * @param {String} username - requested username
   * @param {String} email - requested email address
   * @param {String} plaintext - plaintext password
   * @param {String} confirm - plaintext password confirmation
   * @return {Promise} resolves to new user record on success
   */
  auth.create_user = function(username, email, plaintext, confirm) {
    username = _.str.clean(username);
    email = _.str.clean(email);

    if (!auth.is_valid_username(username) || !auth.is_valid_email(email) ||
      plaintext !== confirm || !auth.is_valid_password(plaintext))
    {
      return utils.reject(new utils.ServerStatus(400));
    }

    // check that the login is available first
    return db.login_exists(username, email).then(function(exists) {
      if (exists) {
        return utils.reject(new utils.ServerStatus(409));
      }

      return auth.generate_hash(plaintext).then(function(hash) {
        return db.create_user(username, email, hash);
      });
    });
  };

  /**
   * Change the password for a user
   * @param {String} username
   * @param {String} current - current plaintext password
   * @param {String} plaintext - new plaintext password
   * @param {String} confirm - new plaintext password confirmation
   * @return {Promise}
   */
  auth.change_password = function(username, current, plaintext, confirm) {
    username = _.str.clean(username);

    if (!auth.is_valid_username(username) || plaintext !== confirm ||
      !auth.is_valid_password(plaintext))
    {
      return utils.reject(new utils.ServerStatus(400));
    }

    return auth.get_user_by_login(username, current).then(function(user) {
      if (!user) {
        return utils.reject(new utils.ServerStatus(403));
      }

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
    return auth.sanitize_username(username) ===
      username && username.length >= 3 && username.length <= 64;
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
   * least one non-whitespace character, be at least 8 characters and at most
   * 1024 characters.  Users are free to shoot themselves in the foot.
   *
   * @param {String} plaintext - a string to treat as password input
   * @return {Boolean} true if password is valid, false otherwise
   */
  auth.is_valid_password = function(plaintext) {
    return _.isString(plaintext) && /^(?=.*\S).{8,1024}$/.test(plaintext);
  };

  return auth;
});
