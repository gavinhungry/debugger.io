/*
 * sandbug: An interactive web scripting sandbox
 */

define(function(require) {
  'use strict';

  var _ = require('underscore');

  var http  = require('http');
  var https = require('https');
  var Q     = require('q');

  var cjson     = require('cjson');
  var fs        = require('fs');
  var module    = require('module');
  var path      = require('path');
  var __dirname = path.dirname(module.uri);

  // ---

  var utils = {};

  /**
   * Log messages to console
   *
   * @param {Mixed} - messages to log
   */
  utils.log = function() {
    var args = _.toArray(arguments);
    args.unshift('==>');
    console.log.apply(console, args);
  };

  /**
   * Load remote JSON
   *
   * @param {Object} opts - options to http.get
   * @return {Promise} promise to return JSON
   */
  utils.get_json = function(opts) {
    var d = Q.defer();

    var protocol = (opts.port === 443) ? https : http;

    protocol.get(opts, function(res) {
      var datas = [];
      res.on('data', function (data) { datas.push(data); });
      res.on('end', function() {
        try {
          var result = JSON.parse(datas.join(''));
          d.resolve(result);
        } catch(err) { d.reject(err); }
      });
    }).on('error', d.reject);

    return d.promise;
  };

  /**
   * Get an object of JSON from a directory
   *
   * @param {String} dir - directory path relative to sandbug root
   * @return {Promise}
   */
  utils.dir_json = _.memoize(function(dir) {
    var d = Q.defer();

    var root = path.resolve('.');
    dir = path.resolve(dir);

    if (!_.str.startsWith(dir, root) || dir === root) {
      return utils.reject();
    }

    fs.readdir(dir, function(err, filenames) {
      if (err) { return d.reject(err); }

      var result = _.chain(filenames).filter(function(filename) {
        return _.str.endsWith(filename, '.json');
      }).map(function(json) {
        var data;

        try {
          data = cjson.load(path.join(dir, json));
        } catch(err) {
          return null;
        }

        var jsonId = _.str.strLeftBack(json, '.');

        return [jsonId, data];
      }).object().value();

      d.resolve(result);
    });

    return d.promise;
  });

  /**
   * Ensure that a value is an array
   *
   * @param {Mixed} value
   * @return {Array}
   */
  utils.ensure_array = function(value) {
    if (value === undefined || value === null) { return []; }
    return _.isArray(value) ? value : [value];
  };

  /**
   * Ensure that a value is a string
   *
   * @param {Mixed} value
   * @return {String}
   */
  utils.ensure_string = function(value) {
    if (_.isObject(value)) { return ''; }
    return _.isString(value) ? value : (value ? value + '' : '');
  };

  /**
   * Reduce a period-delimited string to an object
   *
   * @param {String} str - eg. 'module.run_method'
   * @param {Object} [base] - base object to start from, defaults to `global`
   * @return {Object} eg. `global.module.run_method`
   */
  utils.reduce = function(str, base) {
    base = base || global;
    if (!str || !_.isString(str)) { return base; }

    return _.reduce(str.split('.'), function(obj, prop) {
      return obj ? obj[prop] : null;
    }, base);
  };

  /**
   * Create a promise that resolves to a value now
   *
   * @param {Mixed} value - value that the promise will resolve to
   * @return {Promise} promise to return value
   */
  utils.resolve = function(value) {
    var d = Q.defer();
    d.resolve(value);
    return d.promise;
  };

  /**
   * Create a promise that rejects to a value now
   *
   * @param {Mixed} value - value that the promise will reject to
   * @return {Promise} promise to return value
   */
  utils.reject = function(value) {
    var d = Q.defer();
    d.reject(value);
    return d.promise;
  };

  /**
   * Send a server error to a client
   *
   * @param {express.response} res - Express HTTP response
   * @param {Object} [err]
   */
  utils.server_error = function(res, err) {
    if (err) {
      console.error(err);
    }

    if (!res || !res.status) { return; } // !(res instanceof express.response)

    var statusCode = err instanceof utils.ServerStatus ? err.statusCode : 500;
    res.status(statusCode).end();
  };

  /**
   * Return a handler to send a server error to a client
   *
   * @param {express.response} res - Express HTTP response
   * @return {Function}
   */
  utils.server_error_handler = function(res) {
    return function(err) {
      utils.server_error(res, err);
    };
  };

  /**
   * Determing the age of a Unix timestamp
   *
   * @param {Number | String} timestamp - a Unix timestamp
   * @return {Number} seconds since `timestamp` occurred
   */
  utils.timestamp_age = function(timestamp) {
    var then = parseInt(timestamp, 10);
    var now = utils.timestamp_now();

    var diff = now - then;

    return _.isNaN(diff) ? Math.POSITIVE_INFINITY : diff;
  };

  /**
   * Return the current Unix timestamp
   *
   * @return {Number} current Unix timestamp
   */
  utils.timestamp_now = function() {
    return Math.floor(Date.now() / 1000);
  };

  /**
   * Status code object
   *
   * @param {Number} status - HTTP status code
   */
  utils.ServerStatus = function(status) {
    this.statusCode = status;
  };

  return utils;
});
