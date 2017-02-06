/*
 * sandbug: An interactive web scripting sandbox
 */

define(function(require) {
  'use strict';

  var _     = require('underscore');
  var utils = require('utils');

  var cjson = require('cjson');

  var module    = require('module');
  var path      = require('path');
  var __dirname = path.dirname(module.uri);

  // ---

  var config = { client: {} };

  var appRoot = __dirname + '/../../';

  var required_options = [
    'auth.secret'
  ];

  /**
   * Extend the config object with data from a JSON file, if available
   *
   * @param {String} prop - property to create (if needed) and extend
   * @param {String} filename - JSON filename, relative to `appRoot`
   */
  var extend_config_with_json = function(prop, filename) {
    var obj = prop ? (config[prop] || {}) : config;
    if (prop) { config[prop] = obj; }

    try {
      _.deepExtend(obj, cjson.load(appRoot + filename));
    } catch(err) {
      // nothing to do
    }
  };

  extend_config_with_json(null, 'config.json');
  extend_config_with_json(null, 'deploy.json');
  extend_config_with_json('build', 'build.json');

  config.prod = config.client.prod = (process.env.NODE_ENV === 'production');
  config.client.build = config.build;

  // default theme goes last
  config.themes = ['dark'];
  config.themes[_.indexOf(config.themes, config.client.default_theme)] = null;
  config.themes.push(config.client.default_theme);
  config.themes = _.uniq(_.compact(config.themes));

  var invalids = _.filter(required_options, function(required) {
    var opt = utils.reduce(required, config);
    return _.isUndefined(opt) || _.isNull(opt);
  });

  if (invalids.length) {
    _.each(invalids, function(invalid) {
      console.error('Unset option: ' + invalid);
    });

    console.error('See `config.json`, `deploy.json`');
  }

  return config;
});
