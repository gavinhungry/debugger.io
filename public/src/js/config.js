/*
 * sandbug: An interactive web scripting sandbox
 *
 * config.js: simple configuration manager
 */

define(function(require) {
  'use strict';

  var config = require('promise!config_p');

  // ---

  delete window.__sandbug;
  if (!config.prod) {
    window.config = config;
  }

  return config;
});

define('config_p', function(require) {
  'use strict';

  var $ = require('jquery');
  var _ = require('underscore');
  var proximal = require('proximal');

  // ---

  var config = Object.create(null, {
    _priv: { value: Object.create(null) }
  });

  config._priv.rpc = new proximal.Client({
    url: '/rpc'
  });

  var locals = window.__sandbug || {};
  var hostname = window.location.hostname;
  var protocol = window.location.protocol;
  var proxyable_sub_options = ['mode'];

  // default options
  var options = {
    github: 'https://github.com/gavinhungry/sandbug',
    frame: _.str.sprintf('%s//frame.%s', protocol, hostname),
    username: locals.username,
    csrf: locals.csrf,
    mode: locals.mode,
    com: null,
    title: document.title
  };

  /**
   * Proxy config values from an update to the event bus
   *
   * @param {String} option - option name
   */
  config._priv.proxy = function(option) {
    $(document).trigger('_sandbug-config', {
      option: option,
      value: config[option]
    });
  };

  /**
   * Create a new config option
   *
   * Values may always be functions, but any value originally declared as a
   * boolean must either be a boolean or a function that returns a boolean
   *
   * @param {String} option - option name
   * @param {Mixed} value - initial value
   * @param {Boolean} [parent] - parent option
   */
  config._priv.set_option = function(option, value, parent) {
    if (Object.hasOwnProperty.call(config, option)) { return; }
    var dest = parent ? config[parent] : config;

    var isBool = _.isBoolean(value);

    Object.defineProperty(dest, option, {
      enumerable: true,

      get: function() {
        var val = options[option];
        var isFn = _.isFunction(val);
        return isFn ? (isBool ? !!val() : val()) : val;
      },
      set: function(val) {
        var wasUndefined = (options[option] === undefined);

        var isFn = _.isFunction(val);
        options[option] = (isBool && !isFn) ? !!val : val;

        if (!wasUndefined) { config._priv.proxy(parent || option); }

        // define proxyable sub-options
        if (_.contains(proxyable_sub_options, option) && !parent) {
          config._priv.set_options(val, option);
        }
      }
    });

    dest[option] = value;
  };

  /**
   * Create multiple new config options
   *
   * @param {Object} opts - key/value pairs
   * @param {Boolean} [parent] - parent option
   */
  config._priv.set_options = function(opts, parent) {
    _.each(opts, function(value, option) {
      config._priv.set_option(option, value, parent);
    });
  };

  config._priv.set_options(options);

  $.ajaxSetup({
    beforeSend: function(xhr, settings) {
      if (!settings.crossDomain) {
        xhr.setRequestHeader('X-CSRF-Token', config.csrf);
      }
    }
  });

  return config._priv.rpc.getModule('config').getConfig().then(client => {
    if ($(window).width() < 1280) {
      config._priv.set_option('default_layout', client.default_compact_layout);
    }

    config._priv.set_options(client);
    config._priv.set_option('default_locale', client.locale);

    return config;
  });
});
