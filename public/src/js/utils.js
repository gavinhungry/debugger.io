/*
 * sandbug: An interactive web scripting sandbox
 *
 * utils.js: utility functions
 */

define(function(require) {
  'use strict';

  var $      = require('jquery');
  var _      = require('underscore');
  var config = require('config');

  // ---

  var utils;

  /**
   * New module is just an empty object, but attach it to the global window
   * object if config.prod is false
   *
   * @param {String} name - name of the module (only relevant to window)
   * @param {Object} [base] - base object to use
   * @param {Boolean} [global] - if true, attach to global window object as well
   * @return {Object} empty module object
   */
  var _module = function(name, base, global) {
    var module = base || Object.create(null);

    if (!module._priv) {
      Object.defineProperty(module, '_priv', {
        value: Object.create(null)
      });
    }

    module.console = utils ? (module.console || new utils.Console(name)) : null;

    if (global || (global === undefined && !config.prod)) {
      window[name] = module;
    }

    return module;
  };

  utils = _module('utils', Object.create(null, { module: { value: _module } }));

  /**
   * Ensure that a value is wrapped with jQuery
   *
   * @param {Mixed} value
   * @return {jQuery}
   */
  utils.ensure_jquery = function(value) {
    if (value instanceof $) { return value; }
    if ((value instanceof HTMLElement) || _.isArray(value)) { return $(value); }
    return $();
  };

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
   * @param {Object} [base] - base object to start from, defaults to `window`
   * @return {Object} eg. `window.module.run_method`
   */
  utils.reduce = function(str, base) {
    base = base || window;
    if (!str || !_.isString(str)) { return base; }

    return _.reduce(str.split('.'), function(obj, prop) {
      return obj ? obj[prop] : null;
    }, base);
  };

  /**
   * Remove all double quotes (") from a string
   *
   * @param {String} str - input string
   * @return {String} input string with double quotes removed
   */
  utils.no_quotes = function(str) {
    return _.isString(str) ? str.replace(/\"/g, '') : '';
  };

  /**
   * Get the extension of a URI or filename
   *
   * @param {String} uri - URI or filename
   * @returns {String} extension
   */
  utils.extension = function(uri) {
    uri = _.str.trim(utils.no_quotes(uri));
    return _.str.strRightBack(uri, '.');
  };

  /**
   * Get string for a new script element
   *
   * @param {String} uri - URI of script
   * @param {String} [type] - script MIME type, defaults to JavaScript
   * @return {String} script string
   */
  utils.script_element_string = function(uri, type) {
    uri = _.str.trim(utils.no_quotes(uri));
    type = type || ext_map.js.type;

    var template = '<script type="%s" src="%s"></script>';
    return _.str.sprintf(template, type, uri);
  };

  /**
   * Get string for a new stylesheet link element
   *
   * @param {String} uri - URI of stylesheet
   * @param {String} [type] - style MIME type, defaults to CSS
   * @return {String} style link string
   */
  utils.style_element_string = function(uri, type) {
    uri = _.str.trim(utils.no_quotes(uri));
    type = type || ext_map.css.type;

    var template = '<link rel="stylesheet" type="%s" href="%s">';
    return _.str.sprintf(template, type, uri);
  };

  // map file extensions to functions generating the appropriate element string
  var ext_map = {
    'js': {
      tag: 'script',
      type: 'application/javascript',
      fn: utils.script_element_string
    },

    'css': {
      tag: 'link',
      type: 'text/css',
      fn: utils.style_element_string
    }
  };

  /**
   * Get the tag name that should be used for a resource, based on extension
   *
   * @param {String} uri - URI of resource
   * @return {String} tag name of resource
   */
  utils.resource_tag = function(uri) {
    var ext = utils.extension(uri);

    var map = ext_map[ext];
    return map ? map.tag : null;
  };

  /**
   * Get string for a new resource element, based on extension
   *
   * @param {String} uri - URI of resource
   * @return {String} resource element string
   */
  utils.resource_element_string = function(uri) {
    var ext = utils.extension(uri);

    var map = ext_map[ext];
    return map ? map.fn(uri, map.type) : null;
  };

  /**
   * Get the base path for a URI
   *
   * @example
   * // returns 'example.tld/foo/bar'
   * utils.path('http://example.tld/foo/bar/baz.html?q=abc')
   *
   * @param {String} uri - URI of resource
   * @return {String}
   */
  utils.path = function(uri) {
    uri = utils.ensure_string(uri).trim();
    if (!uri) { return ''; }

    var html = _.str.sprintf('<a href="%s"></a>', uri);
    var nodes = $.parseHTML(html);
    var a = utils.ensure_array(nodes)[0];

    var path = a.hostname  + a.pathname.replace(/\/[^\/\.]*\.[^\/\.]*$/, '');
    return _.str.rtrim(path, '/.');
  };

  /**
   * Create a promise that resolves to a value now
   *
   * @param {Mixed} value - value that the promise will resolve to
   * @return {Promise} promise to return value
   */
  utils.resolve = function(value) {
    return $.Deferred().resolve(value).promise();
  };

  /**
   * Create a promise that rejects to a value now
   *
   * @param {Mixed} value - value that the promise will reject to
   * @return {Promise} promise to return value
   */
  utils.reject = function(value) {
    return $.Deferred().reject(value).promise();
  };

  /**
   * Always resolve to true (success) or false (failure)
   *
   * @param {Deferred|Promise} p
   * @return {Promise} resolves to boolean value
   */
  utils.resolve_boolean = function(p) {
    var d = $.Deferred();

    $.when(p).then(function() {
      d.resolve(true);
    }, function() {
      d.resolve(false);
    });

    return d.promise();
  };

  /**
   * Return a number clamped by a minimum and maximum
   *
   * @param {Number} val - number to clamp
   * @param {Number} [min] - minimum value, defaults to 0
   * @param {Number} [max] - maximum value, defaults to `val`
   * @return {Number} clamped value
   */
  utils.clamp = function(val, min, max) {
    val = _.isFinite(val) ? val: 0;
    min = _.isFinite(min) ? min : Number.NEGATIVE_INFINITY;
    max = _.isFinite(max) ? max : Number.POSITIVE_INFINITY;

    return Math.min(Math.max(val, min), max);
  };

  /**
   * Deep clone an object parsable as JSON
   *
   * @param {Object} val
   * @return {Object} deep copy of `val`
   */
  utils.clone = function(val) {
    return JSON.parse(JSON.stringify(val));
  };

  /**
   * Try to parse JSON
   *
   * @param {String} json
   * @return {Object}
   */
  utils.parse_json = function(json) {
    try {
      return JSON.parse(json);
    } catch(err) {
      return null;
    }
  };

  /**
   * Hash function for _.memoize
   *
   * @return {String} joined arguments with hopefully unique separator
   */
  utils.memoize_hasher = function() {
    return _.toArray(arguments).join('<<<!>>>');
  };

  /**
   * Clean up a potential resource ID
   *
   * @param {String} id - a string to treat as a resource ID
   * @return {String} `id` with only alphanumeric chars, underscores and hyphens
   */
  utils.sanitize_resource_id = function(id) {
    id = utils.ensure_string(id);
    return id.replace(/[^a-z0-9_-]/ig, '');
  };

  /**
   * Minifies a CSS selector string
   *
   * @param {String} selector - original selector
   * @return {String} minified selector
   */
  utils.minify_css_selector = function(selector) {
    selector = utils.ensure_string(selector);
    return _.str.clean(selector.replace(/\s*([>+~])\s*/g, '$1'));
  };

  /**
   * Submit a form with jQuery and return its promise
   *
   * @param {jQuery} $form - form element
   * @return {Promise} from $.ajax
   */
  utils.submit_form = function($form) {
    $form = utils.ensure_jquery($form);

    var uri = $form.attr('action');
    var data = utils.form_map($form);

    var method = utils.ensure_string($form.attr('method')) || 'get';
    return $.ajax({
      method: method,
      url: uri,
      data: data
    });
  };

  /**
   * Convert a form to a map
   *
   * @param {jQuery} $form
   * @return {Object}
   */
  utils.form_map = function($form) {
    return _.reduce($form.serializeArray(), function(obj, prop) {

      var $input = $form.find(_.str.sprintf('[name="%s"]', prop.name)).first();
      var group = $input.data('form-group');

      if (group) {
        obj[group] = obj[group] || {};
        obj[group][prop.name] = prop.value;
      } else {
        obj[prop.name] = prop.value;
      }

      return obj;
    }, {});
  };

  /**
   * Get a value from a function or promise (arbitrarily nested)
   *
   * @param {Mixed} value - value, promise, or a function returning either
   * @return {Promise}
   */
  utils.value = function(value) {
    if (_.isUndefined(value) || _.isNull(value)) {
      return utils.resolve(value);
    }

    // base case: not a a function, and not a duck-typed promise
    if (!_.isFunction(value) && !_.isFunction(value.promise)) {
      return utils.resolve(value);
    }

    var value_m = _.isFunction(value) ? value(): value;
    return $.when(value_m).then(utils.value);
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
   * Get the number of seconds since startup
   *
   * @return {Number} time in seconds
   */
  utils.runtime = function() {
    return Math.floor(performance.now() / 1000);
  };

  /**
   * Set the document title, suffixed by config.title
   *
   * @param {String} title - new title to set
   */
  utils.title = function(title) {
    document.title = title ? _.str.sprintf('%s - %s', title, config.title) :
      config.title;
  };

  /**
   * An array of limited capacity
   *
   * @param {Number} cap - capacity of the buffer
   */
  utils.Buffer = function(cap) {
    this._data = [];
    this.set_cap(cap);
  };

  utils.Buffer.prototype = {
    /**
     * Buffer some value(s), then truncate to capacity
     *
     * @param {Mixed} - value(s) to buffer
     * @return {this}
     */
    buf: function() {
      _.each(arguments, function(arg) { this._data.push(arg); }, this);
      if (this._data.length > this._cap) {
        this._data.splice(0, this._data.length - this._cap);
      }

      return this;
    },

    set_cap: function(cap) { this._cap = utils.clamp(cap, 0); },
    get: function() { return this._data.slice(0); },
    flush: function() { this._data = []; }
  };

  /**
   * Get a console object with an optional namespace prefix
   *
   * @param {Mixed} [namespace_m] - value, promise or function
   * @return {Object}
   */
  utils.Console = function(namespace_m) {
    this.value = namespace_m;
  };

  utils.Console.prototype = _.reduce([
    'debug', 'error', 'info', 'log', 'warn'
  ], function(prototype, method) {
    prototype[method] = function() {
      if (config.prod) { return; }

      var args = _.toArray(arguments);
      utils.value(this.value).then(function(namespace) {
        if (namespace) { args.unshift(_.str.sprintf('[%s]', namespace)); }
        console[method].apply(console, args);
      });
    };
    return prototype;
  }, {});

  utils.console = new utils.Console();

  return utils;
});
