/*
 * sandbug: An interactive web scripting sandbox
 *
 * locales.js: localized strings
 */

define(function(require) {
  'use strict';

  var $      = require('jquery');
  var _      = require('underscore');
  var bus    = require('bus');
  var config = require('config');
  var utils  = require('utils');
  var rpc    = require('rpc');

  var observers = require('observers');

  // ---

  var locales = utils.module('locales');

  var dir = '/locales';
  var cache = {};
  var sync = {};

  var prefix = '@';

  bus.init(function(av) {
    locales.console.log('init locales module');

    // localize nodes with `data-localize` attribute as added
    observers.register_listener(function(mutation) {
      locales.localize_dom_nodes($(mutation.addedNodes));
    });

    bus.on('config:locale', function(localeStr) {
      locales.string('onbeforeunload');
      locales.localize_dom_nodes();
    });
  });

  /**
   * Make sure a locale is loaded (either from cache or the server),
   * then return a promise to return extended locale
   *
   * @param {String} id - locale id
   * @return {Promise} promise to return the extended locale
   */
  locales.get = function(id) {
    if (cache[id]) {
      return cache[id].then(utils.clone);
    }

    console.debug('Getting LOCALE FROM SERVER!!!!!!', id);
    cache[id] = rpc.getModule('locales').getLocale(id);

    return locales.get(id);
  };

  /**
   * Returned a localized string from a string ID
   *
   * @param {String} strId - a string ID
   * @param {String} [...] - strings to pass to _.str.sprintf, if applicable
   * @return {Promise} to return localed string matching `strId`
   */
  locales.string = function(strId) {
    var d = $.Deferred();

    var args = _.rest(arguments);

    locales.get(config.locale).then(function(locale) {
      var str = (locale.strings && strId) ? locale.strings[strId] : null;
      if (!str) {
        locales.console.warn(_.str.sprintf('No %s locale string: %s', config.locale, strId));
        return d.resolve(null);
      }

      // count the number of sprintf placeholders are present
      var sprintfMatches = str.match(/\%s/g);
      var sprintfCount = sprintfMatches ? sprintfMatches.length : 0;

      // an array of the same length, with missing values set to an empty string
      var sprintfArgs = _.map((new Array(sprintfCount)), function(val, i) {
        var arg = args[i];
        return (arg || (arg === 0)) ? arg : '';
      });

      sprintfArgs.unshift(str);
      var formattedStr = _.str.sprintf.apply(null, sprintfArgs);
      sync[strId] = formattedStr; // sprintfArgs are not cached
      d.resolve(formattedStr);
    }, function(err) {
      d.reject(null);
    });

    return d.promise();
  };

  /**
   * For an array of string IDs, return an object mapping them to their strings
   *
   * @example
   * // returns {Promise} => { foo: 'Foo!', bar: 'Bar?' }
   *
   * locales.multi_string(['foo', 'bar']);
   *
   * @param {Array} strIds
   * @return {Promise}
   */
  locales.strings = function(strIds) {
    var strs_p = _.map(utils.ensure_array(strIds), function(strId) {
      return locales.string(strId);
    });

    return $.when.apply(null, strs_p).then(function() {
      return _.object(strIds, arguments);
    });
  };

  /**
   * Returns a promise to localize a string if a leading prefix is found
   *
   * @param {Mixed}
   * @return {Promise|String}
   */
  locales.prefixed = function(val) {
    return (_.isString(val) && locales.is_prefixed(val)) ?
      locales.string(_.str.strRight(val, prefix)) : val;
  };

  /**
   * Checks if a string is local prefixed
   *
   * @param {String} str
   * @return {Boolean} true if str is prefixed, false otherwise
   */
  locales.is_prefixed = function(str) {
    return !str.indexOf(prefix);
  };

  /**
   * Localize DOM nodes with `data-localize` attribute
   *
   * @param {jQuery} [$localize] - set of nodes to localize
   * @return {Promise} to resolve upon completion
   */
  locales.localize_dom_nodes = function($root) {
    $root = $root || $('body');
    var $localize = $root.find('[data-localize]');
    var $placeholders = $root.find('[data-localize-placeholder]');

    return locales.get(config.locale).then(function(locale) {
      $localize.each(function() {
        // get the locale string ID
        var localize = $(this).attr('data-localize');

        // replace the first text node with the localized string, if present
        $(this).contents().filter(function() { return this.nodeType === 3; })
        .first().each(function() {
          var that = this;
          locales.string(localize).then(function(localizedValue) {
            if (localizedValue) {
              that.nodeValue = localizedValue;
            }
          });
        });
      });

      $placeholders.each(function() {
        var $placeholder = $(this);
        locales.localize_placeholder($placeholder);
      });
    });
  };

  /**
   * Set a placeholder from a data-localize-placeholder template
   *
   * @param {jQuery} $element - some element with a data-localize-placeholder attribute
   * @param {Array} values - values to pass to _.str.sprintf
   * @return {Promise}
   */
  locales.localize_placeholder = function($element, values) {
    if (!$element) {
      return utils.resolve(false);
    }

    var args;

    if (values) {
      args = utils.ensure_array(values);
      $element.data('placeholder-args', JSON.stringify(args));
    } else {
      args = utils.parse_json($element.data('placeholder-args'));
    }

    var strId = $element.attr('data-localize-placeholder');

    return locales.string(strId, args).then(function(placeholder) {
      $element.attr('placeholder', placeholder);
    });
  };

  /**
   * Return a synchronous value from existing cache
   *
   * @param {String} strId - a string ID
   * @return {String} Localed string matching `strId`
   */
  locales.sync = function(strId) {
    return sync[strId];
  };

  return locales;
});
