/*
 * sandbug: An interactive web scripting sandbox
 *
 * themes.js: theme manager
 */

define(function(require) {
  'use strict';

  var $      = require('jquery');
  var _      = require('underscore');
  var bus    = require('bus');
  var config = require('config');
  var utils  = require('utils');

  var mirrors = require('mirrors');

  // ---

  var themes = utils.module('themes');

  var theme_map = [];

  bus.init(function(av) {
    themes.console.log('init themes module');

    var themeRegex = /\/sandbug\.(\w+)\.min\.css(\?v=.*)?$/;

    _.each(document.styleSheets, function(stylesheet) {
      var href = $(stylesheet.ownerNode).attr('data-href');
      var match = themeRegex.exec(href);

      // either save the matched theme or disable the stylesheet
      if (match) {
        theme_map.push({
          id: match[1],
          stylesheet: stylesheet
        });
      } else {
        stylesheet.disabled = true;
      }        
    });

    bus.on('config:theme', themes.set_theme);
    config._priv.set_option('theme', config.default_theme);
    themes.set_theme(config.default_theme);
  });

  /**
   * Get the current theme id
   *
   * @return {String} current theme id
   */
  themes.get_theme = function() {
    var theme = _.find(theme_map, function(theme, i) {
      return !theme.stylesheet.disabled;
    });

    return theme ? theme.id : null;
  };

  /**
   * Get all theme ids
   *
   * @return {Array}
   */
  themes.get_themes = function() {
    return _.map(theme_map, 'id');
  };

  /**
   * Set the current theme by id
   *
   * @param {String} id - theme id to set
   */
  themes.set_theme = function(id) {
    if (!id) {
      return;
    }

    if (!_.some(theme_map, function(theme) { return theme.id === id; })) {
      return themes.set_theme(config.default_theme);
    }

    mirrors.set_theme_all(id);
    _.each(theme_map, function(theme, i) {
      theme.stylesheet.disabled = (theme.id !== id);
    });

    if (id !== config.theme) {
      config.theme = id;
    }
  };

  /**
   * Rotate through available themes
   */
  themes.cycle_theme = function() {
    var hasTheme = _.some(theme_map, function(theme, i) {
      if (!theme.stylesheet.disabled) {
        var nextTheme = theme_map[(i + 1) % theme_map.length].id;
        themes.set_theme(nextTheme);

        return true;
      }
    });

    if (!hasTheme) {
      themes.set_theme(config.default_theme);
    }
  };

  return themes;
});
