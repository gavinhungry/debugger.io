/*
 * debugger.io: An interactive web scripting sandbox
 *
 * themes.js: theme manager
 */

define([
  'config', 'utils', 'jquery', 'underscore',
  'mirrors'
],
function(config, utils, $, _, mirrors) {
  'use strict';

  var themes = utils.module('themes');

  var theme_map = [];

  /**
   * Cache theme stylesheets and set default theme
   */
  themes.init = function() {
    var themeRegex = /\/debuggerio\.(\w+)\.min\.css$/;

    _.each(document.styleSheets, function(stylesheet) {
      var href = $(stylesheet.ownerNode).attr('data-href');
      var match = themeRegex.exec(href);

      // either save the matched theme or disable the stylesheet
      !!match ?
        theme_map.push({ id: match[1], stylesheet: stylesheet }) :
        stylesheet.disabled = true;
    });

    themes.set_theme(config.default_theme);
  };

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
   * Set the current theme by id
   *
   * @param {String} id - theme id to set
   */
  themes.set_theme = function(id) {
    var themeExists = _.some(theme_map, function(theme) {
      return theme.id === id;
    });

    if (!themeExists) { return; }

    mirrors.set_theme_all(id === 'dark' ? 'dark' : 'light');
    _.each(theme_map, function(theme, i) {
      theme.stylesheet.disabled = (theme.id !== id);
    });
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

    if (!hasTheme) { themes.set_theme(config.default_theme); }
  };

  return themes;
});
