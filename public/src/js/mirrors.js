/*
 * sandbug: An interactive web scripting sandbox
 *
 * mirrors.js: CodeMirror instances
 */

define(function(require) {
  'use strict';

  var $      = require('jquery');
  var _      = require('underscore');
  var bus    = require('bus');
  var config = require('config');
  var utils  = require('utils');

  var CodeMirror = require('codemirror');
  var dom = require('dom');

  // ---

  var mirrors = utils.module('mirrors');

  var instances = [];
  var last_focused;

  bus.init(function(av) {
    mirrors.console.log('init mirrors module');

    _.each(av.$input_panels, function(panel) {
      var $panel = $(panel);
      var $textarea = $panel.children('textarea');
      var mode = $panel.children('.mode').val();

      var cm = CodeMirror.fromTextArea($textarea[0], {
        lineNumbers: true,
        lineWrapping: true,
        mode: mode,
        tabSize: 2,
        scrollbarStyle: 'simple'
      });

      var mirror = {
        panel: $panel.attr('id'),
        $panel: $panel,
        $textarea: $textarea,
        cm: cm,
        mode: mode
      };

      cm.on('focus', function() {
        bus.trigger('mirror:focus', mirror);
        last_focused = mirror;
      });

      cm.on('change', function() {
        var content = mirrors.get_content(mirror);
        bus.trigger('mirrors:content', mirror.panel, content);
      });

      bus.on('panels:resizing', function() {
        _.defer(function() {
          CodeMirror.signal(mirror.cm, 'change');
        });
      });

      bus.on('window:resize panels:resized', function() {
        _.defer(function() {
          mirrors.simulate_change(mirror);
        });
      });

      instances.push(mirror);
    });

    bus.on('cdn:result:select', function(uri) {
      mirrors.add_lib_to_markup(uri);
      mirrors.refocus();
    });
  });

  /**
   * Get all active mirrors
   *
   * @return {Array} of CodeMirror instances
   */
  mirrors.get_all = function() { return instances; };

  /**
   * Save all CodeMirror content to underlying textareas
   */
  mirrors.save_all = function() {
    _.each(instances, function(mirror) { mirror.cm.save(); });
  };

  /**
   * Get a JSON-able map of all mirrors and their content
   *
   * @param {Boolean} [strip] - if true, remove panel property
   * @return {Object}
   */
  mirrors.get_map = function(strip) {
    var arr =  _.map(instances, function(mirror) {
      var map = _.pick(mirror, 'panel', 'mode');
      map.content = mirror.cm.getValue();
      return map;
    });

    var map = _.reduce(arr, function(memo, value) {
      memo[value.panel] = value;
      return memo;
    }, {});

    return strip ? _.each(map, function(value) {
      delete value.panel;
    }) : map;
  };

  /**
   * Get a mirror by its panel id
   *
   * @param {String} id - panel id
   * @return {CodeMirror} mirror with matching panel id, null otherwise
   */
  mirrors.get_by_id = function(id) {
    var mirror = _.find(instances, function(mirror) {
      return mirror.panel === id;
    });

    return mirror && mirror.cm instanceof CodeMirror ? mirror : null;
  };

  /**
   * Get multiple mirrors by their panel ids
   *
   * @param {Array|String} ids - panel ids
   * @return {Array} of CodeMirror instances
   */
  mirrors.get_by_ids = function(ids) {
    return _.compact(_.map(utils.ensure_array(ids), mirrors.get_by_id));
  };

  /**
   * Get a mirror for either its panel id or the mirror itself
   *
   * @param {String | Object} m - panel id or mirror
   * @return {CodeMirror} - null if requested mirror does not exist
   */
  mirrors.get_instance = function(m) {
    return m && m.cm instanceof CodeMirror ? m : mirrors.get_by_id(m);
  };

  var mirror_mode_sets = {
    'markup': [
      { label: 'HTML', mode: 'htmlmixed' },
      { label: 'Markdown', mode: 'gfm' },
      { label: 'Jade', mode: 'jade' },
      { label: 'Haml', mode: 'haml' }
    ],
    'style': [
      { label: 'CSS', mode: 'css' },
      { label: 'LESS', mode: 'less', cm_mode: 'text/x-less' },
      { label: 'SCSS', mode: 'scss', cm_mode: 'text/x-scss' }
    ],
    'script': [
      { label: 'JavaScript', mode: 'javascript' },
      { label: 'Traceur', mode: 'traceur', cm_mode: 'javascript' },
      { label: 'CoffeeScript', mode: 'coffeescript' },
      {
        label: 'TypeScript', mode: 'typescript',
        cm_mode: 'application/typescript'
      },
      { label: 'GorillaScript', mode: 'gorillascript', cm_mode: 'javascript' }
    ]
  };

  var get_mode_set = function(panel, mode) {
    return _.find(mirror_mode_sets[panel], function(set) {
      return set.mode === mode || set.cm_mode === mode;
    }) || _.first(mirror_mode_sets[panel]);
  };

  /**
   * Get the mode for a mirror
   *
   * @param {String | Object} m - panel id or mirror
   * @return {String} current mirror mode
   */
  mirrors.get_mode = function(m) {
    var mirror = mirrors.get_instance(m);
    if (!mirror) { return null; }

    return mirror.mode;
  };

  /**
   * Set the mode for a mirror
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String} [mode] - new mode to set
   */
  mirrors.set_mode = function(m, mode) {
    var mirror = mirrors.get_instance(m);
    if (!mirror) { return; }

    var set = get_mode_set(mirror.panel, mode);
    if (!set) { return; }

    mirror.cm.setOption('mode', set.cm_mode || set.mode);
    mirror.mode = set.mode;

    bus.trigger('mirrors:mode', mirror.panel, set.mode, set.label);
  };

  /**
   * Get the default mode of a mirror
   *
   * @param {String | Object} m - panel id or mirror
   * @return {String | null}
   */
  mirrors.get_default_mode = function(m) {
    var mirror = mirrors.get_instance(m);
    if (!mirror && !_.isString(m)) { return null; }

    var panel = mirror ? mirror.panel : m;
    var set = get_mode_set(panel);
    return set ? set.mode : null;
  };

  /**
   * Rotate a mirror through available modes
   *
   * @param {String | Object} m - panel id or mirror
   */
  mirrors.cycle_mode = function(m) {
    var mirror = mirrors.get_instance(m);
    var panel = mirror.panel;

    var modes = mirror_mode_sets[panel];
    var mode = mirrors.get_mode(panel);
    if (!modes) { return; }

    var set = get_mode_set(panel, mode);
    var i = _.indexOf(modes, set);

    var newMode = modes[++i % modes.length];
    mirrors.set_mode(panel, newMode.mode);
  };

  /**
   * Get the content for a mirror
   *
   * @param {String | Object} m - panel id or mirror
   * @return {String | null} content of mirror
   */
  mirrors.get_content = function(m) {
    var mirror = mirrors.get_instance(m);
    if (!mirror) { return null; }

    return mirror.cm.getValue();
  };

  /**
   * Set the content for a mirror
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String} content - new content to set
   */
  mirrors.set_content = function(m, content) {
    var mirror = mirrors.get_instance(m);
    if (!mirror || !_.isString(content)) { return; }

    mirror.cm.setValue(content);
  };

  /**
   * Get the theme for a mirror
   *
   * @param {String | Object} m - panel id or mirror
   * @return {String} current mirror theme
   */
  mirrors.get_theme = function(m) {
    var mirror = mirrors.get_instance(m);
    if (!mirror) { return ''; }

    return mirror.cm.getOption('theme');
  };

  /**
   * Set the theme for a mirror
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String} theme - new theme to set
   */
  mirrors.set_theme = function(m, theme) {
    var mirror = mirrors.get_instance(m);
    if (!mirror || !_.isString(theme)) { return; }

    mirror.cm.setOption('theme', theme);
  };

  /**
   * Set the theme for all mirrors
   *
   * @param {String} theme - new theme to set
   */
  mirrors.set_theme_all = function(theme) {
    _.each(instances, function(mirror) {
      mirrors.set_theme(mirror, theme);
    });
  };

  /**
   * Set the cursor focus on a mirror
   *
   * @param {String | Object} m - panel id or mirror
   */
  mirrors.focus = function(m) {
    var mirror = mirrors.get_instance(m);
    if (!mirror) { return; }

    mirror.cm.focus();
  };

  /**
   * Refocus the last focused mirror
   */
  mirrors.refocus = function() {
    mirrors.focus(last_focused);
  };

  /**
   * Search a mirror for the first occurrence of a string
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String | RegExp} str - string to search for
   * @param {Boolean} ci - if true, search is case-insensitive
   * @return {Object} position map { line, ch } if found, null otherwise
   */
  mirrors.search_first = function(m, str, ci) {
    var mirror = mirrors.get_instance(m);
    if (!mirror || (!_.isString(str) && !_.isRegExp(str))) { return null; }

    var cur = mirror.cm.getSearchCursor(str, null, !!ci);
    return (cur && cur.find()) ? { from: cur.from(), to: cur.to() } : null;
  };

  /**
   * Search a mirror for the last occurrence of a string
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String | RegExp} str - string to search for
   * @param {Boolean} ci - if true, search is case-insensitive
   * @return {Object} position map { line, ch } if found, null otherwise
   */
  mirrors.search_last = function(m, str, ci) {
    var mirror = mirrors.get_instance(m);
    if (!mirror || (!_.isString(str) && !_.isRegExp(str))) { return null; }

    var cur = mirror.cm.getSearchCursor(str, null, !!ci);

    var pos;
    while (cur && cur.find()) {
      pos = { from: cur.from(), to: cur.to() };
    }

    return pos || null;
  };

  /**
   * Add content to a mirror at a specific position
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String} str - content to add
   * @param {Object} pos - position map { line, ch } to insert at
   */
  mirrors.add_content_at = function(m, str, pos) {
    var mirror = mirrors.get_instance(m);
    if (!mirror || !_.isString(str)) { return; }

    mirror.cm.replaceRange(str, pos);
  };

  /**
   * Add content to a mirror as the first line(s)
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String} str - content to add
   */
  mirrors.add_content_start = function(m, str) {
    if (!_.isString(str)) { return; }
    return mirrors.add_content_at(m, str + '\n', { line: 0, ch: 0 });
  };

  /**
   * Add content to a mirror as the last line(s)
   *
   * @param {String | Object} m - panel id or mirror
   * @param {String} str - content to add
   */
  mirrors.add_content_end = function(m, str) {
    var mirror = mirrors.get_instance(m);
    if (!mirror || !_.isString(str)) { return; }

    var lastLine = mirror.cm.lastLine();
    var lastLineContent = mirror.cm.getLine(lastLine);
    var nlStr = !lastLineContent ? str : '\n' + str;

    return mirrors.add_content_at(m, nlStr, { line: lastLine });
  };

  /**
   * Trigger a real change event by inserting and then removing a character
   *
   * @param {String | Object} m - panel id or mirror
   */
  mirrors.simulate_change = function(m) {
    var mirror = mirrors.get_instance(m);
    if (!mirror) { return; }

    mirror.cm.replaceRange(' ', { line: 0, ch: 0 });
    mirror.cm.replaceRange('',  { line: 0, ch: 0 }, { line: 0, ch: 1 });
  };

  /**
   * Add a library element string at the best position that can be found
   *
   * @param {String} uri - URI of the library to be added
   */
  mirrors.add_lib_to_markup = function(uri) {
    var markup = mirrors.get_by_id('markup');
    if (!markup || !uri) { return; }

    var indent = markup.cm.getOption('indentUnit'); // default 2
    var tag = utils.resource_tag(uri);
    var lib = utils.resource_element_string(uri); // <script ...> or <link ...>
    var indentLib = _.str.sprintf('%s%s', indent, lib);

    // put the new script element after the last script element in the document
    var scriptPos = mirrors.search_last(markup, /<script [^>]*><\/script>/i);
    if (scriptPos) {
      if (tag === 'script') {
        lib = _.str.sprintf('\n%s%s', _.str.repeat(' ', scriptPos.from.ch), lib);
        return mirrors.add_content_at(markup, lib, scriptPos.to);
      }
    }

    // put the new link element after the last link element in the document
    var linkPos = mirrors.search_last(markup, /<link [^>]*>/i);
    if (linkPos) {
      if (tag === 'link') {
        lib = _.str.sprintf('\n%s%s', _.str.repeat(' ', linkPos.from.ch), lib);
        return mirrors.add_content_at(markup, lib, linkPos.to);
      }
    }

    // put the new element as the last item in <head>
    var headPos = mirrors.search_first(markup, '</head>', true);
    if (headPos) {
      lib = _.str.sprintf('%s%s\n', _.str.repeat(' ', indent), lib);
      return mirrors.add_content_at(markup, lib, headPos.from);
    }

    // put the new element as the first item in <head>
    headPos = mirrors.search_first(markup, '<head>', true);
    if (headPos) {
      lib = _.str.sprintf('\n%s%s', _.str.repeat(' ', headPos.from.ch + indent), lib);
      return mirrors.add_content_at(markup, lib, headPos.to);
    }

    // put the new element as the first item in <html>
    var htmlPos = mirrors.search_first(markup, '<html>', true);
    if (htmlPos) {
      lib = _.str.sprintf('\n%s%s', _.str.repeat(' ', htmlPos.from.ch + indent), lib);
      return mirrors.add_content_at(markup, lib, htmlPos.to);
    }

    // last resort: just prepend the entire document
    mirrors.add_content_start(markup, lib);
  };

  return mirrors;
});
