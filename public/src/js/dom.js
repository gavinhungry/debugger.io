/*
 * debugger.io: An interactive web scripting sandbox
 *
 * dom.js: DOM helpers
 */

define([
  'config', 'utils', 'jquery', 'underscore',
  'backbone', 'bus'
],
function(config, utils, $, _, Backbone, bus) {
  'use strict';

  var dom = utils.module('dom');

  bus.init(function(av) {
    utils.log('init dom module');

    var $blank = $('#blank');
    var $button = $('<button></button>');
    $blank.empty().append($button);

    $('body').toggleClass('alt', !!$button.width());
    $blank.empty();
  });

  /**
   * Cache DOM elements by id and class name onto another object
   *
   * @param {Object} context - object to save references to
   * @param {jQuery} $source - source set within which to find elements
   * @param {Object} elements - { 'by_id' => Array, 'by_class' => Array }
   * @return {Object} context used
   */
  dom.cache = function(context, $source, elements) {
    context = context || {};

    // #output cached to this.$output
    _.each(utils.ensure_array(elements.by_id), _.bind(function(id) {
      this['$' + _.underscored(id)] = $source.find('#' + id);
    }, context));

    // .panel-options elements cached to this.$panel_options
    _.each(utils.ensure_array(elements.by_class), _.bind(function(c) {
      this['$' + _.pluralize(_.underscored(c))] = $source.find('.' + c);
    }, context));

    // '[name="username"]' cached to this.$username
    _.each(utils.ensure_array(elements.by_name), _.bind(function(n) {
      this['$' + _.underscored(n)] = $source.find(_.sprintf('[name="%s"]', n));
    }, context));

    return context;
  };

  /**
   * Stop listening to events on a Backbone View, but empty it instead of
   * removing it, as View.remove would do
   *
   * @param {Backbone.View} view - view to destroy
   */
  dom.destroy_view = function(view) {
    if (!(view instanceof Backbone.View)) { return; }
    utils.log('destroying view:', view.template);

    view.trigger('destroy');
    view.$el.empty();
    view.stopListening();
    view.undelegateEvents();
    bus.off_for(view);
  };

  /**
   * Get a *rounded* approximation of the width of an element, as a percentage
   *
   * @param {jQuery} $element - some element in the DOM
   * @return {String} percentage string
   */
  dom.get_percent_width = function($element) {
    var width = $element.width();
    var parentWidth = $element.parent().width();
    return Math.round((width / parentWidth) * 100) + '%';
  };

  /**
   * Get a *rounded* approximation of the height of an element, as a percentage
   *
   * @param {jQuery} $element - some element in the DOM
   * @return {String} percentage string
   */
  dom.get_percent_height = function($element) {
    var height = $element.height();
    var parentHeight = $element.parent().height();
    return Math.round((height / parentHeight) * 100) + '%';
  };

  /**
   * Determine is a node is currently detached from the DOM
   *
   * @param {jQuery} $element - some element which may or may not be in the DOM
   * @param {Document} [doc] - document to check, defaults to window.document
   * @return {Boolean} true if $element is not in the DOM, false otherwise
   */
  dom.is_detached = function($element, doc) {
    doc = doc || window.document;
    var docEl = doc.documentElement;

    return !$element.closest(docEl).length;
  };

  /**
   * (Re)initialize an element with a nanoScrollerJS scrollbar
   *
   * @param {jQuery} $element - some .nano element in the DOM
   */
  dom.init_scrollbar = function($element) {
    if (!$element.hasClass('nano')) {
      return console.error($element, 'already has scrollbar');
    }

    if (!$element.children('.content').length) {
      return console.error($element, 'has no content to scroll');
    }

    // remove the old nanoscroller property if the content has been replaced
    if ($element[0].nanoscroller) {
      var $nanoContent = $element[0].nanoscroller.$content;
      if (dom.is_detached($nanoContent)) {
        $element.removeClass('has-scrollbar');
        $element[0].nanoscroller = null;
      }
    }

    $element.nanoScroller({ alwaysVisible: true });
  };

  /**
   * Transition an element, then (re)initialize a nanoScrollerJS scrollbar
   *
   * @param {jQuery} $element - some .nano element in the DOM
   * @param {Object} [opts] - options to $.fn.transition
   * @param {Function} [callback] - callback to $.fn.transition
   */
  dom.transition_with_scrollbar = function($element, opts, callback) {
      opts = opts || {};

      $element.transition(opts, 'fast', function() {
        dom.init_scrollbar($element);
        _.isFunction(callback) && callback.call($element[0]);
      });
  };

  /**
   * Determine if an element is overflowing itself or a parent
   *
   * @param {jQuery} $element - some element in the DOM
   * @param {String} [closest] - compare $element to $element.closest(closest)
   * @return {Boolean} true if $element is overflowing, false otherwise
   */
  dom.is_overflowing = function($element, closest) {
    var $compare = closest ? $element.closest(closest) : $element;
    return $element[0].scrollHeight > $compare[0].offsetHeight;
  };

  /**
   * Determine if a nanoScrollerJS content area is overflowing
   *
   * @param {jQuery} $element - some element within a nanoScrollerJS scrollbar
   * @return {Boolean} true if $element is overflowing, false otherwise
   */
  dom.is_overflowing_with_scrollbar = function($element) {
    return dom.is_overflowing($element, '.nano');
  };

  /**
   * Get a CSS property from an enabled stylesheet
   *
   * @param {String} selector - CSS selector
   * @return {Object} CSS property map matching selector
   */
  dom.css = function(selector) {
    var match;
    selector = utils.minify_css_selector(selector);

    // start with the last stylesheet
    var stylesheets = _.toArray(document.styleSheets).reverse();

    _.every(stylesheets, function(stylesheet) {
      // ignore disabled stylesheets
      if (stylesheet.disabled) { return true; } // continue

      var rules = stylesheet.cssRules || stylesheet.rules || [];
      match = _.find(rules, function(rule) {
        // find matching minified selector
        return utils.minify_css_selector(rule.selectorText) === selector;
      });

      return !match;
    });

    // always return an object
    if (!match) { return {}; }

    // remove selector and braces, leaving only the CSS properties
    var rule = match.cssText.replace(/^.*{\s*/, '').replace(/\s*}\s*$/, '');

    // convert the property string to an object
    return _.object(_.map(rule.split(';'), function(property) {
      var map = _.map(property.split(':'), _.clean);
      return map.length === 2 ? map : null;
    }));
  };

  /**
   * Scroll a nanoScrollerJS container to a specified scrollTop
   *
   * @param {jQuery} $element - some element within a nanoScrollerJS scrollbar
   * @param {Number | String} [value] - position to scroll to, defaults to 'top'
   */
  dom.scrollbar_scroll_top = function($element, value) {
    var $nano = $element.closest('.nano');
    if (!$nano.length) { return; }

    value = value || 'top';
    $nano.nanoScroller({ scrollTop: value });
  };

  return dom;
});
