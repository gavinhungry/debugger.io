/*
 * sandbug: An interactive web scripting sandbox
 *
 * bugs.js: bug actions
 */

define('bugs', function(require) {
  'use strict';

  var $      = require('jquery');
  var _      = require('underscore');
  var bus    = require('bus');
  var com    = require('com');
  var config = require('config');
  var utils  = require('utils');

  var Backbone = require('backbone');
  var flash    = require('flash');
  var frame    = require('frame');
  var keys     = require('keys');
  var locales  = require('locales');
  var mirrors  = require('mirrors');
  var popups   = require('popups');

  // ---

  var bugs = utils.module('bugs');
  bugs._priv.schema = {
    private: false
  };

  bus.init(function(av) {
    bugs._priv.current = {};

    // set all default modes in schema
    bugs._priv.schema.map = _.reduce(mirrors.get_all(), function(memo, mirror) {
      memo[mirror.panel] = {
        mode: mirrors.get_default_mode(mirror.panel),
        content: ''
      };

      return memo;
    }, {});

    bus.on('bugs:save', function() {
      bugs.save();
    });

    bus.on('bugs:delete', function() {
      bugs.delete();
    });

    bus.on('mirrors:mode', function(panel, mode, label) {
      bugs.model().set(_.str.sprintf('map.%s.mode', panel), mode);
    });

    bus.on('mirrors:content', function(panel, content) {
      // FIXME
      // bugs.model().set(_.str.sprintf('map.%s.content', panel), content);
    });

    keys.register_handler({ ctrl: true, key: 's' }, function(e) {
      bugs.save();
    });

    keys.register_handler({ ctrl: true, shift: true, key: 's' }, function(e) {
      bugs.save_as();
    });

    bus.on('bugs:title', function() {
      locales.string('untitled_bug').then(function(untitled) {
        var title = bugs.model().get('title') || untitled;
        av.$title.text(title);
      });
    });

    av.$title.on('input', function(e) {
      bugs.model().set('title', av.$title.text());
    });
  });

  /**
   *
   */
  bugs.Bug = Backbone.DeepModel.extend({
    idAttribute: 'slug',

    _url: '/api/bug/',
    url: function() {
      return this._url + this.get(this.idAttribute);
    },

    isEmpty: function() {
      return _.every(this.get('map'), function(panel) {
        return _.str.isBlank(panel.content);
      });
    },

    isNew: function() {
      return !this.has('_fetched') || (this.get('slug') !== this._lastSlug);
    },

    isWritable: function() {
      if (!this.get('slug')) {
        return utils.resolve(false);
      }

      var writableUri = _.str.sprintf('%s/writable', this.url());
      return utils.resolve_boolean($.get(writableUri));
    },

    sync: function(method, model, options) {
      if (method === 'create') {
        options.url = '/api/bugs';
      }

      return Backbone.sync.apply(this, arguments);
    }
  });

  /**
   *
   */
  bugs.BugView = Backbone.View.extend({
    render: function() {
      var map = this.model.get('map');

      _.each(map, function(value, key) {
        mirrors.set_mode(key, value.mode);
        mirrors.set_content(key, value.content);
      });

      if (this.model.get('autorun')) { _.defer(frame.update); }

      return this.trigger('render');
    }
  });

  /**
   * Get the current (or new) bug model
   *
   * @return {bugs.Bug}
   */
  bugs.model = function() {
    return {
      get: function(){}, // FIXME
      map: function(){}
    };

    if (!(bugs._priv.current.model instanceof bugs.Bug)) {
      bugs._priv.current.model = bugs.create();
    }

    return bugs._priv.current.model;
  };

  /**
   * Get the current (or new) bug view
   *
   * @return {bugs.BugView}
   */
  bugs.view = function() {
    if (!(bugs._priv.current.view instanceof bugs.BugView)) {
      bugs._priv.current.view = new bugs.BugView({
        model: bugs.model()
      });

      utils.title();
    }

    return bugs._priv.current.view;
  };

  /**
   * Display a Bug
   *
   * @param {bugs.Bug} bug
   */
  bugs.display = function(bug) {
    utils.title(bug.get('title'));

    var slug = bug.get('slug');
    bus.trigger('navigate', slug ? ('bug/' + slug) : '');

    bug._lastSlug = bug.get('slug');
    bugs._priv.current.map = utils.clone(bug.get('map'));

    if (bug === bugs.model()) {
      bus.trigger('bugs:title');
      return;
    }

    bugs._priv.current.model = bug;
    bugs._priv.current.view = new bugs.BugView({
      model: bug
    });

    _.defer(function() {
      bus.trigger('bugs:title');
      bugs._priv.current.view.render();
    });
  };

  /**
   * Get a bug from the server matching a slug
   *
   * @param {String} slug - slug id for a bug
   * @return {Promise} resolving to {bugs.Bug}
   */
  bugs.get = function(slug) {
    var bug = new bugs.Bug({ slug: slug });
    return bug.fetch().then(function() {
      return bug;
    }, function(xhr, status, err) {
      switch(xhr.statusCode().status) {
        case 403: flash.message_bad('@bug_is_private'); break;
        case 404: flash.message_bad('@bug_not_found'); break;
        default: flash.xhr_error(xhr, status, err);
      }

      bus.trigger('navigate', '/');
    });
  };

  /**
   * Get a bug from the server and display it
   *
   * @param {String} slug - slug id for a bug
   * @return {Promise}
   */
  bugs.open = function(slug) {
    return bugs.get(slug).then(bugs.display);
  };

  /**
   * Save the currently displayed bug
   *
   * @return {Promise}
   */
  bugs.save = function() {
    var model = bugs.model();
    var slug = model.get('slug');

    if (!slug) {
      return bugs.save_as();
    }

    var isNew = model.isNew();

    bugs.console.log('Saving bug', slug);
    return model.save().then(function(res) {
      _.defer(function() {
        bus.trigger('bugs:saved');
      });

      if (isNew) {
        flash.message_good('@bug_saved', locales.string('bug_saved_msg', res.slug));
      }

      bugs.display(model);
    }, function(xhr, status, err) {
      switch(xhr.statusCode().status) {
        case 400: flash.message_bad('@bug_invalid_data'); break;
        case 403: flash.message_bad('@bug_no_save_perm'); break;
        case 409: flash.message_bad('@bug_slug_in_use'); break;
        default: flash.xhr_error(xhr, status, err);
      }
    });
  };

  /**
   * Save the currently displayed bug, prompting for title
   *
   * @return {Promise}
   */
  bugs.save_as = function() {
    var model = bugs.model();

    return popups.prompt('@bug_name_pick', [
      {
        name: 'title',
        placeholder: '@bug_title',
        value: model.get('title'),
        copy_to: 'slug',
        copy_if: function() {
          return model.isNew();
        }
      }, {
        name: 'slug',
        placeholder: '@url_slug',
        value: model.get('slug'),
        filter: _.str.slugify
      }
    ]).then(function(result) {
      model.set('title', result.title);
      model.set('slug', result.slug);

      return bugs.save();
    });
  };

  /**
   * Delete the current bug
   */
  bugs.delete = function() {
    var model = bugs.model();

    if (model.isNew()) {
      return utils.reject();
    }

    bugs.model().destroy().then(function() {
      flash.message_good('@bug_deleted');
      bugs.display(bugs.create());
      com.flush();
    }, function() {
      flash.message_bad('@error_deleting_bug');
    });
  };

  /**
   * Create a new bug
   */
  bugs.create = function() {
    bugs.console.log('Creating new bug');
    return new bugs.Bug(bugs._priv.schema);
  };

  /**
   * Check if the current bug has unsaved content
   *
   * @return {Boolean} true if unsaved, false otherwise
   */
  bugs.dirty = function() {
    return false; // FIXME
    return !_.isEqual(bugs.model().get('map'), bugs._priv.current.map);
  };

  /**
   * Check if the current bug is empty
   *
   * @return {Boolean} true if empty, false otherwise
   */
  bugs.empty = function() {
    return bugs.model().isEmpty();
  };

  return bugs;
});
