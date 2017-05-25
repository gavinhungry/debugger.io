/*
 * sandbug: An interactive web scripting sandbox
 *
 * popup.js: template-able popup windows
 */

define(function(require) {
  'use strict';

  var $      = require('jquery');
  var _      = require('underscore');
  var bus    = require('bus');
  var config = require('config');
  var utils  = require('utils');

  var cdn       = require('cdn');
  var dom       = require('dom');
  var flash     = require('flash');
  var keys      = require('keys');
  var locales   = require('locales');
  var panels    = require('panels');
  var templates = require('templates');
  var themes    = require('themes');
  var user      = require('user');
  var rpc       = require('rpc');

  let auth = rpc.getModule('auth');

  // ---

  var popups = utils.module('popups');
  var popupEl = '#popup';
  var popupKeyHander;
  var currentView = null;

  bus.init(function(av) {
    bus.on('popup:login', function() {
      popups.popup('login');
    });
  });

  var superViewInit = function(view, args) {
    view.constructor.__super__.initialize.apply(view, args);
  };

  /**
   * Base popup Model
   *
   * @param {Boolean} small - mini style popup if true, full-sized if false
   * @param {String} title - Popup heading
   */
  popups.Popup = Backbone.Model.extend({
    defaults: {
      small: false,
      title: null
    },

    // array of promises to resolve before model is ready
    pre_ready: [],

    /**
     * Add remote data to model
     *
     * @param {Object} opts - { key: uri }, add data from uri to key on model
     */
    remote_data: function(opts) {
      var that = this;

      var opts_p = _.map(opts, function(uri, key) {
        return $.get(uri).then(function(data) {
          return that.set(key, data);
        }, function(err) {
          flash.message_bad('@server_error');
        });
      });

      this.pre_ready.push($.when.apply(null, opts_p));
    }
  });

  /**
   * Base popup View
   */
  popups.PopupView = Backbone.View.extend({
    el: popupEl,

    initialize: function(options) {
      var that = this;

      _.extend(this.events, this.subevents);
      _.extend(this, _.pick(options, 'template', 'post_render'));

      $.when.apply(null, this.model.pre_ready)
        .then(function() {
          popups.destroy().then(function() {
            that.render();
          });
        }, function() {
          that.destroy();
        });

      popupKeyHander =
        keys.register_handler({ key: 'esc' }, function(e) { that.destroy(); });
    },

    events: {
      'submit form': function(e) {
        e.preventDefault();
        this.trigger('submit', e.target);
      },

      'mousedown': function(e) {
        // only destroy the popup if the background area is clicked
        this.bg_mousedown = $(e.target).is(popupEl);
      },

      'mouseup': function(e) {
        if ($(e.target).is(popupEl) && this.bg_mousedown) { this.destroy(); }
      },

      // destroy a popup when the cancel button is pressed
      'click .popup-cancel': function(e) {
        e.preventDefault();
        this.destroy();
      }
    },

    destroy: function() {
      var d = $.Deferred();

      var that = this;
      keys.unregister_handler(popupKeyHander);

      this.undelegateEvents();
      this.$el.removeData('type');

      popups.hide().always(function() {
        dom.destroy_view(that);
        currentView = null;
        d.resolve(true);
      });

      return d.promise();
    },

    render: function() {
      currentView = this;

      var that = this;
      var data = this.model.toJSON();

      var popup_p = templates.get('popup', this);
      var content_p = templates.get(this.template, this);
      var title_p = locales.prefixed(data.title);

      return $.when(popup_p, content_p, title_p)
      .then(function(popup_fn, content_fn, title) {
        var that = _.first(utils.ensure_array(this));

        var contentHtml = content_fn({
          data: data,
          config: _.clone(config)
        });

        var popupHtml = popup_fn({
          small: !!data.small,
          title: title,
          content: contentHtml,
          name: _.str.sprintf('%s-outer', that.template)
        });

        // remove any existing popups first
        popups.hide().then(function() {
          that.$el.html(popupHtml);
          that.$el.data('type', that.template);

          locales.localize_dom_nodes(that.$el).then(function() {
            that.delegateEvents();
            popups.show().done(function() {
              if (_.isFunction(that.post_transition)) {
                that.post_transition();
              }
            });

            that.$el.find('input:not([type=hidden])').first().focus();

            if (_.isFunction(that.post_render)) { that.post_render(); }
          });
        });

        return that.trigger('render');

      }, function(err) {
        var that = _.first(utils.ensure_array(this));
        var msg = _.str.sprintf('Error rendering "%s": %s', that.template, err);
        popups.console.error(msg);
      });
    }
  });

  /**
   * Login popup
   */
  popups.LoginPopup = popups.Popup.extend({
    defaults: {
      small: true,
      title: '@login'
    }
  });

  popups.LoginPopupView = popups.PopupView.extend({
    template: 'popup-login',

    initialize: function(options) {
      superViewInit(this, arguments);

      this.on('submit', function(form) {
        var that = this;
        var $form = $(form);

        utils.submit_form($form).then(function(username) {
          bus.trigger('user:login', username);
          that.destroy();
        }, function() {
          that.show_invalid_login(); // invalid credentials
        });
      });
    },

    post_render: function() {
      dom.cache(this, this.$el, { 'by_name': ['username', 'password'] });
    },

    show_invalid_login: function() {
      this.$el.find('input[name="password"]').select();
      flash.message_bad('@invalid_creds');
    }
  });

  /**
   * Sign Up popup
   */
  popups.SignupPopup = popups.Popup.extend({
    defaults: {
      small: true,
      title: '@signup'
    }
  });

  popups.SignupPopupView = popups.PopupView.extend({
    template: 'popup-signup',

    initialize: function(options) {
      superViewInit(this, arguments);

      this.on('submit', form => {
        var $form = $(form);

        if (this.$username.val().length < 3) {
          return flash.message_bad('@invalid_username');
        }

        if (this.$email.is(':invalid') || !this.$email.val()) {
          return flash.message_bad('@invalid_email');
        }

        if (this.$password.val() !== this.$confirm.val()) {
          return flash.message_bad('@password_mismatch');
        }

        if (this.$password.val().length < 4) {
          return flash.message_bad('@invalid_password');
        }

        auth.createUser(utils.form_map(form)).then(username => {
          bus.trigger('user:login', username);
          this.destroy();
        }, err => {
          alert(err);

          //   case 400: flash.message_bad('@invalid_form'); break;
          //   case 409: flash.message_bad('@user_exists'); break;
          //   default: flash.xhr_error(xhr, status, err);
        });
      });
    },

    post_render: function() {
      dom.cache(this, this.$el, {
        'by_name': ['username', 'email', 'password', 'confirm']
      });
    }
  });

  /**
   * User settings popup
   */
  popups.SettingsPopup = popups.Popup.extend({
    defaults: {
      small: true,
      title: '@settings'
    },

    initialize: function() {
      var that = this;

      this.remote_data({
        'locales': '/api/resource/locales'
      });

      var themes_p = locales.strings(themes.get_themes())
      .then(function(themes) {
        return that.set('themes', themes);
      });

      var layouts_p = locales.strings(panels.get_layouts())
      .then(function(layouts) {
        return that.set('layouts', layouts);
      });

      this.pre_ready.push(themes_p);
      this.pre_ready.push(layouts_p);

      this.set('cdns', cdn.get_cdns());
    }
  });

  popups.SettingsPopupView = popups.PopupView.extend({
    template: 'popup-settings',

    subevents: {
      'input [name="current"]': function(e) {
        var $passwords = this.$el.find('[name="password"], [name="confirm"]');

        if ($(e.target).val()) {
          $passwords.removeAttr('disabled');
        } else {
          $passwords.attr('disabled', 'disabled');
        }
      }
    },

    initialize: function(options) {
      var that = this;
      superViewInit(this, arguments);

      this.on('submit', function(form) {
        var $form = $(form);

        if (this.$password.is(':enabled')) {
          if (this.$password.val() !== this.$confirm.val()) {
            return flash.message_bad('@password_mismatch');
          }

          if (this.$password.val().length < 8) {
            return flash.message_bad('@invalid_password');
          }
        }

        utils.submit_form($form).then(function() {
          user.get_settings().then(function() {
            that.destroy();
            flash.message_good('@settings_updated');
          });
        }, function(xhr, status, err) {
          switch(xhr.statusCode().status) {
            case 400: flash.message_bad('@invalid_settings'); break;
            case 403: flash.message_bad('@incorrect_current_password'); break;
            default: flash.xhr_error(xhr, status, err);
          }
        });
      });
    },

    post_render: function() {
      dom.cache(this, this.$el, {
        'by_name': ['password', 'confirm']
      });
    }
  });

  /**
   * Bug properties popup
   */
  popups.BugPropertiesPopup = popups.Popup.extend({
    defaults: {
      small: true,
      title: '@bug_properties'
    }
  });

  popups.BugPropertiesPopupView = popups.PopupView.extend({
    template: 'popup-bug-properties',

    subevents: {
      'click #delete_bug': function(e) {
        var that = this;

        popups.confirm('@confirm_delete_bug', '@confirm_delete_bug_body').then(function() {
          this.destroy();
          bus.trigger('bugs:delete');
        });
      }
    },

    initialize: function(options) {
      var that = this;
      var args = _.toArray(arguments);

      var extras = this.model.get('extras');
      var bug = extras.bug;

      bug.isWritable().then(function(writable) {
        extras.writable = writable;
        superViewInit(that, args);
      });

      this.on('submit', function(form) {

        var map = utils.form_map(form);
        map.private = !!map.private;

        var save = function() {
          bug.set(map);
          bus.trigger('bugs:save');
        };

        if (!bug.get('private') && map.private && !config.username && !bug.get('username')) {
          popups.confirm('@confirm_private', '@confirm_private_body').then(function() {
            save();
            this.destroy();
          });
        } else {
          save();
          this.destroy();
        }
      });
    },

    post_render: function() {
      this.$el.find('input[type="text"]').first().select();
    }
  });

  /**
   * User prompt
   */
  popups.InputPopup = popups.Popup.extend({
    defaults: {
      small: true,
      title: '@input'
    }
  });

  popups.InputPopupView = popups.PopupView.extend({
    template: 'popup-input',

    initialize: function(options) {
      var that = this;
      var args = _.toArray(arguments);

      this.extras = utils.ensure_array(this.model.get('extras'));

      var placeholder_p = _.map(this.extras, function(extra) {
        return locales.prefixed(extra.placeholder).then(function(placeholder) {
          extra.placeholder = placeholder;
        });
      });

      $.when.apply(null, placeholder_p).done(function() {
        superViewInit(that, args);
      });

      this.on('submit', function(form) {
        this.destroy();
      });
    },

    post_render: function() {
      var that = this;

      _.each(this.extras, function(extra, i) {
        var $input = that.$el.find(_.str.sprintf("input[name='%s']", extra.name));

        if (i === 0) {
          $input.select();
        }

        $input.on('input input-filter', function(e, no_copy) {
          var $this = $(this);
          var filtering = (e.type === 'input-filter');

          // mark manually updated inputs
          if ($this.is(':focus')) { $this.data('touched', true); }

          if (_.isFunction(extra.filter)) {
            var start = this.selectionStart, end = this.selectionEnd;

            var val = extra.filter($this.val());
            $this.val(val);

            if (!filtering) { this.setSelectionRange(start, end); }
          }

          if (extra.copy_to && _.isFunction(extra.copy_if) && extra.copy_if()) {
            var $dest = that.$el.find(_.str.sprintf("input[name='%s']", extra.copy_to));
            if (!$dest.val()) { $dest.data('touched', false); }
            if (!$dest.data('touched') && (!no_copy || !$dest.val())) {
              $dest.val($input.val()).trigger('input-filter');
            }
          }
        }).trigger('input-filter', true); // filter existing values right away
      });
    }
  });

  /**
   * Confirmation popup
   */
  popups.ConfirmPopup = popups.Popup.extend({
    defaults: {
      small: true,
      title: '@confirm'
    }
  });

  popups.ConfirmPopupView = popups.PopupView.extend({
    template: 'popup-confirm',

    initialize: function(options) {
      superViewInit(this, arguments);
    }
  });

  /**
   * Build a popup and show it right away
   *
   * @param {String} name - name of the popup template to use
   * @param {String} [title] - locale key to use as popup title
   * @param {Object} [extras] - optional data to pass to template
   * @return {Promise} to resolve to a map of the submitted form
   */
  popups.popup = function(name, title, extras) {
    var d = $.Deferred();

    if (!_.isString(title) && _.isUndefined(extras)) {
      extras = title;
      title = null;
    }

    var modelName = _.str.sprintf('%sPopup', _.str.capitalize(_.str.camelize(name)));
    var viewName = _.str.sprintf('%sView', modelName);

    var ModelConstructor = popups[modelName];
    var ViewConstructor = popups[viewName];

    if (!ModelConstructor || !ViewConstructor) {
      popups.console.error(_.str.sprintf('popups.%s or popups.%s not found', modelName, viewName));
      return utils.reject();
    }

    var model = new ModelConstructor();
    if (title) {
      model.set('title', title);
    }

    model.set('extras', extras);

    var view = new ViewConstructor({ model: model });

    view.on('destroy', d.reject);

    view.on('submit', function(form) {
      var map = utils.form_map(form);

      _.each(_.keys(map), function(prop) {
        if (_.first(prop) === '_') { delete map[prop]; }
      });

      d.resolveWith(view, [map]);
    });

    return d.promise();
  };

  /**
   * Show the currently assigned popup
   *
   * @return {Promise} resolves after showing, or rejects on failure
   */
  popups.show = function() {
    var $popup = $(popupEl);
    if (!$popup.length || $popup.is(':empty')) {
      return utils.reject();
    }

    $popup.removeClass('nopointer');
    $popup.css({ 'display': 'block' });

    var $inner = $popup.find('.popup');
    var $wrap = $popup.find('.popup-wrap');
    var $bar = $popup.find('.popup-actionbar');
    var offset = $bar.offset().top - ($wrap.offset().top + $wrap.outerHeight());
    $wrap.css('margin-bottom', _.str.sprintf('-%spx', offset));

    return dom.multi_transition([
      { el: $popup, args: { 'opacity': 1 } },
      { el: $inner, args: { 'margin-top': '1em' } }
    ]);
  };

  /**
   * Hide the currently visible popup
   *
   * @return {Promise} resolves after hiding, or rejects on failure
   */
  popups.hide = function() {
    var d = $.Deferred();

    var $popup = $(popupEl);
    if (!$popup.length) {
      return utils.reject();
    }

    // popup is already hidden, don't wait to resolve
    if ($popup.css('opacity') === '0') {
      return utils.resolve();
    }

    $popup.addClass('nopointer');

    var $inner = $popup.find('.popup');

    return dom.multi_transition([
      { el: $popup, args: { 'opacity': 0 } },
      { el: $inner, args: { 'margin-top': 0 } }
    ]).then(function() {
      $popup.css({ 'display': 'none' });
    });
  };

  /**
   * Destroy the currently visible popup(s)
   *
   * @param {String} [type]
   * @return {Promise}
   */
  popups.destroy = function(type) {
    if (!(currentView instanceof popups.PopupView)) {
      return utils.resolve(true);
    }

    if (!type || (type === currentView.$el.data('type'))) {
      return currentView.destroy();
    }
  };

  /**
   * User prompt using input popup
   *
   * @param {String} title - locale key to use as popup title
   * @param {Object|Array} - inputs, or an array of inputs
   * @return {Promise}
   */
  popups.prompt = function(title, inputs) {
    return popups.popup('input', title, utils.ensure_array(inputs));
  };

  /**
   * Prompt for user confirmation
   *
   * @param {String} title - locale key to use as popup title
   * @param {String} body - locale key to use as popup body
   * @return {Promise}
   */
  popups.confirm = function(title, body) {
    return locales.prefixed(body).then(function(bodyStr) {
      return popups.popup('confirm', title, {
        body: bodyStr,
        affirmClass: 'warning light'
      });
    });
  };

  return popups;
});
