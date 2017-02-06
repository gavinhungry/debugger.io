/**
 * sandbug: An interactive web scripting sandbox
 * https://github.com/gavinhungry/sandbug
 *
 * Copyright (C) 2013 - 2016 Gavin Lloyd <gavinhungry@gmail.com>
 * This is free software distributed under the terms of the MIT license
 */

(function() {
  'use strict';

  requirejs.config({
    baseUrl: '/src/js',

    //>> excludeStart('bustCache', pragmas.bustCache);
    urlArgs: 'v=' + (Date.now()),
    //>> excludeEnd('bustCache');

    paths: {
      promise: 'plugins/requirejs-promise',
      proximal: '//cdn.rawgit.com/gavinhungry/proximal/1.0.1/proximal',

      // libraries
      jqueryjs: '//cdn.jsdelivr.net/jquery/3.1/jquery.min',
      underscorejs: '//cdn.jsdelivr.net/underscorejs/1.8/underscore-min',
      backbonejs: '//cdn.jsdelivr.net/backbonejs/1.3/backbone-min',
      codemirrorjs: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/codemirror.min',
      hammer: '//cdn.jsdelivr.net/hammerjs/2.0/hammer.min',

      // plugins
      ui: '//cdn.jsdelivr.net/jquery.ui/1.11/jquery-ui.min',
      touchpunch: '//cdn.jsdelivr.net/jquery.ui.touch-punch/0.2/jquery.ui.touch-punch.min',
      transit: '//cdn.jsdelivr.net/jquery.transit/0.9/jquery.transit.min',
      cookie: '//cdn.jsdelivr.net/jquery.cookie/1.4.1/jquery.cookie.min',
      storage: '//cdn.jsdelivr.net/jquery.storage-api/1.7.2/jquery.storageapi.min',

      string: '//cdn.jsdelivr.net/underscore.string/3.3/underscore.string.min',
      inflection: '//cdn.jsdelivr.net/underscore.inflection/1.0/underscore.inflection.min',
      objmap: 'plugins/_.objMapFunctions.amd',
      deepclone: 'plugins/underscore.deepclone',
      deepmodel: '//cdn.jsdelivr.net/backbone.deepmodel/0.10/deep-model.min',

      platform: '//cdnjs.cloudflare.com/ajax/libs/platform/1.3.1/platform.min',
      screenfull: '//cdnjs.cloudflare.com/ajax/libs/screenfull.js/3.0.2/screenfull.min',

      cm_meta: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/meta.min',
      cm_overlay: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/addon/mode/overlay.min',
      cm_search: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/addon/search/searchcursor.min',
      cm_scrollbars: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/addon/scroll/simplescrollbars.min',

      // CodeMirror markup
      cm_xml: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/xml/xml.min',
      cm_html: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/htmlmixed/htmlmixed.min',
      cm_markdown: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/markdown/markdown.min',
      cm_gfm: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/gfm/gfm.min',
      cm_ruby: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/ruby/ruby.min',
      cm_haml: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/haml/haml.min',

      // CodeMirror style
      cm_css: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/css/css.min',

      // CodeMirror script
      cm_js: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/javascript/javascript.min',
      cm_coffeescript: '//cdnjs.cloudflare.com/ajax/libs/codemirror/5.20.2/mode/coffeescript/coffeescript.min',

      jquery: 'libs/jquery',
      underscore: 'libs/underscore',
      backbone: 'libs/backbone',
      codemirror: 'libs/codemirror'
    },

    map: {
      '*': {
        '../lib/codemirror': 'codemirrorjs',
        '../../lib/codemirror': 'codemirrorjs',
        '../../addon/mode/overlay': 'cm_overlay',
        '../search/search': 'cm_search',
        '../xml/xml': 'cm_xml',
        '../htmlmixed/htmlmixed': 'cm_html',
        '../markdown/markdown': 'cm_markdown',
        '../gfm/gfm': 'cm_gfm',
        '../ruby/ruby': 'cm_ruby',
        '../haml/haml': 'cm_haml',
        '../css/css': 'cm_css',
        '../javascript/javascript': 'cm_js',
        '../coffeescript/coffeescript': 'cm_coffeescript'
      },

      cm_markdown: {
        '../meta': 'cm_meta',
      },

      ui: {
        jquery: 'jqueryjs'
      },

      cookie: {
        jquery: 'jqueryjs'
      },

      objmap: {
        underscore: 'underscorejs'
      },

      deepclone: {
        underscore: 'underscorejs'
      },

      deepmodel: {
        underscore: 'underscorejs',
        backbone: 'backbonejs'
      },

      transit: {
        jquery: 'jqueryjs'
      }
    },

    shim: {
      // libraries
      jqueryjs: { exports: '$' },
      underscorejs: { exports: '_' },
      backbonejs: { deps: ['jqueryjs', 'underscorejs'], exports: 'Backbone' },
      codemirrorjs: { exports: 'CodeMirror' },

      // plugins
      ui: { deps: ['jqueryjs'], exports: '$.ui' },
      touchpunch: { deps: ['jqueryjs', 'ui'] },
      transit: { deps: ['jqueryjs'], exports: '$.transit' },
      cookie: { deps: ['jqueryjs'] },
      storage: { deps: ['jqueryjs', 'cookie'] },
      hammer: { deps: ['jqueryjs'] },

      string: { deps: ['underscorejs'], exports: '_.str' },
      inflection: { deps: ['underscorejs'] },
      objmap: { deps: ['underscorejs'] },
      deepclone: { deps: ['underscorejs'] },
      deepmodel: { deps: ['underscorejs', 'deepclone', 'backbonejs'] },

      screenfull: { exports: 'screenfull' },

      cm_scrollbars: { deps: ['codemirrorjs'] },
      cm_overlay: { deps: ['codemirrorjs'] },
      cm_search: { deps: ['codemirrorjs'] },
      cm_xml: { deps: ['codemirrorjs'] },
      cm_html: { deps: ['codemirrorjs'] },
      cm_markdown: { deps: ['codemirrorjs', 'cm_meta'] },
      cm_gfm: { deps: ['codemirrorjs', 'cm_overlay', 'cm_markdown'] },
      cm_ruby: { deps: ['codemirrorjs'] },
      cm_haml: { deps: ['codemirrorjs', 'cm_ruby'] },
      cm_css: { deps: ['codemirrorjs'] },
      cm_js: { deps: ['codemirrorjs'] },
      cm_coffeescript: { deps: ['codemirrorjs'] }
    }
  });

})();
