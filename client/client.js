/*
 * jsbyte: An interactive JS/HTML/CSS environment
 */

(function() {
  'use strict';
  var CDNJS = '//cdnjs.cloudflare.com/ajax/libs';

  requirejs.config({
    baseUrl: '/js',
    urlArgs: 'v=' + (new Date()).getTime(),

    paths: {
      // libraries
      jqueryjs: CDNJS + '/jquery/2.0.3/jquery.min',
      underscorejs: CDNJS + '/underscore.js/1.5.1/underscore-min',
      backbonejs: CDNJS + '/backbone.js/1.0.0/backbone-min',

      // plugins
      transit: CDNJS + '/jquery.transit/0.9.9/jquery.transit.min',
      string: CDNJS + '/underscore.string/2.3.3/underscore.string.min',

      // libraries with plugins
      jquery: 'lib/jquery',
      underscore: 'lib/underscore',
      backbone: 'lib/backbone'
    },

    shim: {
      // libraries
      jqueryjs: { exports: '$' },
      underscorejs: { exports: '_' },
      backbonejs: { deps: ['jqueryjs', 'underscorejs'], exports: 'Backbone' },

      // plugins
      transit: { deps: ['jqueryjs'], exports: '$.transit' },
      string: { deps: ['underscorejs'], exports: '_.str' }
    }
  });

  require(['jquery', 'app'],
  function($, JSByte) {
    'use strict';

    $(function() {
      var jsbyte = new JSByte.App();
    });

  });
})();
