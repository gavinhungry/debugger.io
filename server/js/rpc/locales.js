/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const _ = require('underscore');
  const utils = require('utils');

  let _getAllLocales = () => utils.dir_json('./public/locales');

  let getLocales = () => _getAllLocales().then(locales => _.mapObject(locales, 'locale'));
  let getLocale = id => _getAllLocales().then(locales => locales[id]);

  return { getLocales, getLocale };

});
