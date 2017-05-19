/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const config = require('config');

  let getConfig = () => config.client;

  return { getConfig };

});
