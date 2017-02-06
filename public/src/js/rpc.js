/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const config = require('config');
  const utils = require('utils');

  return utils.module('rpc', config._priv.rpc);
});
