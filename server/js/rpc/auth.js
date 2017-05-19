/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const auth = require('auth');

  let createUser = form => auth.create_user(form).then(user => user.username);

  return { createUser };

});
