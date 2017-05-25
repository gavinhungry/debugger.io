/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const auth = require('auth');

  let signUp = form => auth.createUser(form).then(user => {
    return user.username;
  });

  return { signUp };

});
