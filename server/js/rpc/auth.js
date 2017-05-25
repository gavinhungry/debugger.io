/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const auth = require('auth');

  let createUser = req => {
    return auth.createUser(req.username, req.email, req.password, req.confirm).then(user => {
      return user.username;
    });
  };

  let authenticateUser = req => {
    return auth.getAuthenticatedUser(req.login, req.password).then(user => user.username);
  };

  return { createUser, authenticateUser };

});
