/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const auth = require('auth');

  let _authenticatedUserResponse = user => {
    return auth.genToken({
      username: user.username
    }).then(token => {
      return {
        token,
        user: {
          username: user.username,
          email: user.email,
          settings: user.settings
        }
      }
    });
  };

  let createUser = form => auth.createUser(form.username, form.email, form.password, form.confirm)
    .then(_authenticatedUserResponse);

  let authenticateUser = form => auth.getAuthenticatedUser(form.login, form.password)
    .then(_authenticatedUserResponse);

  let authenticateToken = token => auth.authenticateToken(token)
    .then(payload => auth.getUnauthenticatedUser(payload.username))
    .then(_authenticatedUserResponse);

  return { createUser, authenticateUser, authenticateToken };

});
