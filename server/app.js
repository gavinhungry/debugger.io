/*
 * sandbug: An interactive web scripting sandbox
 */

define(require => {
  'use strict';

  const _ = require('underscore');
  const bodyParser = require('body-parser');
  const cons = require('consolidate');
  const express = require('express');
  const mobile = require('connect-mobile-detection');
  const proximal = require('proximal');

  const auth = require('auth');
  const config = require('config');
  const utils = require('utils');

  const module = require('module');
  const path = require('path');
  const __dirname = path.dirname(module.uri);

  let app = {};
  let api = express();

  api.use(bodyParser.json());
  api.use(bodyParser.urlencoded({ extended: true }));

  api.use(mobile());
  api.engine('html', cons.underscore);
  api.set('view engine', 'html');
  api.set('views', __dirname + '/templates');

  api.get('/', (req, res) => {
    let user = req.user || {};

    res.render('index', {
      prod: config.prod,
      rev: config.build.rev,
      username: auth.cleanUsername(user.username),
      mode: { mobile: !!req.mobile, phone: !!req.phone, tablet: !!req.tablet },
      themes: config.themes
    });
  });

  let rpc = new proximal.Server({
    modules: {
      config: require('rpc/config'),
      locales: require('rpc/locales'),
      auth: require('rpc/auth')
    }
  });

  api.post('/rpc', rpc.middleware());

  app.port = config.server.port;
  app.init = () => api.listen(app.port);

  return app;
});
