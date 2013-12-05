/*
 * debugger.io: An interactive web scripting sandbox
 */

define([
  'module', 'path', 'config', 'utils', 'us', 'q',
  'auth', 'cdn', 'consolidate', 'express', './frame'
],
function(
  module, path, config, utils, _, Q,
  auth, cdn, cons, express, frame
) {
  'use strict';

  var __dirname = path.dirname(module.uri);
  var app = {};

  // Express server
  var server = express();
  app.port = config.ports.server;

  auth.init(server);

  app.init = function() {
    server.listen(app.port);
    frame.start();
  };

  // use Underscore templates
  server.engine('html', cons.underscore);
  server.set('view engine', 'html');
  server.set('views', __dirname + '/templates');

  server.get('/', function(req, res) {
    var user = req.user || {};
    res.render('index');

    // { username: auth.sanitize_username(user.username) }
  });

  // GET /cdn - list of CDN packages
  server.get('/cdn', function(req, res) {
    cdn.get_cache().done(function(packages) {
      res.json(packages);
    });
  });

  // POST /login
  server.post('/login', auth.authenticate, function(req, res) {
    res.redirect('/');
  });

  return app;
});
