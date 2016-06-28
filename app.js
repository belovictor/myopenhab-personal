/*
  my.openHAB personal edition
 */

var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var morgan = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var router = express.Router();
var basicAuth = require('basic-auth');

var logger = require('./logger');

var app = express();

// Socket.io

var socket_io = require('socket.io');
var io = socket_io();
app.io = io;

/*
  Load configuration from config.json
 */
var config = require('./config.json');
/*
  Load list of users
 */
var users = require('./users.json');

// Global vars
// a var to hold current online/offline status of openHAB
var openHABStatus = 'offline';
// a var to issue request ids
var requestCounter = 1;
// an array to hold active requests (technically it holds response objects)
var activeRequests = {};

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
// app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
// uncomment this line if you want to debug requests
// app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
// Uncomment this line if you want to serve local static files
// app.use(express.static(path.join(__dirname, 'public')));

/*
  Route all requests we receive first to authentication, then to preassmble request body,
  then proxy it to openHAB
 */

router.all('/*', authenticateRequest, preassembleBody, proxyRouteOpenhab);

/*
  We process all requests from root
 */

app.use('/', router);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

/*
  This function authenticates request against a list of users from users.json
 */

function authenticateRequest(req, res, next) {
  // if my.openHAB level auth is switched off in config, no authentication is needed
  if (!config.enableAuth) {
    return next();
  }

  function unauthorized(res) {
    res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
    return res.send(401);
  };
  // Get credentials from request
  var user = basicAuth(req);
  // Check if there are any credentials, if not - deny
  if (!user || !user.name || !user.pass) {
    return unauthorized(res);
  };
  // Authenticate user
  if (authenticateUser(user.name, user.pass)) {
    return next();
  } else {
    return unauthorized(res);
  };
};

/*
  This function authenticates user against users.json
 */

function authenticateUser(username, password) {
  for (var i = 0; i < users.length; i++) {
    if (username == users[i].username && password == users[i].password) {
      return true;
    }
  }
  return false;
}

/*
  This function preassembles request body for further forwarding it to openHAB
  The downside of this approach is we are putting the whole request body into the RAM
  On the other side we do not expect huge request bodies when talking to openHAB as
  they are typically used to send commands to items
 */

function preassembleBody(req, res, next) {
  var data = '';
  req.on('data', function(chunk) {
    data += chunk;
  });
  req.on('end', function() {
    req.rawBody = data;
    next();
  });
}

/*
  This function proxy routes request to openHAB through socket.io connection event
 */

function proxyRouteOpenhab(req, res) {
  // Set maximum timeout for long polling requests to work
  req.connection.setTimeout(600000);
  // Check if openHAB is online, respond with 500 if not
  if (openHABStatus == 'offline') {
    res.writeHead(500, 'openHAB is offline', {'content-type': 'text/plain'});
    res.end('openHAB is offline');
    return;
  }
  // Increment request counter. As node is single threaded this is atomic
  requestCounter++;
  var requestId = requestCounter;
  // make a local copy of request headers to modify
  var requestHeaders =  req.headers;
  // get remote hose from either x-forwarded-for or request
  var remoteHost = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  // We need to remove and modify some headers here
  requestHeaders['host'] = req.headers.host || config.hostname;
  requestHeaders['user-agent'] = "openhab-cloud-personal/0.0.1";
  io.sockets.in(config.uuid).emit('request', {id:requestId, method: req.method,
    headers: requestHeaders, path:req.path, query: req.query, body: req.rawBody});
  activeRequests[requestId] = res;
  res.on('close', function() {
    io.sockets.in(config.uuid).emit('cancel', {id:requestId});
    delete activeRequests[requestId];
  });
}

/*
  Authenticate incoming socket.io connections and set everything up
 */

io.use(function(socket, next) {
  var handshakeData = socket.handshake;
  logger.info("Authorizing incoming openHAB connection");
  handshakeData.uuid = handshakeData.query['uuid'];
  handshakeData.openhabVersion = handshakeData.query['openhabversion'];
  handshakeData.myohVersion = handshakeData.query['myohversion'];
  handshakeSecret = handshakeData.query['secret'];
  if (!handshakeData.uuid) {
    handshakeData.uuid = handshakeData.headers['uuid'];
    handshakeSecret = handshakeData.headers['secret'];
    handshakeData.openhabVersion = handshakeData.headers['openhabversion'];
    handshakeData.myohVersion = handshakeData.headers['myohversion'];
  }
  if (handshakeData.uuid && handshakeSecret){
    if (handshakeData.uuid == config.uuid && handshakeSecret == config.secret) {
      logger.info('Successfully authorized openHAB ' + handshakeData.uuid);
      next();
    } else {
      logger.error('Error authenticating socket.io connection - incorrect uuid or secret');
      next(new Error('Authentication error'));
    }
  } else {
    logger.error('Error authenticating socket.io connection - no credentials');
    next(new Error('Authentication error'));
  }
  return;
});

/*
  Process new authenticated connection and set it's event handlers
 */

io.sockets.on('connection',function(socket){
  logger.info('openHAB ' + socket.handshake.uuid + ' connected');
  socket.join(socket.handshake.uuid);
  openHABStatus = 'online';

  /*
    responseHeader event is received from openHAB when response header for our request is received
    Forward it into corresponding response object from request array
   */

  socket.on('responseHeader', function(data) {
    var self = this;
    var requestId = data.id;
    // Check if we have this request active
    if (activeRequests[requestId] != null) {
      activeRequests[requestId].writeHead(data.responseStatusCode, data.responseStatusText, data.headers);
    } else {
      self.emit('cancel', {id: requestId});
    }
  });

  /*
    responseContentBinary event is received for every chunk of request response content from openHAB
    Forward this content into corresponding response object from request array
   */

  socket.on('responseContentBinary', function(data) {
    var self = this;
    var requestId = data.id;
    // Check if we have this request active
    if (activeRequests[requestId] != null) {
      activeRequests[requestId].write(data.body);
    } else {
      self.emit('cancel', {id: requestId});
    }
  });

  /*
    responseFinished event is received when request is finished
    Finish the corresponding response from request array and delete it
   */

  socket.on('responseFinished', function(data) {
    var self = this;
    var requestId = data.id;
    if (activeRequests[requestId] != null) {
      activeRequests[requestId].end();
      delete activeRequests[requestId];
    } else {
      self.emit('cancel', {id: requestId});
    }
  });

  /*
    responseError event is received if an error occures while my.openHAB bundle tries to process request
    Send the error into corresponding response from request array and delete it
   */

  socket.on('responseError', function(data) {
    var self = this;
    var requestId = data.id;
    if (activeRequests[requestId] != null) {
      activeRequests[requestId].send(500, data.responseStatusText);
      delete activeRequests[requestId];
    }
  });

  /*
    This events are used for sending notifications, not supported in personal edition
   */

  socket.on('notification', function(data) {
    logger.warn('Personal edition has no support for notifications');
  });

  socket.on('broadcastnotification', function(data) {
    logger.warn('Personal edition has no support for notifications');
  });

  socket.on('lognotification', function(data) {
    logger.warn('Personal edition has no support for notifications');
  });

  /*
    This event is used to send SMS, not supported in personal edition
   */

  socket.on('sms', function(data) {
    logger.warn('Personal edition has no support for sms');
  });

  /*
    This event is used to send persistence data from openHAB, not supported in personal edition
   */

  socket.on('itemupdate', function(data) {
    logger.warn('Personal edition has no support for persistence');
  });

  /*
    Socket.io disconnect event. Means openHAB disconnected for some reason.
   */

  socket.on('disconnect', function() {
    logger.info('openHAB ' + socket.handshake.uuid + ' disconnected');
    openHABStatus = 'offline';
  });

});

module.exports = app;
