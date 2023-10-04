const express = require('express');
const app = express();
require('dotenv').config();
const { AuthMiddleware } = require('./utils/auth_middleware');
const knex = require('knex')(require('./knexfile'));

knex.migrate.latest().then(([batchNo, log]) => {
  if (!log.length) {
    console.info('Database is already up to date');
  } else {
    console.info('Ran migrations: ' + log.join(', '));
  }
}).catch(error => {
  console.error('Error running migrations:', error);
}).finally(() => {
  // Close the database connection to ensure the script can exit
  knex.destroy();
});

AuthMiddleware.initOidcStrategy()
app.use(AuthMiddleware.sessionManager);

// Home page
app.get('/', AuthMiddleware.authenticateHybrid, (req, res) => {
  res.send(`Welcome ${req.locals.user.first_name}!`);
});

// User profile
app.get('/profile', AuthMiddleware.authenticateHybrid, (req, res) => {
  res.send(`${req.locals.user.first_name}'s profile`); 
});

// Admin page
app.get('/admin', AuthMiddleware.authenticateHybrid, (req, res) => {
  if (req.locals.user.role === 'admin') {
    res.send('Admin dashboard');
  } else {
    res.status(401).send('Unauthorized');
  }
});

// Login route
app.post('/login', (req, res) => {
  // Login logic here  
  const user = {/* logged in user */};
  AuthMiddleware.newSession(user, req, res)
    .then(user => {
      res.send(`${user.first_name} is now logged in`);
    });
});

// Route for initiating OIDC authentication
app.get('/api/login/google', AuthMiddleware.oidcAuth);

// Route for handling OIDC callback
app.get('/api/oauth2/redirect', AuthMiddleware.oidcAuthCallback);

app.listen(3000,() => {
  console.log(`Server is running and listening on port 3000`);
});