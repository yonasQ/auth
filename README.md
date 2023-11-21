# AuthMiddleware

This repository contains an authentication middleware module (`AuthMiddleware`) implemented in Node.js using various libraries such as `bcrypt`, `knex`, `jsonwebtoken`, `express-session`, `uuid`, `connect-session-knex`, `passport-google-oidc`, and a custom `logger`.

## Features
- **Session Management**: Utilizes `express-session` for session management with rolling sessions and a Knex-based session store.
- **JWT Authentication**: Implements JSON Web Token (JWT) authentication for access tokens with configurable expiration times.
- **Bearer Token Authentication**: Supports bearer token authentication with the option for passthrough (allowing non-authenticated requests to proceed).
- **Google OIDC Integration**: Includes an OpenID Connect (OIDC) strategy for Google authentication using Passport.

## Usage
1. **Installation**: Install the required dependencies by running `npm install`.

2. **Configuration**: Set up your environment variables, including JWT secret, Google OAuth credentials, and other configuration options.

3. **Session Initialization**: Initialize the session manager with the provided settings.

```javascript
const {AuthMiddleware} = require('path/to/AuthMiddleware');
AuthMiddleware.sessionManager; // Use this as middleware in your Express app
```
## Authentication Methods:

- **`AuthMiddleware.authenticateHybrid`**: Authenticates requests using either JWT or session.
- **`AuthMiddleware.authenticateBearerWithoutPassthrough`**: Authenticates requests using only bearer token without passthrough.
- **`AuthMiddleware.authenticateBearerWithPassthrough`**: Authenticates requests using only bearer token with passthrough.
- **`AuthMiddleware.initOidcStrategy`**: Initializes the Google OIDC strategy for Passport.
- **`AuthMiddleware.oidcAuth`**: Initiates the Google OIDC authentication process.
- **`AuthMiddleware.oidcAuthCallback`**: Handles the callback from Google OIDC authentication.

## Google OIDC Authentication Flow:

1. Initialize the OIDC strategy using `AuthMiddleware.initOidcStrategy()`.
2. Use `AuthMiddleware.oidcAuth` to initiate authentication.
3. Handle the callback with `AuthMiddleware.oidcAuthCallback`.
