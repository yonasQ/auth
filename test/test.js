const assert = require('assert');
const request = require('supertest');
const express = require('express');
require('dotenv').config();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oidc');
const { AuthMiddleware } = require('../utils/auth_middleware');

const app = express();
app.use(AuthMiddleware.sessionManager);

// Mock the passport strategy
passport.use('google', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/oauth2/redirect',
},
    async function verify(issuer, profile, cb) {
        try {
            // Mock user data based on the Google profile
            const user = {
                email: profile.emails[0].value,
                first_name: profile.name.givenName,
                last_name: profile.name.familyName,
            };

            // Mock access token
            const accessToken = 'mockAccessToken';

            return cb(null, { user, accessToken });
        } catch (error) {
            return cb(error);
        }
    }));

app.use(passport.initialize());
AuthMiddleware.initOidcStrategy();

// Route for initiating OIDC authentication
app.get('/api/login/google', AuthMiddleware.oidcAuth);

// Route for handling OIDC callback
app.get('/api/oauth2/redirect', AuthMiddleware.oidcAuthCallback);

describe('OIDC Authentication', () => {
    it('should redirect to Google login page', (done) => {
        request(app)
            .get('/api/login/google')
            .expect(302)
            .end((err, res) => {
                if (err) return done(err);
                done();
            });
    });

    it('should handle successful OIDC callback', (done) => {
        request(app)
            .get('/api/oauth2/redirect')
            .query({ code: 'mockCode', state: 'mockState' })
            .expect(302)
            .end((err, res) => {
                if (err) return done(err);
                done();
            });
    });

  
});

