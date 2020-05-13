const functions = require('firebase-functions');
const express = require('express');
const jwt = require('jsonwebtoken')
const axios = require('axios')
const qs = require('qs')
const engines = require('consolidate');
const crypto = require('crypto');

// read property file
const config_data = require('./config.json');

const iv = new Buffer('0000000000000000');

// method to encrypt text data with given key
const encrypt = (data, key) => {
    var decodeKey = crypto.createHash('sha256').update(key, 'utf-8').digest();
    var cipher = crypto.createCipheriv('aes-256-cbc', decodeKey, iv);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
};

const app = express();
app.engine('hbs', engines.handlebars);
app.set('views', './views');
app.set('view engine', 'hbs');

let code = null

app.get('/', (request, response) => {
    code = request.query.code;
    if (!code) {
        // Code is required to obtain access token
        response.render('index_noCode');
    } else {
        response.render('index');
    }
});

app.post('/credentials', (request, response) => {
    const { privateKey, client_id } = request.body
    generateToken(privateKey, client_id, response)
});

// method to generate JWT and call API to generate access token
function generateToken(privateKey, client_id, res) {
    const tokenUrl = 'https://b2b.revolut.com/api/1.0/auth/token' // production url
    // const tokenUrl = 'https://sandbox-b2b.revolut.com/api/1.0/auth/token' // test url
    const issuer = 'revolut-test-516c1.web.app' // Issuer for JWT, should be derived from your redirect URL
    const aud = 'https://revolut.com' // Constant

    const payload = {
        "iss": issuer,
        "sub": client_id,
        "aud": aud
    }
    const days = Number(config_data.token_valid_days);
    // generates json web token with given data
    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: 60 * 60 * 24 * days });
    
    // calls Revolut API to generate access token
    axios({
        method: 'POST',
        url: tokenUrl,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        // It's important to stringify data since we're sending www-form-urlencoded data
        data: qs.stringify({
            "grant_type": "authorization_code",
            "code": code,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_id": client_id,
            "client_assertion": token,
        })
        // eslint-disable-next-line promise/always-return
    }).then((result) => {
        // encrypts received data
        const key = config_data.encryption_key.toString();
        const object = {
            access_token: encrypt(result.data.access_token, key),
            refresh_token: encrypt(result.data.refresh_token, key),
            JWT: encrypt(token, key),
        }
        res.json(object);
    }).catch(e => {
        console.dir(e)
        res.send(e)
    })
}

exports.app = functions.https.onRequest(app);
