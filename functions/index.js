const functions = require('firebase-functions');
const express = require('express');
const jwt = require('jsonwebtoken')
const axios = require('axios')
const qs = require('qs')
const engines = require('consolidate');

const app = express();
app.engine('hbs', engines.handlebars);
app.set('views', './views');
app.set('view engine', 'hbs');

let code = null

app.get('/', (request, response) => {
    code = request.query.code
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
    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: 60 * 60 });
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
        const jwt = { JWT: token }
        const responseJson = Object.assign(result.data, jwt);
        res.json(responseJson);
    }).catch(e => {
        console.dir(e)
        res.send(e)
    })
}

exports.app = functions.https.onRequest(app);
