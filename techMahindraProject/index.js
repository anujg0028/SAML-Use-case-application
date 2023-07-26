var https = require('https');
var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var passport = require('passport');
var saml = require('passport-saml');
var fs = require('fs');

//declare constants
const PORT = 8000;

/** SAML Configurations attributes
 * callbackurl : apps url for IDP to response post authetication
 * signout: apps url for IDP to notify app post signout
 * entrypoint: IDP url to redirect for authentication
 * entityId : Apps Id
 */
const samlConfig = {
    issuer: "6046caad-d794-4815-8a32-e6ad6fcd23fe",
    entityId: "Saml-SSO-App",
    callbackUrl: "http://localhost:8000/login/callback",
    signOut: "http://localhost:8000/signout/callback",
    entryPoint: "https://login.microsoftonline.com/d703ed0c-4430-49fa-9c5b-64366d0e4510/saml2",
};

// For running apps on https mode
// load the public certificate
const sp_pub_cert = fs.readFileSync('certificate.pem', 'utf8');
console.log("sp_pub_cert     ",sp_pub_cert)

//load the private key
const sp_pvk_key = fs.readFileSync('private.key', 'utf8');
console.log("sp_pvk_key     ",sp_pvk_key)

//Idp's certificate from metadata
const idp_cert = fs.readFileSync('idp-pub-key.pem', 'utf8');

passport.serializeUser(function (user, done) {
    //Serialize user, console.log if needed
    console.log("serialize",user)
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    //Deserialize user, console.log if needed
    console.log("deserialize",user)
    done(null, user);
});

// configure SAML strategy for SSO
const samlStrategy = new saml.Strategy({
    callbackUrl: samlConfig.callbackUrl,
    entryPoint: samlConfig.entryPoint,
    issuer: samlConfig.issuer,
    identifierFormat: null,
    decryptionPvk: sp_pvk_key,
    cert: [idp_cert, idp_cert],
    privateCert: fs.readFileSync('csr.pem', 'utf8'),
    validateInResponseTo: true,
    disableRequestedAuthnContext: true,
}, (profile, done) => {
    console.log('passport.use() profile: %s \n', JSON.stringify(profile));
    return done(null, profile);
});

//initialize the express middleware
const app = express();
app.use(cookieParser());

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

//configure session management
// Note: Always configure session before passport initialization & passport session, else error will be encounter
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
}));

passport.use('samlStrategy', samlStrategy);
app.use(passport.initialize({}));
app.use(passport.session({}));

/** Configure routes **/
// default route
app.get('/',
    (req, res) => {
        res.send('Weclome to Single Sign-On Application');
    }
);

//login route
app.get('/login',
    (req, res, next) => {

        // console.log("login:   ",req)
        //console.log("login:   ",res)
        //login handler starts
        next();
    },
    passport.authenticate('samlStrategy'),
);

//post login callback route
app.post('/login/callback',
    (req, res, next) => {

        // console.log(req)
        // console.log(res)
        //login callback starts
        next();
    },
    passport.authenticate('samlStrategy'),
    (req, res) => {

        //SSO response payload
        res.send(req.user.attributes);
    }
);

//Run the https server
// const server = https.createServer({
//     'key': sp_pvk_key,
//     'cert': sp_pub_cert
// }, app).listen(PORT, () => {
//     console.log('Listening on https://techmahindra-rnd.azurewebsites.net:%d', server.address().port)
// });

app.listen(process.env.port || process.env.PORT || PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});