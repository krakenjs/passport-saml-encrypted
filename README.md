passport-saml-encrypted
=======================

A strategy for Passport authentication that supports encrypted SAML responses.

This is largely a fork of https://github.com/bergie/passport-saml
Which seems to be dormant.

It was created to support encrypted SAML responses.

### Returned data object:
**Note**: If there is a single value for an attribute, it will be a string. If there are multiple values, it will be an array. E.G.:

```json
{ issuer: 'https://fedpocv1.corp.company.com',
  nameID: 'g2IpU4vJ53211ila09gh8wUtzgm',
  nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  Email: ' lmarkus@company.com',
  Corpid: 'lmarkus',
  FirstName: 'Lenny',
  LastName: 'Markus',
  ROLE_NAME: [ 'R_DEFAULT_ADMINISTRATION_ROLE', 'V_V_OPERATIONS' ] }
```


Contributions welcome.


Documentation from the original forked repo follows:

Passport-SAML
=============

This is a [SAML 2.0](http://en.wikipedia.org/wiki/SAML_2.0) authentication provider for [Passport](http://passportjs.org/), the Node.js authentication library.

The code was originally based on Michael Bosworth's [express-saml](https://github.com/bozzltron/express-saml) library.

Passport-SAML has been tested to work with both [SimpleSAMLphp](http://simplesamlphp.org/) based Identity Providers, and with [Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## Installation

    $ npm install passport-saml-encrypted

## Usage

### Configure strategy

This example utilizes the [Feide OpenIdp identity provider](https://openidp.feide.no/). You need an account there to log in with this. You also need to [register your site](https://openidp.feide.no/simplesaml/module.php/metaedit/index.php) as a service provider.

The SAML identity provider will redirect you to the URL provided by the `path` configuration.

```javascript
passport.use(new SamlStrategy(
  {
    path: '/login/callback',
    entryPoint: 'https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php',
    issuer: 'passport-saml'
  },
  function(profile, done) {
    findByEmail(profile.email, function(err, user) {
      if (err) {
        return done(err);
      }
      return done(null, user);
    });
  })
));
```

### Provide the authentication callback

You need to provide a route corresponding to the `path` configuration parameter given to the strategy:

```javascript
app.post('/login/callback',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);
```

### Authenticate requests

Use `passport.authenticate()`, specifying `saml` as the strategy:

```javascript
app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);
```

## Security and signatures

Passport-SAML uses the HTTP Redirect Binding for its `AuthnRequest`s, and expects to receive the messages back via the HTTP POST binding.

Authentication requests sent by Passport-SAML can be signed using RSA-SHA1. To sign them you need to provide a private key in the PEM format via the `privateCert` configuration key. For example:

```javascript
    privateCert: fs.readFileSync('./cert.pem', 'utf-8')
```

It is a good idea to validate the incoming SAML Responses. For this, you can provide the Identity Provider's certificate using the `cert` confguration key:

```javascript
    cert: 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W=='
```

If the response is encrypted, you need to supply your public key to the SAML provider, and use your private key to decrypt the response.
This is specified as:
 ```javascrip
     privateCert: fs.readFileSync('path/to/privkey.pem', 'utf-8')
```

## Usage with Active Directory Federation Services

Here is a configuration that has been proven to work with ADFS:

```javascript
  {
    entryPoint: 'https://ad.example.net/adfs/ls/',
    issuer: 'https://your-app.example.net/login/callback',
    callbackUrl: 'https://your-app.example.net/login/callback',
    cert: 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==',
    privateCert: fs.readFileSync('./ssl/privkey.pem', 'utf-8'),  //need to generate key using openssl and put it in server
    encryptedSAML:true,
    identifierFormat:"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  }
```

Please note that ADFS needs to have a trust established to your service in order for this to work.

