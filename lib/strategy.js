var passport = require('passport-strategy');
var util = require('util');
var saml = require('./saml');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  this.name = 'saml';

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(options);
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  var self = this;
  if (req.body && req.body.SAMLResponse) {
    // We have a response, get the user identity out of it
    var response = req.body.SAMLResponse;

    try{
      this._saml.validateResponse(response, function (err, profile, loggedOut) {
      if (err) {
        return self.error(err);
        console.log('[STRATEGY] Error validating response: ' + err);
      }

      if (loggedOut) {
        if (self._saml.options.logoutRedirect) {
          self.redirect(self._saml.options.logoutRedirect);
          return;  
        } else {
          self.redirect("/");          
        }
        
      }

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
          console.log('[STRATEGY] Error Verifying: ' + err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      self._verify(profile, verified);
    });
    }catch(err){
      console.log('[STRATEGY] Unable to authenticate: ' + err);
    }
  } else {
    // Initiate new SAML authentication request

    this._saml.getAuthorizeUrl(req, function (err, url) {
      if (err) {
        return self.fail();
        console.log('[STRATEGY] Failed to getAuthorizeUrl: ' + err);
      }

      self.redirect(url);
    });
  }
};

Strategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

module.exports = Strategy;