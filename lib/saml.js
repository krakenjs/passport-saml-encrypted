var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var decryptSAML = require('./decryptSAML');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');

var SAML = function (options) {
  this.options = this.initialize(options);
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (!options.protocol) {
    options.protocol = 'https://';
  }

  if (!options.path) {
    options.path = '/saml/consume';
  }

  if (!options.issuer) {
    options.issuer = 'onelogin_saml';
  }

  if (options.identifierFormat === undefined) {
    options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
  }

  return options;
};

SAML.prototype.generateUniqueID = function () {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

/*SAML.prototype.generateInstant = function () {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + (date.getUTCHours()+2)).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z"; 
};
*/

//from old passport-saml plugin
SAML.prototype.generateInstant = function () {
  return new Date().toISOString();
}; 

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
}

SAML.prototype.generateAuthorizeRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  // Post-auth destination
  if (this.options.callbackUrl) {
    callbackUrl = this.options.callbackUrl;
  } else {
    var callbackUrl = this.options.protocol + req.headers.host + this.options.path;
  }

  var request =
   "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant + 
   "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" + 
   this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

  if (this.options.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat + 
    "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }
   
 /* request += 
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
  "</samlp:AuthnRequest>";
  */

  request +=  "</samlp:AuthnRequest>";
  return request;
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  //samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
  // ID="_135ad2fd-b275-4428-b5d6-3ac3361c3a7f" Version="2.0" Destination="https://idphost/adfs/ls/" 
  //IssueInstant="2008-06-03T12:59:57Z"><saml:Issuer>myhost</saml:Issuer><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" 
  //NameQualifier="https://idphost/adfs/ls/">myemail@mydomain.com</NameID<samlp:SessionIndex>_0628125f-7f95-42cc-ad8e-fde86ae90bbe
  //</samlp:SessionIndex></samlp:LogoutRequest>

  var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "+
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\""+id+"\" Version=\"2.0\" IssueInstant=\""+instant+
    "\" Destination=\""+this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>"+
    "<saml:NameID Format=\""+req.user.nameIDFormat+"\">"+req.user.nameID+"</saml:NameID>"+
    "</samlp:LogoutRequest>";
  return request;
}

SAML.prototype.requestToUrl = function (request, operation, callback) {
  var self = this;
  zlib.deflateRaw(request, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = self.options.entryPoint + '?';

    if (operation === 'logout') {
      if (self.options.logoutUrl) {
        target = self.options.logoutUrl + '?';
      } 
    }
 
    var samlRequest = {
      SAMLRequest: base64
    };

    if (self.options.privateCert) {
      samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
    }
    target += querystring.stringify(samlRequest);

    callback(null, target);
  });
}

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var request = this.generateAuthorizeRequest(req);
  
  this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function(req, callback) {
  var request = this.generateLogoutRequest(req);

  this.requestToUrl(request, 'logout', callback);
}

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.checkSAMLStatus = function (xmlDomDoc) {
	var status = {StatusCodeValue:null, StatusMessage:null, StatusDetail:null}	
	
	var statusCodeValueNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusCode']")[0];
	if(statusCodeValueNode)
	{
		status.StatusCodeValue  = statusCodeValueNode.getAttribute('Value');
	}
	
	var statusMessageNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusMessage']")[0];
	if(statusMessageNode)
	{
		status.StatusMessage  = statusMessageNode.childNodes[0].nodeValue;
	}
	
	var statusDetailNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusDetail']/*[local-name(.)='Cause']")[0];	
	if(statusDetailNode)
	{
		status.StatusDetail  = statusDetailNode.childNodes[0].nodeValue;
	}
	//status.StatusMessage = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusMessage']")[0].childNodes[0].nodeValue;
	//status.StatusDetail = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='StatusDetail']/*[local-name(.)='Cause']")[0].childNodes[0].nodeValue;	
	return status;
};

SAML.prototype.decryptSAMLAssertion = function (xmlDomDoc, privateCert) {
	var encryptedDataNode  = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='EncryptedData' and namespace-uri(.)='http://www.w3.org/2001/04/xmlenc#']")[0];
	var encryptedData = encryptedDataNode.toString();
	//console.log(encryptedData);
	var decryptOptions = {    key: privateCert	};	
	var resultObj = decryptSAML(encryptedData,decryptOptions);
	if(resultObj.result) 
	{
		return resultObj.result;
	}
	else
	{
		return resultObj.err;	
	}
};

SAML.prototype.validateSignature = function (xml, cert) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  } else if (parentElement['samlp:'+elementName]) {
    return parentElement['samlp:'+elementName];
  } 
  return parentElement[elementName];
}

SAML.prototype.validateResponse = function (samlResponse, callback) {
  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');
  
  var samlAssertion = null;  
	// Verify signature on the response
	if (self.options.cert && !self.validateSignature(xml, self.options.cert)) {
	  return callback(new Error('Invalid signature'), null, false);
	}
	
	var xmlDomDoc = new xmldom.DOMParser().parseFromString(xml);
	//Check Status code in the SAML Response
	var statusObj = self.checkSAMLStatus(xmlDomDoc);
	if(statusObj.StatusCodeValue != "urn:oasis:names:tc:SAML:2.0:status:Success")
		return callback(new Error('SAML Error Response:\nStatusCodeValue = '+ statusObj.StatusCodeValue + '\nStatusMessage = ' + statusObj.StatusMessage + '\nStatusDetail = ' + statusObj.StatusDetail + '\n'), null, false);
	
	 // Decrypt and Retrieve SAML Assertion 
	if (self.options.encryptedSAML &&  self.options.privateCert)
	{
		samlAssertion = self.decryptSAMLAssertion(xmlDomDoc, self.options.privateCert); 
		if (!samlAssertion){
	  		return callback(new Error('Decryption Failed'), null, false);
		}
		else //trim the unwanted characters after closing </saml:Assertion>
		{
			var nIndex = samlAssertion.indexOf("</saml:Assertion>");
			var validStringLen = nIndex + 17;
			samlAssertion = samlAssertion.slice(0, validStringLen);
		}
		//	console.log(samlAssertion);
		// Verify signature on the decrypted assertion
		if (self.options.cert && !self.validateSignature(samlAssertion, self.options.cert)) {
			return callback(new Error('Invalid signature'), null, false);
		}
	}
	else //Retrieve SAML Assertion 
	{
		samlAssertionNode = xmlCrypto.xpath(xmlDomDoc, "//*[local-name(.)='Assertion']")[0];
		if (samlAssertionNode)
		{	
			samlAssertion = samlAssertionNode.toString();
		}
		else
		{
			return callback(new Error('Missing Assertion'), null, false);
		}
	}		
	
	var parser = new xml2js.Parser({explicitRoot:true});
 	parser.parseString(samlAssertion, function (err, doc) {   
	
	var assertion = self.getElement(doc, 'Assertion');
	
    if (assertion) {
      /*
      if (!assertion) {
        return callback(new Error('Missing SAML assertion'), null, false);
      }
	  */

      profile = {};
      var issuer = self.getElement(assertion, 'Issuer');
      if (issuer) {
        profile.issuer = issuer[0];
      }

      var subject = self.getElement(assertion, 'Subject');
      if (subject) {
        var nameID = self.getElement(subject[0], 'NameID');
        if (nameID) {
            profile.nameID = nameID[0]["_"];

          if (nameID[0]['$'].Format) {
            profile.nameIDFormat = nameID[0]['$'].Format;
          }
        }
      }

      var attributeStatement = self.getElement(assertion, 'AttributeStatement');
      if (!attributeStatement) {
        return callback(new Error('Missing AttributeStatement'), null, false);
      }

      var attributes = self.getElement(attributeStatement[0], 'Attribute');

      if (attributes) {
        attributes.forEach(function (attribute) {
          var value = self.getElement(attribute, 'AttributeValue');
          if (typeof value[0] === 'string') {
            profile[attribute['$'].Name] = value[0];
          } else {
            profile[attribute['$'].Name] = value[0]['_'];
          }
        });
      }
        

      if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
        // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
        profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
      }

      if (!profile.email && profile.mail) {
        profile.email = profile.mail;
      }

      callback(null, profile, false);
    } else {
      var logoutResponse = self.getElement(doc, 'LogoutResponse');

      if (logoutResponse){
        callback(null, null, true);
      } else {
        return callback(new Error('Unknown SAML response message'), null, false);
      }

    }


  });
};

exports.SAML = SAML;
