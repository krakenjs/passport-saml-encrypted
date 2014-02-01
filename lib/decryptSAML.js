/**
 * Created by lmarkus on 1/31/14.
 */
'use strict';
var crypto = require('crypto');
var xmldom = require('xmldom');
var xmlencryption = require('xml-encryption');
var xpath  = require('xpath');

var auto_padding = false;

module.exports = function decryptSAML(xml, options) {
    if (!options) {
        return {
            err: new Error('must provide options'),
            result :null
        };
    }
    if (!xml) {
        return {
            err: new Error('must provide XML to encrypt'),
            result :null
        };
    }
    if (!options.key) {
        return {
            err: new Error('key option is mandatory and you should provide a valid RSA private key'),
            result :null
        };
    }
    var doc = new xmldom.DOMParser().parseFromString(xml);

    var symmetricKey = xmlencryption.decryptKeyInfo(doc, options);
    var encryptionMethod = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
    var encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

    var decrypted;
    switch (encryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
            var encryptedContent = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];

            var encrypted = new Buffer(encryptedContent.textContent, 'base64');

            var decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, encrypted.slice(0, 16));
            decipher.setAutoPadding(auto_padding=false);
            decrypted = decipher.update(encrypted.slice(16), 'base64', 'utf8') + decipher.final('utf8') ;
            break;
        default:
            throw new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported');
    }
    return {
        err: null,
        result :decrypted
    };

};
