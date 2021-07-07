const path = require('path');
const { xpath } = require('xml-crypto');
const { DOMParser } = require('xmldom');
const { SignedXml } = require('xml-crypto');
const { Certificate } = require('@fidm/x509');
const { readFileSync } = require('fs');
const { CertificateError } = require('./error.js');

/**
 *
 * Load the certificate into memory
 *
 * Reference: https://www.audkenni.is/adstod/skilriki-kortum/skilrikjakedjur/
 */

/* eslint new-cap: ["error", { "newIsCap": false }] */
const FullgiltAudkenni = Certificate.fromPEM(
  readFileSync(path.resolve(__dirname, '../cert/FullgiltAudkenni.pem')),
);

/**
 *
 * A key info provider implementation
 *
 */
function FileKeyInfo(pemKey) {
  this.key = pemKey;

  this.getKeyInfo = function getKeyInfo(key, xmlPrefix) {
    let prefix = '';


    if (typeof xmlPrefix === 'string') {
      prefix = `${xmlPrefix}:`;
    }

    return `<${prefix}X509Data></${prefix}X509Data>`;
  };

  this.getKey = function getKey() {
    return this.key;
  };
}

function isCertificateDataValid(cert) {
  const { serialName } = cert.subject;
  const { organizationName } = cert.issuer;
  const { validFrom, validTo } = cert;

  if (serialName !== '5210002790' || organizationName !== 'Audkenni hf.') {
    return false;
  }

  const timestamp = Date.now();

  if (
    timestamp < new Date(validFrom).getTime()
        || timestamp > new Date(validTo).getTime()
  ) {
    return false;
  }

  return true;
}

function checkSignature(doc, pem, xml) {
  const signature = xpath(
    doc,
    "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
  )[0];

  const sig = new SignedXml();
  sig.keyInfoProvider = new FileKeyInfo(pem);
  sig.loadSignature(signature);
  const isValid = sig.checkSignature(xml);

  return isValid;
}

function isCertificateValid(certificate) {
  // we only need to verify FullgiltAudkenni cert because that is the cert used
  // to sign the message from Island.is
  if (
    FullgiltAudkenni.verifySubjectKeyIdentifier()
        && certificate.verifySubjectKeyIdentifier()
        && FullgiltAudkenni.checkSignature(certificate) === null
        && certificate.isIssuer(FullgiltAudkenni)
  ) {
    return true;
  }

  return false;
}

function certToPEM(cert) {
  return `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`;
}

/*

    Validates x509 certificate validity, checks certificate
    and validates digital signature of XML.

*/
function validate(xml, signature) {
  return new Promise((resolve, reject) => {
    const doc = new DOMParser().parseFromString(xml);

    // construct x509 certificate
    const pem = certToPEM(signature);
    const cert = Certificate.fromPEM(new Buffer.from(pem));

    // Verify certificate data, i.e.
    // serialNumber & organization name is Auðkenni etc.
    if (!isCertificateDataValid(cert)) {
      return reject(new CertificateError('XML message is not signed by Auðkenni.'));
    }

    // Verify that the XML document provided by the request was signed by the
    // certificate provided with the request.
    if (!checkSignature(doc, pem, xml)) {
      return reject(new CertificateError('XML signature is invalid.'));
    }

    // Verify that the certificate we get from the Island.is request
    // is signed and issued by Traustur Bunadur certificate.
    if (!isCertificateValid(cert)) {
      return reject(
        new CertificateError(
          'The XML document is not signed by Auðkenni.',
        ),
      );
    }

    return resolve();
  });
}

module.exports = {
  validateCert: validate,
};
