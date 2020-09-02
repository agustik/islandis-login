const { parseStringPromise } = require('xml2js');
const { validateCert } = require('./src/validateSignature.js');
const { ValidationError } = require('./src/error.js');

function toIsoDate(epochms) {
  return new Date(epochms).toISOString();
}


const IslandISLogin = function IslandISLogin(optinalOptions) {
  // Utility method to extend defaults with user options
  function extendDefaults(source, properties) {
    const output = source;
    Object.keys(properties).forEach((key) => {
      const property = properties[key];
      if (property !== undefined) {
        output[key] = properties[key];
      }
    });
    return output;
  }

  function getXmlFromToken(token) {
    return Buffer.from(token, 'base64').toString('utf8');
  }

  function gatherUserData(attribs) {
    const userOb = {
      kennitala: '',
      mobile: '',
      fullname: '',
      ip: '',
      userAgent: '',
      destinationSSN: '',
      authId: '',
      authenticationMethod: '',
    };

    // Gather neccessary data from SAML request from island.is.


    attribs.forEach((item) => {
      if (item.$.Name === 'UserSSN') {
        userOb.kennitala = item.AttributeValue[0]._;
        return;
      }

      if (item.$.Name === 'Mobile') {
        userOb.mobile = item.AttributeValue[0]._.replace('-', '');
        return;
      }

      if (item.$.Name === 'Name') {
        userOb.fullname = item.AttributeValue[0]._;
        return;
      }

      if (item.$.Name === 'IPAddress') {
        userOb.ip = item.AttributeValue[0]._;
        return;
      }

      if (item.$.Name === 'UserAgent') {
        userOb.userAgent = item.AttributeValue[0]._;
        return;
      }

      if (item.$.Name === 'AuthID') {
        userOb.authId = item.AttributeValue[0]._;
        return;
      }

      if (item.$.Name === 'Authentication') {
        userOb.authenticationMethod = item.AttributeValue[0]._;
        return;
      }

      if (item.$.Name === 'DestinationSSN') {
        userOb.destinationSSN = item.AttributeValue[0]._;
      }
    });
    return userOb;
  }


  const defaults = {
    verifyDates: true,
    audienceUrl: null,
  };


  if (typeof optinalOptions === 'object') {
    this.options = extendDefaults(defaults, optinalOptions);
  } else {
    this.options = defaults;
  }

  IslandISLogin.prototype.verify = (token) => {
    const xml = getXmlFromToken(token);

    return new Promise(async (resolve, reject) => {

      let json;
      try {
        json = await parseStringPromise(xml);
      } catch (e) {
        return reject(new ValidationError('PARSE-XML-ERROR', e))
      }

      if (! json.Response || ! json.Response.Signature || ! Array.isArray(json.Response.Signature) ) {
        return reject(
          new ValidationError('XML-INVALID-RESPONSE', `No 'Response' in xml`)
        )
      }

      const x509signature = json.Response
        .Signature[0]
        .KeyInfo[0]
        .X509Data[0]
        .X509Certificate[0];

      // Validate signature of XML document from Island.is, verify that the
      // XML document was signed by Island.is and verify certificate issuer.
      try {
        await validateCert(xml, x509signature);
      } catch (e) {
        return reject(
          new ValidationError('CERTIFICATE-INVALID', e),
        );
      }

      const audienceUrl = json.Response
        .Assertion[0]
        .Conditions[0]
        .AudienceRestriction[0]
        .Audience[0];

      if (!this.options.audienceUrl) {
        return reject(
          new ValidationError('AUDIENCEURL-MISSING',
            'You must provide an \'audienceUrl\' in the options when calling the constructor function.'),
        );
      }

      // Check that the message is intented for the provided audienceUrl.
      // This is done to protect against a malicious actor using a token
      // intented for another service that also uses the island.is login.
      if (this.options.audienceUrl !== audienceUrl) {
        return reject(
          new ValidationError('AUDIENCEURL-NOT-MATCHING',
            `The AudienceUrl you provide must match data from Island.is. Got: '${audienceUrl}'`),
        );
      }

      const dates = {
        notBefore: new Date(
          json.Response.Assertion[0].Conditions[0].$.NotBefore,
        ),
        notOnOrAfter: new Date(
          json.Response.Assertion[0].Conditions[0].$.NotOnOrAfter,
        ),
      };

      // Used to test locally with a token that has expired.
      // verifyDates should always be true in Production!
      if (this.options.verifyDates) {
        // Verify that the login request is not too old.
        const timestamp = Date.now();

        if (
          !(
            timestamp < dates.notOnOrAfter
            && timestamp > dates.notBefore
          )
        ) {
          return reject(
            new ValidationError('LOGIN-REQUEST-EXPIRED',
              `Login request has expired. Expired at: ${toIsoDate(dates.notOnOrAfter)}`),
          );
        }
      }

      // Array of attributes about the user
      const attribs = json.Response.Assertion[0].AttributeStatement[0].Attribute;

      // Get user data from attribs array
      const userOb = gatherUserData(attribs);
      const destination = json.Response.$.Destination;

      // All checks passed - return Data
      return resolve({
        user: userOb,
        extra: {
          destination,
          audienceUrl,
          dates,
        },
      });

        // .catch(() => reject(
        //   new ValidationError('INVALID-TOKEN-XML',
        //     'Invalid login token - cannot parse XML from Island.is.'),
        // ));
    });
  };
};

module.exports = IslandISLogin;
