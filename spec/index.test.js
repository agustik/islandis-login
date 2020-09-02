

const IslandISLogin = require("../");

const fs = require('fs');
const path = require('path');
const {ValidationError} = require('../src/error.js');

const validResponse = fs.readFileSync(path.join(__dirname, 'token.txt')).toString()
const invalidResponseSignature = fs.readFileSync(path.join(__dirname, 'decoded-invalid-signature.xml')).toString('base64')
const invalidResponseSignature2 = fs.readFileSync(path.join(__dirname, 'decoded-invalid-signature-2.xml')).toString('base64')


const audienceUrl = 'orkanmin.arborg.is';

//
// const loginIS = new IslandISLogin({
//   verifyDates: false,
//   audienceUrl: audienceUrl,
// });
// loginIS.verify(`æjasdgh`)


//     .then(user => {
//         // Token is valid, return user object
//         console.log("User object ");
//         console.log(user);
//     })
//     .catch(err => {
//         // Error verifying signature or token is invalid.
//         console.log("Error verifying token");
//         console.log(err);
//     });

test('Should return invalid PARSE-XML-ERROR', async () => {
  const loginIS = new IslandISLogin({
    verifyDates: false,
    audienceUrl: audienceUrl,
  });
  try {
    await loginIS.verify(`iahesfoihasdflkhaæsdfhj`)
  } catch (e) {
    expect(e).toBeInstanceOf(ValidationError)
    expect(e.message).toBe('PARSE-XML-ERROR')
  }

});

test('Should return invalid XML-INVALID-RESPONSE', async () => {
  const loginIS = new IslandISLogin({
    verifyDates: false,
    audienceUrl: audienceUrl,
  });
  try {
    await loginIS.verify(Buffer.from('<?xml version="1.0" encoding="UTF-8"?><Response xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_7aba496e-7900-4236-bf59-fcda97db5c6e" Version="2.0" IssueInstant="2020-06-08T20:32:45.6527579Z" Destination="https://api.web.com" xmlns="urn:oasis:names:tc:SAML:2.0:protocol"></Response>'))
  } catch (e) {
    expect(e).toBeInstanceOf(ValidationError)
    expect(e.message).toBe('XML-INVALID-RESPONSE')
  }
});

test('Should return invalid LOGIN-REQUEST-EXPIRED', async () => {
  const loginIS = new IslandISLogin({
    verifyDates: true,
    audienceUrl: audienceUrl,
  });
  try {
    await loginIS.verify(validResponse)
  } catch (e) {
    expect(e).toBeInstanceOf(ValidationError)
    expect(e.message).toBe('LOGIN-REQUEST-EXPIRED')
  }
});

test('Should return invalid AUDIENCEURL-NOT-MATCHING', async () => {
  const loginIS = new IslandISLogin({
    verifyDates: false,
    audienceUrl: 'api.com',
  });
  try {
    await loginIS.verify(validResponse)
  } catch (e) {
    expect(e).toBeInstanceOf(ValidationError)
    expect(e.message).toBe('AUDIENCEURL-NOT-MATCHING')
  }
});

test('Should return invalid CERTIFICATE-INVALID', async () => {
  const loginIS = new IslandISLogin({
    verifyDates: false,
    audienceUrl: 'api.com',
  });
  try {
    await loginIS.verify(invalidResponseSignature)
  } catch (e) {
    expect(e).toBeInstanceOf(ValidationError)
    expect(e.message).toBe('CERTIFICATE-INVALID')
  }
});

test('Should return invalid CERTIFICATE-INVALID', async () => {
  const loginIS = new IslandISLogin({
    verifyDates: false,
    audienceUrl: 'api.com',
  });
  try {
    await loginIS.verify(invalidResponseSignature2)
  } catch (e) {
    expect(e).toBeInstanceOf(ValidationError)
    expect(e.message).toBe('CERTIFICATE-INVALID')
  }
});
