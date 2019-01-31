const forge = require('node-forge');
const { promisify } = require('util');
const isIp = require('is-ip');
const randomInt = require('random-int');
const pki = forge.pki;
const generateKeyPair = promisify(pki.rsa.generateKeyPair.bind(pki.rsa));

async function generateCert({ subject, issuer, extensions, validityDays, signWith }) {
  const keyPair = await generateKeyPair({ bits: 2048, workers: 4 });
  const cert = pki.createCertificate();
  const serial = randomInt(50000, 99999).toString(); //Generate a random number between 50K and 100K

  //Use the provided private key to sign the certificate if that exists; otherwise sign the certificate with own key
  signWith = signWith? pki.privateKeyFromPem(signWith): keyPair.privateKey;

  //Set public key
  cert.publicKey = keyPair.publicKey;
  cert.serialNumber = Buffer.from(serial).toString('hex'); //Hex encode the serial number

  //Validity
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + validityDays);

  //Set subject
  cert.setSubject(subject);

  //Set issuer
  cert.setIssuer(issuer);

  //Set extensions
  cert.setExtensions(extensions);

  //Sign using sha256
  cert.sign(signWith, forge.md.sha256.create());

  return {
    key: pki.privateKeyToPem(keyPair.privateKey),
    cert: pki.certificateToPem(cert)
  };
}

async function createCA({ organization, countryCode, state, locality, validityDays }) {
  //Certificate Attributes: https://git.io/fptna
  const attributes = [
    { name: 'commonName', value: organization },
    { name: 'countryName', value: countryCode },
    { name: 'stateOrProvinceName', value: state },
    { name: 'localityName', value: locality },
    { name: 'organizationName', value: organization }
  ];

  //Certificate extensions for a CA
  const extensions = [
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, critical: true }
  ];

  return await generateCert({
    subject: attributes,
    issuer: attributes,
    extensions: extensions,
    validityDays: validityDays
  });
}

async function createCert({ domains, validityDays, caKey, caCert }) {
  //Certificate Attributes: https://git.io/fptna
  const attributes = [
    { name: 'commonName', value: domains[0] } //Use the first address as common name
  ];

  //Certificate extensions for a domain certificate
  const extensions = [
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    { name: 'subjectAltName', altNames: domains.map( domain=> {
      // Available Types: https://git.io/fptng
      const types = { domain: 2, ip: 7 };
      if(isIp(domain)) {
        return { type: types.ip, ip: domain };
      } else {
        return { type: types.domain, value: domain };
      }
    })}
  ];

  //Parse CA certificate
  const ca = pki.certificateFromPem(caCert);

  //Create the cert
  return await generateCert({
    subject: attributes,
    issuer: ca.subject.attributes,
    extensions: extensions,
    validityDays: validityDays,
    signWith: caKey
  });
}

module.exports = { createCA, createCert };
