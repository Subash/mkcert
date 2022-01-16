const ipRegex = require('ip-regex');
const forge = require('node-forge');
const { promisify } = require('util');
const pki = forge.pki;
const generateKeyPair = promisify(pki.rsa.generateKeyPair.bind(pki.rsa));

async function generateCert({ subject, issuer, extensions, validityDays, signWith }) {
  // create serial from and integer between 50000 and 99999
  const serial = Math.floor((Math.random() * 95000) + 50000).toString();
  const keyPair = await generateKeyPair({ bits: 2048, workers: 4 });
  const cert = pki.createCertificate();

  cert.publicKey = keyPair.publicKey;
  cert.serialNumber = Buffer.from(serial).toString('hex'); // serial number must be hex encoded
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + validityDays);
  cert.setSubject(subject);
  cert.setIssuer(issuer);
  cert.setExtensions(extensions);

  // sign the certificate with it's own private key if no separate signing key is provided
  signWith = signWith? pki.privateKeyFromPem(signWith): keyPair.privateKey;
  cert.sign(signWith, forge.md.sha256.create());

  return {
    key: pki.privateKeyToPem(keyPair.privateKey),
    cert: pki.certificateToPem(cert)
  };
}

async function createCA({ organization, countryCode, state, locality, validityDays }) {
  // certificate Attributes: https://git.io/fptna
  const attributes = [
    { name: 'commonName', value: organization },
    { name: 'countryName', value: countryCode },
    { name: 'stateOrProvinceName', value: state },
    { name: 'localityName', value: locality },
    { name: 'organizationName', value: organization }
  ];

  // required certificate extensions for a certificate authority
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
  // certificate Attributes: https://git.io/fptna
  const attributes = [
    { name: 'commonName', value: domains[0] } // use the first address as common name
  ];

  // required certificate extensions for a tls certificate
  const extensions = [
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    { name: 'subjectAltName', altNames: domains.map( domain=> {
      const types = { domain: 2, ip: 7 }; // available Types: https://git.io/fptng
      const isIp = ipRegex({ exact: true }).test(domain);

      if(isIp) return { type: types.ip, ip: domain };
      return { type: types.domain, value: domain };
    })}
  ];

  const ca = pki.certificateFromPem(caCert);

  return await generateCert({
    subject: attributes,
    issuer: ca.subject.attributes,
    extensions: extensions,
    validityDays: validityDays,
    signWith: caKey
  });
}

module.exports = { createCA, createCert };
