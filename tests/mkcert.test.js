import * as mkcert from '../src/mkcert';
import https from 'https';
jest.setTimeout(20 * 1000); //Generating RSA key pairs can take some time

test('Test createCA()', async ()=> {
  const ca = await mkcert.createCA({
    organization: 'Test CA',
    countryCode: 'NP',
    state: 'Bagmati',
    locality: 'Kathmandu',
    validityDays: 365
  });
  
  expect(ca.key).toBeDefined();
  expect(ca.cert).toBeDefined();
});

test('Test createSSL()', async ()=> {
  const ca = await mkcert.createCA({
    organization: 'Test CA',
    countryCode: 'NP',
    state: 'Bagmati',
    locality: 'Kathmandu',
    validityDays: 365
  });

  const ssl = await mkcert.createSSL({
    addresses: ['127.0.0.1', 'localhost'],
    validityDays: 365,
    caKey: ca.key,
    caCert: ca.cert
  });

  expect(ssl.key).toBeDefined();
  expect(ssl.cert).toBeDefined();
});

// test.only('Test server for manual testing', async (cb)=> {
//   const ca = await mkcert.createCA({
//     organization: 'Test CA',
//     countryCode: 'NP',
//     state: 'Bagmati',
//     locality: 'Kathmandu',
//     validityDays: 365
//   });

//   const ssl = await mkcert.createSSL({
//     addresses: ['localhost', '127.0.0.1'],
//     validityDays: 365,
//     caKey: ca.key,
//     caCert: ca.cert
//   });

//   const server = https.createServer({
//     key: ssl.key,
//     cert: `${ssl.cert}\n${ca.cert}` //Create full chain by combining ca and domain certificate
//   }, (req, res)=> {
//     res.end('This Works');
//   });

//   server.listen(9090);
//   console.log(ca.cert);
// }, 10000000); //Run Indefinitely
