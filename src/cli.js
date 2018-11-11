#!/usr/bin/env node
import program from 'commander';
import pkg from '../package.json';
import path from 'path';
import fs from 'fs';
import * as mkcert from './mkcert';

async function createCA({ organization, countryCode, state, locality, validity, key, cert }) {
  //Validate days
  validity = Number.parseInt(validity, 10);
  if(!validity || validity < 0) return console.error('`--validity` must be at least 1 day.');

  //Create the certificate
  let ca;
  try {
    ca = await mkcert.createCA({ organization, countryCode, state, locality, validityDays: validity });
  } catch (err) {
    return console.error(`Failed to create the certificate. Error: ${err.message}`);
  }

  //Write certificates
  fs.writeFileSync(path.resolve(key), ca.key);
  fs.writeFileSync(path.resolve(cert), ca.cert);
}

async function createCert({ addresses, caKey, caCert, validity, key, cert }) {
  //Validate days
  validity = Number.parseInt(validity, 10);
  if(!validity || validity < 0) return console.error('`--validity` must be at least 1 day.');

  //Validate addresses
  addresses = addresses.split(',').map( str=> str.trim()); //Split comma separated list of addresses
  if(!addresses.length) return console.error('`--address` must be a comma separated list of ip/domains.');

  //Check if ca key exists
  let caKeyData;
  try {
    caKeyData = fs.readFileSync(path.resolve(caKey), 'utf-8');
  } catch(err) {
    return console.error(`Unable to read \`${caKey}\`. Please run \`mkcert create-ca\` to create a new certificate authority.`);
  }

  //Check if ca certificate exists
  let caCertData;
  try {
    caCertData = fs.readFileSync(path.resolve(caCert), 'utf-8');
  } catch(err) {
    return console.error(`Unable to read \`${caCert}\`. Please run \`mkcert create-ca\` to create a new certificate authority.`);
  }

  //Create the certificate
  let ssl;
  try {
    ssl = await mkcert.createSSL({ addresses, validityDays: validity, caKey: caKeyData, caCert: caCertData });
  } catch (err) {
    return console.error(`Failed to create the certificate. Error: ${err.message}`);
  }

  //Write certificates
  fs.writeFileSync(path.resolve(key), ssl.key);
  fs.writeFileSync(path.resolve(cert), [ ssl.cert, caCert ].join('\n')); //Create full chain by combining ca and domain certificate
}

program
  .command('create-ca')
  .option('--organization [value]', 'Organization name', 'Test CA')
  .option('--country-code [value]', 'Country code', 'US')
  .option('--state [value]', 'State name', 'California')
  .option('--locality [value]', 'Locality address', 'San Francisco')
  .option('--validity [days]', 'Validity in days', 365)
  .option('--key [file]', 'Output key', 'ca.key')
  .option('--cert [file]', 'Output certificate', 'ca.crt')
  .action((...args)=> {
    const options = args.reverse()[0];
    createCA(options);
  });

program
  .command('create-cert')
  .option('--ca-key [file]', 'CA private key', 'ca.key')
  .option('--ca-cert [file]', 'CA certificate', 'ca.crt')
  .option('--validity [days]', 'Validity in days', 365)
  .option('--key [file]', 'Output key', 'cert.key')
  .option('--cert [file]', 'Output certificate', 'cert.crt')
  .option('--addresses [values]', 'Comma separated list of domains/ip addresses', 'localhost,127.0.0.1')
  .action((...args)=> {
    const options = args.reverse()[0];
    createCert(options);
  });

program
  .version(pkg.version)
  .parse(process.argv);

//Show help by default
if(process.argv.length < 3) program.outputHelp();