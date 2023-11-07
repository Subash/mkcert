Create self signed tls certificates without OpenSSL.

## Install

```
npm install -g mkcert
```

## CLI

### Create a Certificate Authority

```
$ mkcert create-ca --help

  Options:
    --organization [value]  organization name (default: "Test CA")
    --country-code [value]  country code (default: "US")
    --state [value]         state name (default: "California")
    --locality [value]      locality address (default: "San Francisco")
    --validity [days]       validity in days (default: 365)
    --key [file]            output key file (default: "ca.key")
    --cert [file]           output certificate file (default: "ca.crt")
    -h, --help              display help for command
```

### Create a Certificate

```
$ mkcert create-cert --help

  Options:
    --ca-key [file]                  ca private key file (default: "ca.key")
    --ca-cert [file]                 ca certificate file (default: "ca.crt")
    --validity [days]                validity in days (default: 365)
    --key [file]                     output key file (default: "cert.key")
    --cert [file]                    output certificate file (default: "cert.crt")
    --organization [value]           optional organization name
    --email [value]                  optional email address
    --domains, --domain [values...]  domains or ip addresses (default: ["localhost","127.0.0.1"])
    -h, --help                       display help for command
```

## API

```js
import { createCA, createCert } from "mkcert";

const ca = await createCA({
  organization: "Hello CA",
  countryCode: "NP",
  state: "Bagmati",
  locality: "Kathmandu",
  validity: 365
});

const cert = await createCert({
  ca: { key: ca.key, cert: ca.cert },
  domains: ["127.0.0.1", "localhost"],
  validity: 365
});

console.log(cert.key, cert.cert); // certificate info
console.log(`${cert.cert}${ca.cert}`); // create full chain certificate by merging CA and domain certificates
```
