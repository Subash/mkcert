import { md, pki } from "node-forge";
import net from "node:net";
import { promisify } from "node:util";

export type Certificate = {
  key: string;
  cert: string;
};

type GenerateOptions = {
  subject: pki.CertificateField[];
  issuer: pki.CertificateField[];
  extensions: Record<string, unknown>[];
  validity: number;
  signWith?: string;
};

async function generateCert(options: GenerateOptions): Promise<Certificate> {
  const { subject, issuer, extensions, validity } = options;
  const generateKeyPair = promisify(pki.rsa.generateKeyPair.bind(pki.rsa));

  // create random serial number between between 50000 and 99999
  const serial = Math.floor(Math.random() * 95000 + 50000).toString();
  const keyPair = await generateKeyPair({ bits: 2048, workers: 4 });
  const cert = pki.createCertificate();

  // serial number must be hex encoded
  cert.serialNumber = Buffer.from(serial).toString("hex");
  cert.publicKey = keyPair.publicKey;
  cert.setSubject(subject);
  cert.setIssuer(issuer);
  cert.setExtensions(extensions);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + validity);

  // sign the certificate with it's own
  // private key if no separate signing key is provided
  const signWith = options.signWith ? pki.privateKeyFromPem(options.signWith) : keyPair.privateKey;
  cert.sign(signWith, md.sha256.create());

  return {
    key: pki.privateKeyToPem(keyPair.privateKey),
    cert: pki.certificateToPem(cert)
  };
}

export type CertificateAuthorityOptions = {
  organization: string;
  countryCode: string;
  state: string;
  locality: string;
  validity: number;
};

export async function createCA(options: CertificateAuthorityOptions): Promise<Certificate> {
  // certificate Attributes: https://git.io/fptna
  const attributes = [
    { name: "commonName", value: options.organization },
    { name: "countryName", value: options.countryCode },
    { name: "stateOrProvinceName", value: options.state },
    { name: "localityName", value: options.locality },
    { name: "organizationName", value: options.organization }
  ];

  // required certificate extensions for a certificate authority
  const extensions = [
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, critical: true }
  ];

  return await generateCert({
    subject: attributes,
    issuer: attributes,
    extensions: extensions,
    validity: options.validity
  });
}

export type CertificateOptions = {
  domains: string[];
  validity: number;
  organization?: string;
  email?: string;
  ca: Certificate;
};

export async function createCert(options: CertificateOptions): Promise<Certificate> {
  // certificate Attributes: https://git.io/fptna
  const attributes = [
    { name: "commonName", value: options.domains[0] } // use the first address as common name
  ];

  if (options.organization) {
    attributes.push({ name: "organizationName", value: options.organization });
  }

  if (options.email) {
    attributes.push({ name: "emailAddress", value: options.email });
  }

  // required certificate extensions for a tls certificate
  const extensions = [
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
      critical: true
    },
    { name: "extKeyUsage", serverAuth: true, clientAuth: true },
    {
      name: "subjectAltName",
      altNames: options.domains.map((domain) => {
        // types https://git.io/fptng
        const TYPE_DOMAIN = 2;
        const TYPE_IP = 7;

        if (net.isIP(domain)) {
          return { type: TYPE_IP, ip: domain };
        }

        return { type: TYPE_DOMAIN, value: domain };
      })
    }
  ];

  const ca = pki.certificateFromPem(options.ca.cert);

  return await generateCert({
    subject: attributes,
    issuer: ca.subject.attributes,
    extensions: extensions,
    validity: options.validity,
    signWith: options.ca.key
  });
}
