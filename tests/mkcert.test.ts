import { expect, test } from "@jest/globals";
import { pki } from "node-forge";
import * as mkcert from "../src/mkcert";

test("Create Certificate Authority", async () => {
  const ca = await mkcert.createCA({
    organization: "Test CA",
    countryCode: "NP",
    state: "Bagmati",
    locality: "Kathmandu",
    validity: 365
  });

  expect(ca.key).toBeDefined();
  expect(ca.cert).toBeDefined();
});

test("Create Certificate", async () => {
  const ca = await mkcert.createCA({
    organization: "Test CA",
    countryCode: "NP",
    state: "Bagmati",
    locality: "Kathmandu",
    validity: 365
  });

  const tls = await mkcert.createCert({
    ca: { key: ca.key, cert: ca.cert },
    domains: ["127.0.0.1", "localhost"],
    email: "abc@example.com",
    organization: "Test Cert",
    validity: 365
  });

  expect(tls.key).toBeDefined();
  expect(tls.cert).toBeDefined();
});

test("Verify Certificate Chain", async () => {
  const ca = await mkcert.createCA({
    organization: "Test CA",
    countryCode: "NP",
    state: "Bagmati",
    locality: "Kathmandu",
    validity: 365
  });

  const server = await mkcert.createCert({
    ca,
    domains: ["127.0.0.1", "localhost"],
    validity: 365
  });

  const caStore = pki.createCaStore([ca.cert]);
  const serverCert = pki.certificateFromPem(server.cert);

  expect(() => {
    pki.verifyCertificateChain(caStore, [serverCert]);
  }).not.toThrow();
});
