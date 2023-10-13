#!/usr/bin/env node
import { Option, program } from "commander";
import { readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createCA, createCert } from "./mkcert";

program
  .command("create-ca")
  .option("--organization [value]", "organization name", "Test CA")
  .option("--country-code [value]", "country code", "US")
  .option("--state [value]", "state name", "California")
  .option("--locality [value]", "locality address", "San Francisco")
  .addOption(
    new Option("--validity [days]", "validity in days")
      .default(365)
      .argParser((val) => Number.parseInt(val, 10))
  )
  .option("--key [file]", "output key file", "ca.key")
  .option("--cert [file]", "output certificate file", "ca.crt")
  .action(async (options) => {
    const ca = await createCA(options);
    await writeFile(options.key, ca.key);
    console.log(`CA Private Key: ${options.key}`);
    await writeFile(options.cert, ca.cert);
    console.log(`CA Certificate: ${options.cert}`);
  });

program
  .command("create-cert")
  .alias("create-certificate")
  .option("--ca-key [file]", "ca private key file", "ca.key")
  .option("--ca-cert [file]", "ca certificate file", "ca.crt")
  .addOption(
    new Option("--validity [days]", "validity in days")
      .default(365)
      .argParser((val) => Number.parseInt(val, 10))
  )
  .option("--key [file]", "output key file", "cert.key")
  .option("--cert [file]", "output certificate file", "cert.crt")
  .option("--organization [value]", "optional organization name")
  .option("--email [value]", "optional email address")
  .option("--domain [values...]", "domains or ip addresses", ["localhost", "127.0.0.1"])
  .action(async (options) => {
    let ca = {
      key: await readFile(options.caKey, "utf-8").catch(() => void 0),
      cert: await readFile(options.caCert, "utf-8").catch(() => void 0)
    };

    if (!ca.key || !ca.cert) {
      console.error("Unable to find CA key or certificate.");
      console.error("Please run `mkcert create-ca` to create a new certificate authority.");
      return;
    }

    const cert = await createCert({
      ca: { key: ca.key, cert: ca.cert },
      domains: options.domain,
      validity: options.validity,
      organization: options.organization,
      email: options.email
    });

    await writeFile(options.key, cert.key);
    console.log(`Private Key: ${options.key}`);
    await writeFile(options.cert, `${cert.cert}${ca.cert}`); // write full chain certificate
    console.log(`Certificate: ${options.cert}`);
  });

function getVersion(): string {
  return JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf-8")).version;
}

program.version(getVersion()).parseAsync(process.argv);
