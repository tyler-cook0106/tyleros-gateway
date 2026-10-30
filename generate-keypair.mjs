#!/usr/bin/env node
import { generateKeyPairSync } from 'node:crypto';
import { chmodSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function usage() {
  console.log(`TylerOS ECDSA P-256 JWK generator

Usage:
  node generate-keypair.mjs --save <private-key-file>
  node generate-keypair.mjs --print-private
  node generate-keypair.mjs --help

--save           Save the private JWK to a new file; print the public JWK.
--print-private  Print both private and public JWKs to the console.
`);
}

const args = process.argv.slice(2);
if (args.includes('--help')) {
  usage();
  process.exit(0);
}
if (args.length === 0) {
  usage();
  process.exit(1);
}

const saveIndex = args.indexOf('--save');
const printPrivate = args.includes('--print-private');
const validSave = saveIndex !== -1 && args[saveIndex + 1] && !args[saveIndex + 1].startsWith('--');
const validArgs = (saveIndex !== -1 && args.length === 2 && validSave) ||
                  (printPrivate && args.length === 1);

if (!validArgs) {
  console.error('Choose exactly one: --save <file> OR --print-private. Use --help for details.');
  process.exit(1);
}

try {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });

  if (saveIndex !== -1) {
    const file = resolve(args[saveIndex + 1]);
    writeFileSync(file, `${JSON.stringify(privateJwk, null, 2)}\n`, {
      flag: 'wx',
      mode: 0o600,
    });
    try { chmodSync(file, 0o600); } catch {}
    console.log(`Private JWK saved to: ${file}`);
    console.log('Keep this file secret. It is not printed below.');
    console.log('\nPUBLIC JWK');
    console.log(JSON.stringify(publicJwk, null, 2));
  } else {
    console.warn('WARNING: The private key is being printed. Treat this console output as secret.');
    console.log('\nPRIVATE JWK');
    console.log(JSON.stringify(privateJwk, null, 2));
    console.log('\nPUBLIC JWK');
    console.log(JSON.stringify(publicJwk, null, 2));
  }
} catch (error) {
  if (error?.code === 'EEXIST') {
    console.error('That private-key file already exists. Choose a different filename; it will not be overwritten.');
  } else {
    console.error(`Key generation failed: ${error?.message ?? error}`);
  }
  process.exit(1);
}
