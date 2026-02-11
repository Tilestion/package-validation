import { readFile, writeFile } from 'fs/promises';
import { dirname, join } from 'path';
import { MlDsa } from './signers/post_quantum.ts';
import { Ed25519 } from './signers/classical.ts';
import type { Signer } from './sign.ts';

interface Manifest {
  package: {
    id: string;
    name: string;
  };
  signature: {
    type: string;
    keyId: string;
  };
  artifacts: {
    [key: string]: {
      path: string;
    };
  };
}

function getSigner(type: string): Signer {
  switch (type) {
    case 'ed25519':
      return new Ed25519();
    case 'ml-dsa-65':
      return new MlDsa();
    default:
      throw new Error(`Unknown signature type: ${type}`);
  }
}

function getArtifactPaths(manifest: Manifest, manifestDir: string): string[] {
  const paths: string[] = [];
  for (const artifact of Object.values(manifest.artifacts)) {
    paths.push(join(manifestDir, artifact.path));
  }
  return paths;
}

function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

function fromBase64(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, 'base64'));
}

async function keygen(manifestPath: string): Promise<void> {
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.type);
  
  const { secretKey, publicKey } = signer.generateKeys();
  const manifestDir = dirname(manifestPath);
  
  await writeFile(join(manifestDir, `${manifest.signature.keyId}.priv`), toBase64(secretKey));
  await writeFile(join(manifestDir, `${manifest.signature.keyId}.pub`), toBase64(publicKey));
  
  console.log(`Generated keys: ${manifest.signature.keyId}.priv, ${manifest.signature.keyId}.pub`);
}

async function sign(manifestPath: string, privateKeyPath: string): Promise<void> {
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.type);
  const manifestDir = dirname(manifestPath);
  
  const secretKeyBase64 = await readFile(privateKeyPath, 'utf-8');
  const secretKey = fromBase64(secretKeyBase64.trim());
  const filesToSign = [manifestPath, ...getArtifactPaths(manifest, manifestDir)];
  
  const signature = await signer.signFiles(filesToSign, secretKey);
  const sigPath = join(manifestDir, `${manifest.package.id}.sig`);
  await writeFile(sigPath, toBase64(signature));
  
  console.log(`Signature written to: ${sigPath}`);
}

async function verify(manifestPath: string, signaturePath: string, publicKeyPath: string): Promise<void> {
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.type);
  const manifestDir = dirname(manifestPath);
  
  const publicKeyBase64 = await readFile(publicKeyPath, 'utf-8');
  const publicKey = fromBase64(publicKeyBase64.trim());
  const signatureBase64 = await readFile(signaturePath, 'utf-8');
  const signature = fromBase64(signatureBase64.trim());
  const filesToVerify = [manifestPath, ...getArtifactPaths(manifest, manifestDir)];
  
  const valid = await signer.verifyFiles(filesToVerify, signature, publicKey);
  
  if (!valid) {
    console.error('Verification FAILED');
    process.exit(1);
  }
  
  console.log('Verification successful');
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  const [mode, manifestPath, ...rest] = args;

  if (!mode || !manifestPath) {
    console.error('Usage: package-validation <mode> <manifest.json> [options]');
    console.error('Modes:');
    console.error('  keygen <manifest.json>                              - Generate keypair');
    console.error('  sign <manifest.json> <private-key>                  - Sign manifest and artifacts');
    console.error('  verify <manifest.json> <signature> <public-key>     - Verify signature');
    process.exit(1);
  }

  try {
    switch (mode) {
      case 'keygen':
        await keygen(manifestPath);
        break;
      case 'sign':
        const [privateKeyPath] = rest;
        if (!privateKeyPath) {
          console.error('sign requires: <manifest.json> <private-key>');
          process.exit(1);
        }
        
        await sign(manifestPath, privateKeyPath);
        break;
      case 'verify':
        const [signaturePath, publicKeyPath] = rest;
        if (!signaturePath || !publicKeyPath) {
          console.error('verify requires: <manifest.json> <signature> <public-key>');
          process.exit(1);
        }

        await verify(manifestPath, signaturePath, publicKeyPath);
        break;
      default:
        console.error(`Unknown mode: ${mode}`);
        process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}

main();
