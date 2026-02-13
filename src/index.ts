import { readFile, writeFile } from 'fs/promises';
import { dirname, join } from 'path';
import { MlDsa } from './signers/post_quantum';
import { Ed25519 } from './signers/classical';
import type { Signer } from './sign';
import { hashFile } from './hash';

interface Payload {
  package: {
    id: string;
    name: string;
  };
  artifacts: {
    [key: string]: {
      path: string;
      hash?: string;
    };
  };
}

interface Signature {
  metadata: {
    type: string;
    keyId: string;
  }
  signature?: string;
}

interface Manifest {
  payload: Payload;
  signature: Signature;
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

function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

function fromBase64(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, 'base64'));
}

export async function keygen(manifestPath: string): Promise<void> {
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.metadata.type);
  
  const { secretKey, publicKey } = signer.generateKeys();
  const manifestDir = dirname(manifestPath);
  
  await writeFile(join(manifestDir, `${manifest.signature.metadata.keyId}.priv`), toBase64(secretKey));
  await writeFile(join(manifestDir, `${manifest.signature.metadata.keyId}.pub`), toBase64(publicKey));
  
  console.log(`Generated keys: ${manifest.signature.metadata.keyId}.priv, ${manifest.signature.metadata.keyId}.pub`);
}

export async function sign(manifestPath: string, privateKeyPath: string): Promise<void> {
  // parse manifest
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.metadata.type);

  // Generate hashes
  for (const artifact of Object.values(manifest.payload.artifacts)) {
    artifact.hash = toBase64(await hashFile(artifact.path));
  }
  
  // sign manifest
  const secretKeyBase64 = await readFile(privateKeyPath, 'utf-8');
  const secretKey = fromBase64(secretKeyBase64.trim());

  manifest.signature.signature = toBase64(await signer.sign(manifest.payload, secretKey));

  // save manifest
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
  
  console.log(`Signature written to manifest`);
}

export async function verify(manifestPath: string, publicKeyPath: string): Promise<void> {
  // parse manifest
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.metadata.type);
  
  if (!manifest.signature.signature) {
    throw new Error('No signature in Manifest');
  }
  
  // verify manifest
  const publicKeyContent = await readFile(publicKeyPath, 'utf-8');
  const publicKey = fromBase64(publicKeyContent.trim());


  const valid = await signer.verify(manifest.payload, fromBase64(manifest.signature.signature), publicKey);

  if (!valid) {
    throw new Error('Manifest verification FAILED');
  }

  // verify hashes
  for (const artifact of Object.values(manifest.payload.artifacts)) {
    if (artifact.hash !== toBase64(await hashFile(artifact.path))) {
      throw new Error(`Hash verification of artifact ${artifact.path} FAILED`);
    }
  }
  
  console.log('Verification successful');
}
