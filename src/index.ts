import { readFile, writeFile } from 'fs/promises';
import { dirname, join } from 'path';
import { MlDsa } from './signers/post_quantum';
import { Ed25519 } from './signers/classical';
import type { Signer } from './sign';
import { hashFile } from './hash';

interface Signature {
  metadata: SignatureMetadata;
  signature: string;
}

interface SignatureMetadata {
  type: string;
  keyId: string;
}

interface Manifest {
  package: {
    id: string;
    name: string;
  };
  signature: SignatureMetadata;
  artifacts: {
    [key: string]: {
      path: string;
      hash?: string;
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

function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

function fromBase64(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, 'base64'));
}

export async function keygen(manifestPath: string): Promise<void> {
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.type);
  
  const { secretKey, publicKey } = signer.generateKeys();
  const manifestDir = dirname(manifestPath);
  
  await writeFile(join(manifestDir, `${manifest.signature.keyId}.priv`), toBase64(secretKey));
  await writeFile(join(manifestDir, `${manifest.signature.keyId}.pub`), toBase64(publicKey));
  
  console.log(`Generated keys: ${manifest.signature.keyId}.priv, ${manifest.signature.keyId}.pub`);
}

export async function sign(manifestPath: string, privateKeyPath: string): Promise<void> {
  // parse manifest
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);
  const signer = getSigner(manifest.signature.type);
  const manifestDir = dirname(manifestPath);

  // Generate hashes
  for (const artifact of Object.values(manifest.artifacts)) {
    artifact.hash = toBase64(await hashFile(artifact.path));
  }

  await writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
  
  // sign manifest
  const secretKeyBase64 = await readFile(privateKeyPath, 'utf-8');
  const secretKey = fromBase64(secretKeyBase64.trim());

  const raw_signature = await signer.signFile(manifestPath, secretKey);

  const signature: Signature = {
    metadata: manifest.signature,
    signature: toBase64(raw_signature),
  };
  const sigPath = join(manifestDir, `manifest.sig`);
  await writeFile(sigPath, JSON.stringify(signature), 'utf-8');
  
  console.log(`Signature written to: ${sigPath}`);
}

export async function verify(manifestPath: string, signaturePath: string, publicKeyPath: string): Promise<void> {
  // verify manifest
  const publicKeyContent = await readFile(publicKeyPath, 'utf-8');
  const publicKey = fromBase64(publicKeyContent.trim());
  
  const signatureContent = await readFile(signaturePath, 'utf-8');
  const signature: Signature = JSON.parse(signatureContent);
  
  const signer = getSigner(signature.metadata.type);
  const valid = await signer.verifyFile(manifestPath, fromBase64(signature.signature), publicKey);

  if (!valid) {
    throw new Error('Manifest verification FAILED');
  }

  // parse manifest
  const manifestContent = await readFile(manifestPath, 'utf-8');
  const manifest: Manifest = JSON.parse(manifestContent);

  // verify hashes
  for (const artifact of Object.values(manifest.artifacts)) {
    if (artifact.hash !== toBase64(await hashFile(artifact.path))) {
      throw new Error('Hash verification of artifact ${artifact.path} FAILED');
    }
  }
  
  console.log('Verification successful');
}
