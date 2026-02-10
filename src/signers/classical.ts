import { createHash, generateKeyPairSync, sign, verify } from 'crypto';
import { readFile } from 'fs/promises';
import type { Signer } from '../sign.ts';

export class Ed25519 implements Signer {
  async signFiles(filePaths: string[], secretKey: Uint8Array): Promise<Uint8Array> {
    // 1. Read all files and hash their contents
    const hash = createHash('sha512');
    for (const filePath of filePaths.sort()) {
      const fileContent = await readFile(filePath);
      hash.update(fileContent);
    }
    
    // 2. Sign the hash using Ed25519
    const signature = sign(null, hash.digest(), {
      key: Buffer.from(secretKey),
      format: 'der',
      type: 'pkcs8'
    });
    
    return new Uint8Array(signature);
  }
  
  async verifyFiles(filePaths: string[], signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    // 1. Read all files and hash their contents
    const hash = createHash('sha512');
    for (const filePath of filePaths.sort()) {
      const fileContent = await readFile(filePath);
      hash.update(fileContent);
    }
    
    // 2. Verify the signature
    return verify(null, hash.digest(), {
      key: Buffer.from(publicKey),
      format: 'der',
      type: 'spki'
    }, signature);
  }
  
  generateKeys(): { secretKey: Uint8Array, publicKey: Uint8Array } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    
    return {
      secretKey: new Uint8Array(privateKey),
      publicKey: new Uint8Array(publicKey)
    };
  }
}
