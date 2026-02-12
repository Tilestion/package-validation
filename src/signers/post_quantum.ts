import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import type { Signer } from '../sign';

export class MlDsa implements Signer {
  async signFiles(filePaths: string[], secretKey: Uint8Array): Promise<Uint8Array> {
    // 1. Read all files and hash their contents
    const hash = createHash('sha3-512');
    for (const filePath of filePaths.sort()) {
      const fileContent = await readFile(filePath);
      hash.update(fileContent);
    }
    
    // 2. Sign the combined hash using ML-DSA-65
    const signature = ml_dsa65.sign(hash.digest(), secretKey);
    
    return signature;
  }
  
  async verifyFiles(filePaths: string[], signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    // 1. Read all files and hash their contents
    const hash = createHash('sha3-512');
    for (const filePath of filePaths.sort()) {
      const fileContent = await readFile(filePath);
      hash.update(fileContent);
    }
    
    // 2. Verify the signature
    return ml_dsa65.verify(signature, hash.digest(), publicKey);
  }
  
  generateKeys(): { secretKey: Uint8Array, publicKey: Uint8Array } {
    return ml_dsa65.keygen();
  }
}
