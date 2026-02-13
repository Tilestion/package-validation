import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'crypto';
import canonicalize from 'canonicalize';
import type { Signer } from '../sign';

export class MlDsa implements Signer {
  async sign(data: object, secretKey: Uint8Array): Promise<Uint8Array> {
    // 1. Read all files and hash their contents
    const hash = createHash('sha3-512');
    const bytes = new TextEncoder().encode(canonicalize(data));
    hash.update(bytes);
    
    // 2. Sign the combined hash using ML-DSA-65
    const signature = ml_dsa65.sign(hash.digest(), secretKey);
    
    return signature;
  }
  
  async verify(data: object, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    // 1. Read all files and hash their contents
    const hash = createHash('sha3-512');
    const bytes = new TextEncoder().encode(canonicalize(data));
    hash.update(bytes);
    
    // 2. Verify the signature
    return ml_dsa65.verify(signature, hash.digest(), publicKey);
  }
  
  generateKeys(): { secretKey: Uint8Array, publicKey: Uint8Array } {
    return ml_dsa65.keygen();
  }
}
