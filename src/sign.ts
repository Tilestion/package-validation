
export interface Signer {
  signFile(filePath: string, secretKey: Uint8Array): Promise<Uint8Array>;
  verifyFile(filePath: string, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
  generateKeys(): { secretKey: Uint8Array, publicKey: Uint8Array };
}
