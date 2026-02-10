
export interface Signer {
  signFiles(filePaths: string[], secretKey: Uint8Array): Promise<Uint8Array>;
  verifyFiles(filePaths: string[], signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
  generateKeys(): { secretKey: Uint8Array, publicKey: Uint8Array };
}
