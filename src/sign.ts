
export interface Signer {
  sign(data: object, secretKey: Uint8Array): Promise<Uint8Array>;
  verify(data: object, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
  generateKeys(): { secretKey: Uint8Array, publicKey: Uint8Array };
}
