import { createHash } from 'crypto';
import { readFile } from 'fs/promises';

export async function hashFile(filePath: string): Promise<Uint8Array> {
  const hash = createHash('sha-256');
  hash.update(await readFile(filePath));
  return hash.digest();
}
