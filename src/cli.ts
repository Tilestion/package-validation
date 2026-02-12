import { keygen, sign, verify } from "./index"

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  const [mode, manifestPath, ...rest] = args;

  if (!mode || !manifestPath) {
    console.error('Usage: validator <mode> <manifest.json> [options]');
    console.error('Modes:');
    console.error('  keygen <manifest.json>                              - Generate keypair');
    console.error('  sign <manifest.json> <private-key>                  - Sign manifest and artifacts');
    console.error('  verify <manifest.json> <signature> <public-key>     - Verify signature');
    throw new Error('Missing required arguments');
  }

  switch (mode) {
    case 'keygen':
      await keygen(manifestPath);
      break;
    case 'sign': {
      const [privateKeyPath] = rest;
      if (!privateKeyPath) {
        throw new Error('sign requires: <manifest.json> <private-key>');
      }
      await sign(manifestPath, privateKeyPath);
      break;
    }
    case 'verify': {
      const [signaturePath, publicKeyPath] = rest;
      if (!signaturePath || !publicKeyPath) {
        throw new Error('verify requires: <manifest.json> <signature> <public-key>');
      }
      await verify(manifestPath, signaturePath, publicKeyPath);
      break;
    }
    default:
      throw new Error(`Unknown mode: ${mode}`);
  }
}

main().catch((err) => {
  console.error(`Error: ${err instanceof Error ? err.message : err}`);
  process.exit(1);
});
