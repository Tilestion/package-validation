import { keygen, sign, verify } from "./index";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  const [mode, manifestPath, ...rest] = args;

  if (!mode || !manifestPath) {
    console.log('Usage: tilestion-package-validation <mode> <manifest.json> [options]');
    console.log('Modes:');
    console.log('  keygen <manifest.json>                       - Generate keypair');
    console.log('  sign <manifest.json> <private-key>           - Sign manifest and artifacts');
    console.log('  verify <manifest.json> <public-key>          - Verify signature');
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
      const [publicKeyPath] = rest;
      if (!publicKeyPath) {
        throw new Error('verify requires: <manifest.json> <public-key>');
      }
      await verify(manifestPath, publicKeyPath);
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
