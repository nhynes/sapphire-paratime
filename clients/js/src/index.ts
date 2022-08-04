export { wrapSigner } from './compat.js';
export { makeSignableCall, prepareSignedCall } from './signed_calls.js';

export const MAINNET_CHAIN_ID = 0x5afe;
export const TESTNET_CHAIN_ID = 0x5aff;

// These are the same ones from the PT's Cargo.toml.
export const TESTNET_RT_ID =
  '000000000000000000000000000000000000000000000000a6d1e3ebf60dff6c';
export const MAINNET_RT_ID =
  '0000000000000000000000000000000000000000000000000000000000000000';
