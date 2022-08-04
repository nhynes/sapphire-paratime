import {
  Signer as EthersSigner,
  TypedDataSigner,
} from '@ethersproject/abstract-signer';
import { BigNumber } from '@ethersproject/bignumber';
import {
  BytesLike,
  arrayify,
  hexlify,
  isBytesLike,
} from '@ethersproject/bytes';
import {
  Provider as EthersProvider,
  TransactionRequest,
  Web3Provider,
  JsonRpcSigner,
} from '@ethersproject/providers';
import * as cbor from 'cborg';

import callformat, {
  MetaEncryptedX25519DeoxysII,
} from '@oasisprotocol/client-rt/dist/callformat.js';
import { NodeInternal } from '@oasisprotocol/client/dist/client';
import { Wrapper as CoreWrapper } from '@oasisprotocol/client-rt/dist/core.js';
import { CALLFORMAT_ENCRYPTED_X25519DEOXYSII } from '@oasisprotocol/client-rt/dist/transaction.js';
import { KeyManagerSignedPublicKey } from '@oasisprotocol/client-rt/dist/types.js';

import { EthCall, prepareSignedCall } from './signed_calls.js';
import {
  MAINNET_CHAIN_ID,
  MAINNET_RT_ID,
  TESTNET_CHAIN_ID,
  TESTNET_RT_ID,
} from './index.js';

const TESTNET_RPC = 'https://grpc.oasis.dev';
const MAINNET_RPC = 'https://testnet.grpc.oasis.dev';

const PK_CACHE: Map<number /* chain id */, KeyManagerSignedPublicKey> =
  new Map();

export type UpstreamProvider =
  | { request: (args: Web3ReqArgs) => Promise<unknown> } // EIP-1193
  | { sendAsync: AsyncSend } // old MetaMask
  | { send: AsyncSend } // Web3.js
  | (EthersSigner & TypedDataSigner);

type AsyncSend = (
  args: Web3ReqArgs,
  cb: (err: unknown, ok?: unknown) => void,
) => void;

interface Web3ReqArgs {
  readonly method: string;
  readonly params?: readonly unknown[] | object;
}

function hookEthersCall<T>(
  signer: EthersSigner & TypedDataSigner,
  call: EthersCall<T>,
): EthersCall<T> {
  return async (callP, ...rest) => {
    return call(
      (await callNeedsSigning(callP))
        ? await prepareSignedCall(undefer(callP) as unknown as EthCall, signer)
        : callP,
      ...rest,
    );
  };
}

async function callNeedsSigning(
  callP: Deferrable<TransactionRequest>,
): Promise<boolean> {
  const [from, to] = await Promise.all([callP.from, callP.to]);
  return to !== undefined && from !== undefined && !/^(0x)?0{40}$/.test(from);
}

type EthersCall<T> = (
  tx: Deferrable<TransactionRequest>,
  ...rest: unknown[]
) => Promise<T>;

type Deferrable<T> = {
  [K in keyof T]: T[K] | Promise<T[K]>;
};

async function undefer<T>(obj: Deferrable<T>): Promise<T> {
  return Object.fromEntries(
    await Promise.all(Object.entries(obj).map(async ([k, v]) => [k, await v])),
  );
}

type ProviderOptions = Partial<{
  /** The custom Sapphire GRPC endpoint. */
  rpc: string;
  runtimeId: string;
}>;

export function wrapSigner<T extends UpstreamProvider>(
  upstream: T,
  opts?: ProviderOptions,
): T {
  if (EthersSigner.isSigner(upstream) && '_signTypedData' in upstream) {
    const signer: EthersSigner & TypedDataSigner = upstream;
    const provider = signer.provider;
    if (provider === undefined) {
      throw new Error(
        'ethers Signer must be connected to a Provider before wrapping',
      );
    }
    return signer.connect(
      new Proxy(provider as EthersProvider, {
        get(target, prop) {
          if (prop === 'sendTransaction') {
            return (async (signedTx) => {
              const [ptTx, chainId] = await Promise.all([
                signedTx,
                signer.getChainId(),
              ]);
              const [encTx] = await encrypt(ptTx, chainId, opts);
              return provider.sendTransaction(encTx);
            }) as EthersProvider['sendTransaction'];
          }
          if (prop === 'call') {
            return hookEthersCall(
              signer,
              provider.call.bind(provider) as EthersCall<string>,
            );
          }
          if (prop === 'estimateGas') {
            return hookEthersCall(
              signer,
              provider.estimateGas.bind(provider) as EthersCall<BigNumber>,
            );
          }
          return Reflect.get(target, prop).bind(target);
        },
      }),
    ) as T;
  }

  return new Proxy(upstream, {
    get(target, prop) {
      if (prop !== 'request') return Reflect.get(target, prop).bind(target);
      const signer = new Web3Provider(upstream).getSigner();
      return async (args: Web3ReqArgs) => {
        const [params, meta] = await prepareRequest(args, signer, opts);
        // TODO: decryt call response
        const res = await signer.provider.send(args.method, params);
        if (
          !args.method.endsWith('call') ||
          !meta ||
          typeof res.data !== 'string'
        )
          return res;
        return decrypt(arrayify(res.data), meta);
      };
    },
  });
}

async function prepareRequest(
  { method, params }: Web3ReqArgs,
  signer: JsonRpcSigner,
  opts: ProviderOptions | undefined,
): Promise<[unknown[], MetaEncryptedX25519DeoxysII?]> {
  if (!Array.isArray(params)) return [[params]];

  const enc = async (data: BytesLike, chainId?: number) =>
    encrypt(data, chainId ?? (await signer.getChainId()), opts);

  if (method.endsWith('sendRawTransaction')) {
    return [[enc(params[0]), ...params.slice(1)]];
  }

  if (
    (method.endsWith('call') || method.endsWith('estimateGas')) &&
    (await callNeedsSigning(params[0]))
  ) {
    const chainId = await signer.getChainId();
    const [encData, meta] = await enc(params[0].data ?? [], chainId);
    params[0].data = encData;
    return [
      [prepareSignedCall(params[0], signer, { chainId }), ...params.slice(1)],
      meta,
    ];
  }

  if (
    method.endsWith('sendTransaction') ||
    method.endsWith('signTransaction')
  ) {
    if (isBytesLike(params[0].data)) {
      params[0].data = (await enc(params[0]))[0];
    }
    return [params];
  }

  return [params];
}

async function encrypt(
  data: BytesLike,
  chainId: number,
  opts: ProviderOptions | undefined,
): Promise<[string, MetaEncryptedX25519DeoxysII?]> {
  if (data.length === 0) return [hexlify(data)];

  const [packed, meta] = await callformat.encodeCall(
    {
      method: '',
      body: arrayify(data),
    },
    CALLFORMAT_ENCRYPTED_X25519DEOXYSII,
    { publicKey: await fetchRTPubKey(chainId, opts) },
  );
  return [hexlify(cbor.encode(packed)), meta as MetaEncryptedX25519DeoxysII];
}

async function decrypt(
  data: Uint8Array,
  meta: MetaEncryptedX25519DeoxysII,
): Promise<string> {
  const callResult = cbor.decode(data);
  const { ok, fail, unknown, ...trulyUnknown } = await callformat.decodeResult(
    callResult,
    CALLFORMAT_ENCRYPTED_X25519DEOXYSII,
    meta,
  );

  if (ok) {
    if (typeof ok === 'string') return ok;
    const err = new Error(`unexpected EVM response: ${ok}`);
    (err as any).response = ok;
    throw err;
  }

  if (fail) {
    const msg = fail.message
      ? fail.message
      : `call failed in ${fail.module} with code ${fail.code}`;
    const err = new Error(msg);
    (err as any).cause = fail;
    throw err;
  }

  if (unknown) {
    const err = new Error(`unexpected EVM response: ${unknown}`);
    (err as any).response = unknown;
    throw err;
  }

  const err = new Error('unknown response from runtime');
  (err as any).response = trulyUnknown;
  throw err;
}

async function fetchRTPubKey(
  chainId: number,
  opts?: ProviderOptions,
): Promise<KeyManagerSignedPublicKey> {
  const cached = PK_CACHE.get(chainId);
  if (cached) return cached;

  const rtId = opts?.runtimeId ?? inferRuntimeId(chainId);
  const rpc = opts?.rpc ?? inferRpcUrl(chainId);
  const { public_key: publicKey } = await new CoreWrapper(arrayify(rtId))
    .queryCallDataPublicKey()
    .query(new NodeInternal(rpc));
  PK_CACHE.set(chainId, publicKey);
  return publicKey;
}

function inferRuntimeId(chainId: number): string {
  if (chainId === MAINNET_CHAIN_ID) return MAINNET_RT_ID;
  if (chainId === TESTNET_CHAIN_ID) return TESTNET_RT_ID;
  throw new Error(
    `Unable to infer runtime ID for chain ${chainId}. Please switch to the Sapphire Mainnet or Testnet, or provide an explicit runtime ID.`,
  );
}

function inferRpcUrl(chainId: number): string {
  if (chainId === MAINNET_CHAIN_ID) return MAINNET_RPC;
  if (chainId === TESTNET_CHAIN_ID) return TESTNET_RPC;
  throw new Error(
    `Unable to infer Oasis Node RPC URL for chain ${chainId}. Please switch to the Sapphire Mainnet or Testnet, or provide an explicit RPC URL.`,
  );
}
