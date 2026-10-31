import type { Nep641AccessKeyAuthorization, Nep641OffchainMessage } from "../types";
/** NEP-413 prefix tag: `2^31 + 413`. */
export declare const NEP413_TAG = 2147484061;
/** Domain separator of the NEP-641 canonical hash. */
export declare const NEP641_DOMAIN_SEPARATOR = "NEAR_NEP641_OFFCHAIN_MESSAGE/V1";
/**
 * Clients SHOULD set `timestamp` ~60 seconds before signing time to absorb
 * clock skew and block-time lag.
 */
export declare const NEP641_TIMESTAMP_SKEW_MS = 60000;
export declare class BorshWriter {
    private buf;
    writeU8(v: number): void;
    writeU32(v: number): void;
    writeU64(v: bigint): void;
    writeString(s: string): void;
    writeBytes(b: Uint8Array): void;
    writeOptionString(s: string | null | undefined): void;
    toBytes(): Uint8Array;
}
/**
 * Parse an RFC-3339 timestamp into UNIX nanoseconds, preserving sub-millisecond
 * precision (`Date.parse` alone would truncate it and break the canonical hash).
 */
export declare function rfc3339ToNanos(timestamp: string): bigint;
/**
 * Render UNIX nanoseconds as RFC-3339 (`2026-08-05T07:28:00Z`, fractional part
 * only when non-zero).
 */
export declare function nanosToRfc3339(nanos: bigint): string;
/** RFC-3339 timestamp truncated to whole seconds (cosmetic, for `recipient`). */
export declare function truncateToSeconds(timestamp: string): string;
/** Build a top-level envelope timestamped "now minus skew" (whole seconds). */
export declare function newOffchainMessage(args: {
    chainId: string;
    signerId: string;
    payload: string;
    path?: string[];
    signedAt?: Date;
}): Nep641OffchainMessage;
/** Borsh serialization of the envelope (timestamp as `u64` nanoseconds). */
export declare function borshOffchainMessage(msg: Nep641OffchainMessage): Uint8Array;
/** `SHA3-256(b"NEAR_NEP641_OFFCHAIN_MESSAGE/V1" || borsh(msg))`. */
export declare function offchainMessageHash(msg: Nep641OffchainMessage): Uint8Array;
/**
 * NEP-641 §"NEP-413 mapping": `recipient` renders the bindings for the user —
 * `"<chain_id>: <signer_id>[ -> <id>]... @ <timestamp>"` (path bottom-up,
 * timestamp truncated to whole seconds).
 */
export declare function nep413Recipient(msg: Nep641OffchainMessage): string;
export interface Nep413Payload {
    message: string;
    nonce: Uint8Array;
    recipient: string;
    callbackUrl?: string | null;
}
/** Map the envelope onto the NEP-413 payload a wallet's `signMessage` signs. */
export declare function toNep413Payload(msg: Nep641OffchainMessage, callbackUrl?: string | null): Nep413Payload;
/** NEP-413 hash: `sha256(tag ++ borsh(payload))`. */
export declare function nep413Hash(payload: Nep413Payload): Uint8Array;
declare const CURVES: readonly ["ed25519", "secp256k1", "ml-dsa-65"];
export type Curve = (typeof CURVES)[number];
export interface TypedBytes {
    curve: Curve;
    bytes: Uint8Array;
}
/**
 * `ed25519:<base58 32 bytes>` | `secp256k1:<base58 64 bytes, uncompressed without prefix>` |
 * `ml-dsa-65:<base58 1952 bytes>`.
 */
export declare function parsePublicKey(s: string): TypedBytes;
/** `ed25519:<base58 64 bytes>` | `secp256k1:<base58 65 bytes r||s||v>` | `ml-dsa-65:<base58 3309 bytes>`. */
export declare function parseSignature(s: string): TypedBytes;
export declare function encodeSignature(curve: Curve, bytes: Uint8Array): string;
/**
 * Accept a NEP-413 `signMessage` signature as produced by wallets: either the
 * canonical raw base64 (ed25519) or the typed `<curve>:<base58>` form.
 */
export declare function normalizeNep413Signature(signature: string, publicKey: string): string;
/**
 * Verify `signature` over `hash` (32 bytes) for `publicKey`; curves MUST match.
 * `ml-dsa-65` isn't verified here, so it never passes — dApps verify those
 * server-side.
 */
export declare function verifyHash(hash: Uint8Array, publicKey: TypedBytes, signature: TypedBytes): boolean;
/**
 * Implicit account ID derived from a public key: hex(ed25519 key), or
 * `0x` + last 20 bytes of keccak256(uncompressed secp256k1 key). `ml-dsa-65`
 * keys have no implicit account.
 */
export declare function implicitAccountId(publicKey: TypedBytes): string | null;
/** Serialize an access-key authorization to the blob string. */
export declare function encodeAccessKeyAuthorization(auth: Nep641AccessKeyAuthorization): string;
/**
 * Strictly parse an access-key authorization blob (unknown fields rejected, to
 * reduce collisions with contract-defined blob formats). Returns `null` when
 * the blob is not an access-key authorization at all.
 */
export declare function parseAccessKeyAuthorization(blob: string): Nep641AccessKeyAuthorization | null;
/** Verify the signature of an access-key authorization per its `via` schema. */
export declare function verifyAccessKeyAuthorization(auth: Nep641AccessKeyAuthorization): boolean;
export {};
