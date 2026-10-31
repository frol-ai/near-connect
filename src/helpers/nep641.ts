// NEP-641 primitives shared by the client-side default `resolveAuth`
// (helpers/resolveAuth.ts) and the offchain resolver (helpers/verifyResolveAuth.ts):
// the `OffchainMessage` envelope, its canonical hash, the NEP-413 mapping used
// by access-key authorizations, and key/signature encodings.
//
// Spec: https://github.com/near/NEPs/blob/master/neps/nep-0641.md

import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha3_256, keccak_256 } from "@noble/hashes/sha3.js";
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { base58 } from "@scure/base";

import type { Nep641AccessKeyAuthorization, Nep641OffchainMessage } from "../types";

/** NEP-413 prefix tag: `2^31 + 413`. */
export const NEP413_TAG = 2147484061;
/** Domain separator of the NEP-641 canonical hash. */
export const NEP641_DOMAIN_SEPARATOR = "NEAR_NEP641_OFFCHAIN_MESSAGE/V1";
/**
 * Clients SHOULD set `timestamp` ~60 seconds before signing time to absorb
 * clock skew and block-time lag.
 */
export const NEP641_TIMESTAMP_SKEW_MS = 60_000;

// ─── Borsh ───────────────────────────────────────────────────────────────────

export class BorshWriter {
  private buf: number[] = [];
  writeU8(v: number) {
    this.buf.push(v & 0xff);
  }
  writeU32(v: number) {
    this.buf.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
  }
  writeU64(v: bigint) {
    let x = BigInt.asUintN(64, v);
    for (let i = 0; i < 8; i++) {
      this.buf.push(Number(x & 0xffn));
      x >>= 8n;
    }
  }
  writeString(s: string) {
    const b = new TextEncoder().encode(s);
    this.writeU32(b.length);
    for (const c of b) this.buf.push(c);
  }
  writeBytes(b: Uint8Array) {
    for (const c of b) this.buf.push(c);
  }
  writeOptionString(s: string | null | undefined) {
    if (s == null) this.writeU8(0);
    else {
      this.writeU8(1);
      this.writeString(s);
    }
  }
  toBytes(): Uint8Array {
    return new Uint8Array(this.buf);
  }
}

// ─── Timestamps ──────────────────────────────────────────────────────────────

/**
 * Parse an RFC-3339 timestamp into UNIX nanoseconds, preserving sub-millisecond
 * precision (`Date.parse` alone would truncate it and break the canonical hash).
 */
export function rfc3339ToNanos(timestamp: string): bigint {
  const m = /^(\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/.exec(timestamp);
  if (!m) throw new Error(`invalid RFC-3339 timestamp: ${timestamp}`);
  const ms = Date.parse(`${m[1]}${m[3]}`);
  if (Number.isNaN(ms)) throw new Error(`invalid RFC-3339 timestamp: ${timestamp}`);
  const fraction = (m[2] ?? "").padEnd(9, "0").slice(0, 9);
  return BigInt(ms) * 1_000_000n + BigInt(fraction || "0");
}

/**
 * Render UNIX nanoseconds as RFC-3339 (`2026-08-05T07:28:00Z`, fractional part
 * only when non-zero).
 */
export function nanosToRfc3339(nanos: bigint): string {
  const seconds = nanos / 1_000_000_000n;
  const fraction = nanos % 1_000_000_000n;
  const base = new Date(Number(seconds) * 1000).toISOString().replace(".000Z", "");
  if (fraction === 0n) return `${base}Z`;
  return `${base}.${fraction.toString().padStart(9, "0").replace(/0+$/, "")}Z`;
}

/** RFC-3339 timestamp truncated to whole seconds (cosmetic, for `recipient`). */
export function truncateToSeconds(timestamp: string): string {
  return nanosToRfc3339((rfc3339ToNanos(timestamp) / 1_000_000_000n) * 1_000_000_000n);
}

/** Build a top-level envelope timestamped "now minus skew" (whole seconds). */
export function newOffchainMessage(args: {
  chainId: string;
  signerId: string;
  payload: string;
  path?: string[];
  signedAt?: Date;
}): Nep641OffchainMessage {
  const at = args.signedAt ?? new Date(Date.now() - NEP641_TIMESTAMP_SKEW_MS);
  const seconds = BigInt(Math.floor(at.getTime() / 1000));
  return {
    chain_id: args.chainId,
    signer_id: args.signerId,
    ...(args.path?.length ? { path: [...args.path] } : {}),
    timestamp: nanosToRfc3339(seconds * 1_000_000_000n),
    payload: args.payload,
  };
}

// ─── Canonical hash + NEP-413 mapping ────────────────────────────────────────

/** Borsh serialization of the envelope (timestamp as `u64` nanoseconds). */
export function borshOffchainMessage(msg: Nep641OffchainMessage): Uint8Array {
  const w = new BorshWriter();
  w.writeString(msg.chain_id);
  w.writeString(msg.signer_id);
  const path = msg.path ?? [];
  w.writeU32(path.length);
  for (const id of path) w.writeString(id);
  w.writeU64(rfc3339ToNanos(msg.timestamp));
  w.writeString(msg.payload);
  return w.toBytes();
}

/** `SHA3-256(b"NEAR_NEP641_OFFCHAIN_MESSAGE/V1" || borsh(msg))`. */
export function offchainMessageHash(msg: Nep641OffchainMessage): Uint8Array {
  return sha3_256
    .create()
    .update(new TextEncoder().encode(NEP641_DOMAIN_SEPARATOR))
    .update(borshOffchainMessage(msg))
    .digest();
}

/**
 * NEP-641 §"NEP-413 mapping": `recipient` renders the bindings for the user —
 * `"<chain_id>: <signer_id>[ -> <id>]... @ <timestamp>"` (path bottom-up,
 * timestamp truncated to whole seconds).
 */
export function nep413Recipient(msg: Nep641OffchainMessage): string {
  const ids = [msg.signer_id, ...(msg.path ?? [])].join(" -> ");
  return `${msg.chain_id}: ${ids} @ ${truncateToSeconds(msg.timestamp)}`;
}

export interface Nep413Payload {
  message: string;
  nonce: Uint8Array;
  recipient: string;
  callbackUrl?: string | null;
}

/** Map the envelope onto the NEP-413 payload a wallet's `signMessage` signs. */
export function toNep413Payload(msg: Nep641OffchainMessage, callbackUrl?: string | null): Nep413Payload {
  return {
    message: msg.payload,
    nonce: offchainMessageHash(msg),
    recipient: nep413Recipient(msg),
    callbackUrl: callbackUrl ?? null,
  };
}

/** NEP-413 hash: `sha256(tag ++ borsh(payload))`. */
export function nep413Hash(payload: Nep413Payload): Uint8Array {
  const w = new BorshWriter();
  w.writeU32(NEP413_TAG);
  w.writeString(payload.message);
  if (payload.nonce.length !== 32) throw new Error("nep-413 nonce must be 32 bytes");
  w.writeBytes(payload.nonce);
  w.writeString(payload.recipient);
  w.writeOptionString(payload.callbackUrl ?? null);
  return sha256(w.toBytes());
}

// ─── Keys & signatures ───────────────────────────────────────────────────────

const CURVES = ["ed25519", "secp256k1", "ml-dsa-65"] as const;

export type Curve = (typeof CURVES)[number];

export interface TypedBytes {
  curve: Curve;
  bytes: Uint8Array;
}

function parseTyped(s: string, what: string, sizes: Record<Curve, number>): TypedBytes {
  const idx = s.indexOf(":");
  if (idx < 0) throw new Error(`${what} must be "<curve>:<base58>"`);
  const prefix = s.slice(0, idx);
  const curve = CURVES.find((c) => c === prefix);
  if (!curve) throw new Error(`unsupported ${what} curve: ${prefix}`);
  const bytes = base58.decode(s.slice(idx + 1));
  if (bytes.length !== sizes[curve]) {
    throw new Error(`${curve} ${what} must be ${sizes[curve]} bytes, got ${bytes.length}`);
  }
  return { curve, bytes };
}

/**
 * `ed25519:<base58 32 bytes>` | `secp256k1:<base58 64 bytes, uncompressed without prefix>` |
 * `ml-dsa-65:<base58 1952 bytes>`.
 */
export function parsePublicKey(s: string): TypedBytes {
  return parseTyped(s, "public key", { ed25519: 32, secp256k1: 64, "ml-dsa-65": 1952 });
}

/** `ed25519:<base58 64 bytes>` | `secp256k1:<base58 65 bytes r||s||v>` | `ml-dsa-65:<base58 3309 bytes>`. */
export function parseSignature(s: string): TypedBytes {
  return parseTyped(s, "signature", { ed25519: 64, secp256k1: 65, "ml-dsa-65": 3309 });
}

export function encodeSignature(curve: Curve, bytes: Uint8Array): string {
  return `${curve}:${base58.encode(bytes)}`;
}

/**
 * Accept a NEP-413 `signMessage` signature as produced by wallets: either the
 * canonical raw base64 (ed25519) or the typed `<curve>:<base58>` form.
 */
export function normalizeNep413Signature(signature: string, publicKey: string): string {
  if (signature.includes(":")) return signature;
  const curve = parsePublicKey(publicKey).curve;
  const raw = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
  return encodeSignature(curve, raw);
}

/**
 * Verify `signature` over `hash` (32 bytes) for `publicKey`; curves MUST match.
 * `ml-dsa-65` isn't verified here, so it never passes — dApps verify those
 * server-side.
 */
export function verifyHash(hash: Uint8Array, publicKey: TypedBytes, signature: TypedBytes): boolean {
  if (publicKey.curve !== signature.curve) return false;
  try {
    switch (publicKey.curve) {
      case "ed25519":
        return ed25519.verify(signature.bytes, hash, publicKey.bytes);
      case "secp256k1": {
        // NEAR secp256k1: 65-byte recoverable signature (r || s || v) over an
        // uncompressed 64-byte public key (no 0x04 prefix).
        const recovered = secp256k1.Signature.fromBytes(signature.bytes.slice(0, 64), 'compact')
          .addRecoveryBit(signature.bytes[64])
          .recoverPublicKey(hash)
          .toBytes(false)
          .slice(1);
        return recovered.length === 64 && recovered.every((b, i) => b === publicKey.bytes[i]);
      }
      case "ml-dsa-65":
        return ml_dsa65.verify(signature.bytes, hash, publicKey.bytes);
    }
  } catch {
    return false;
  }
}

/**
 * Implicit account ID derived from a public key: hex(ed25519 key), or
 * `0x` + last 20 bytes of keccak256(uncompressed secp256k1 key). `ml-dsa-65`
 * keys have no implicit account.
 */
export function implicitAccountId(publicKey: TypedBytes): string | null {
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  switch (publicKey.curve) {
    case "ed25519":
      return hex(publicKey.bytes);
    case "secp256k1":
      return `0x${hex(keccak_256(publicKey.bytes).slice(12, 32))}`;
    case "ml-dsa-65":
      return null;
  }
}

// ─── Access-key authorization ────────────────────────────────────────────────

/** Serialize an access-key authorization to the blob string. */
export function encodeAccessKeyAuthorization(auth: Nep641AccessKeyAuthorization): string {
  const { path, ...rest } = auth.msg;
  return JSON.stringify({
    ...auth,
    msg: path?.length ? { ...rest, path } : rest,
  });
}

/**
 * Strictly parse an access-key authorization blob (unknown fields rejected, to
 * reduce collisions with contract-defined blob formats). Returns `null` when
 * the blob is not an access-key authorization at all.
 */
export function parseAccessKeyAuthorization(blob: string): Nep641AccessKeyAuthorization | null {
  let raw: unknown;
  try {
    raw = JSON.parse(blob);
  } catch {
    return null;
  }
  if (!isRecord(raw) || !hasOnlyKeys(raw, ["msg", "via", "access_key", "signature"])) return null;
  const { msg, via, access_key, signature } = raw;
  if (!isRecord(msg) || !hasOnlyKeys(msg, ["chain_id", "signer_id", "path", "timestamp", "payload"])) return null;
  if (
    typeof msg.chain_id !== "string" ||
    typeof msg.signer_id !== "string" ||
    typeof msg.timestamp !== "string" ||
    typeof msg.payload !== "string" ||
    (msg.path !== undefined && !(Array.isArray(msg.path) && msg.path.every((p) => typeof p === "string")))
  ) {
    return null;
  }
  if (!isRecord(via) || via.schema !== "nep413" || !isRecord(via.extra)) return null;
  if (via.extra.callback_url !== undefined && typeof via.extra.callback_url !== "string") return null;
  if (typeof access_key !== "string" || typeof signature !== "string") return null;
  return {
    msg: {
      chain_id: msg.chain_id,
      signer_id: msg.signer_id,
      ...(msg.path ? { path: msg.path as string[] } : {}),
      timestamp: msg.timestamp,
      payload: msg.payload,
    },
    via: { schema: "nep413", extra: via.extra.callback_url ? { callback_url: via.extra.callback_url } : {} },
    access_key,
    signature,
  };
}

/** Verify the signature of an access-key authorization per its `via` schema. */
export function verifyAccessKeyAuthorization(auth: Nep641AccessKeyAuthorization): boolean {
  try {
    const hash = nep413Hash(toNep413Payload(auth.msg, auth.via.extra.callback_url));
    return verifyHash(hash, parsePublicKey(auth.access_key), parseSignature(auth.signature));
  } catch {
    return false;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function hasOnlyKeys(v: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(v).every((k) => keys.includes(k));
}
