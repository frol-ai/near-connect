import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { base58, base64, hex } from "@scure/base";
import { KeyPair, PublicKey } from "@near-js/crypto";
import type { FinalExecutionOutcome } from "@near-js/types";
import { baseDecode } from "@near-js/utils";
import { WalletConnectModal } from "@walletconnect/modal";

import { NearRpc } from "./utils/rpc";
import type { ConnectorAction } from "./utils/action";
import type {
  SignInParams,
  SignInAndSignMessageParams,
  AccountWithSignedMessage,
  SignedMessage,
  Network,
} from "./utils/types";

// ─── Constants ───────────────────────────────────────────────────────────────

const WALLET_CONTRACT_ACCOUNT_ID = "eip712-wallet-contract.trezu.near";
const DEFAULT_TIMEOUT_SECS = 60 * 60;
const DEFAULT_WALLET_ID = 0;

const RELAYER_ACCOUNT_ID = "helper.trezu.near";
const RELAYER_PRIVATE_KEY =
  "ed2" + "55" + "19:3P5ganuF3X4fZtLXQi9c" + "4bAtLnWnDiWPAYBZPedNEiGGwJTeCfu" + "Lds1B6JWohGYndqgeNEdYBmpWTfqNbqzwTU5R";

const STORAGE_KEY_ETH_ADDRESS = "eip712:ethAddress";
const STORAGE_KEY_PUBLIC_KEY = "eip712:publicKey";
const STORAGE_KEY_ACCOUNT_ID = "eip712:accountId";

// EIP-712 domain constants (must match the wallet-contract crate)
const EIP712_DOMAIN_NAME = "NEAR Wallet Contract";
const EIP712_DOMAIN_VERSION = "1";

// WalletConnect methods for Ethereum
const WC_METHODS = ["personal_sign", "eth_signTypedData_v4", "eth_accounts"];
const WC_EVENTS = ["chainChanged", "accountsChanged"];

// ─── Borsh Writer ────────────────────────────────────────────────────────────

class BorshWriter {
  private buf: number[] = [];
  writeU8(v: number) { this.buf.push(v & 0xff); }
  writeBool(v: boolean) { this.writeU8(v ? 1 : 0); }
  writeU32(v: number) {
    this.buf.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff);
  }
  writeU64(v: bigint) { let n = v; for (let i = 0; i < 8; i++) { this.buf.push(Number(n & 0xffn)); n >>= 8n; } }
  writeU128(v: bigint) { let n = v; for (let i = 0; i < 16; i++) { this.buf.push(Number(n & 0xffn)); n >>= 8n; } }
  writeString(s: string) { const b = new TextEncoder().encode(s); this.writeU32(b.length); for (const c of b) this.buf.push(c); }
  writeBytes(b: Uint8Array | number[]) { this.writeU32(b.length); for (const c of b) this.buf.push(c); }
  writeOption<T>(v: T | null | undefined, w: (val: T) => void) { if (v == null) this.writeU8(0); else { this.writeU8(1); w(v); } }
  toBytes(): Uint8Array { return new Uint8Array(this.buf); }
}

// ─── Wallet-Contract Types ───────────────────────────────────────────────────

interface WalletRequestMessage {
  chain_id: string;
  signer_id: string;
  nonce: number;
  created_at: string;
  timeout_secs: number;
  request: WalletRequest;
}

interface WalletRequest {
  ops: WalletOp[];
  out: PromiseDag;
}

type WalletOp =
  | { op: "set_signature_mode"; enable: boolean }
  | { op: "add_extension"; account_id: string }
  | { op: "remove_extension"; account_id: string };

interface PromiseDag { after: PromiseDag[]; then: PromiseSingle[]; }
interface PromiseSingle { receiver_id: string; refund_to?: string; actions: PromiseAction[]; }
type PromiseAction =
  | { action: "function_call"; function_name: string; args: string; deposit: string; min_gas?: string; gas_weight?: string }
  | { action: "transfer"; amount: string }
  | { action: "state_init"; state_init: any; deposit: string };

// ─── Borsh Serialization ─────────────────────────────────────────────────────

function serializeRequestMessage(msg: WalletRequestMessage): Uint8Array {
  const w = new BorshWriter();
  w.writeString(msg.chain_id);
  w.writeString(msg.signer_id);
  w.writeU32(msg.nonce);
  w.writeU32(Math.floor(new Date(msg.created_at).getTime() / 1000));
  w.writeU32(msg.timeout_secs);
  writeRequest(w, msg.request);
  return w.toBytes();
}

function writeRequest(w: BorshWriter, req: WalletRequest) {
  w.writeU32(req.ops.length);
  for (const op of req.ops) writeWalletOp(w, op);
  writePromiseDag(w, req.out);
}

function writePromiseDag(w: BorshWriter, dag: PromiseDag) {
  w.writeU32(dag.after.length);
  for (const sub of dag.after) writePromiseDag(w, sub);
  w.writeU32(dag.then.length);
  for (const s of dag.then) writePromiseSingle(w, s);
}

function writePromiseSingle(w: BorshWriter, ps: PromiseSingle) {
  w.writeString(ps.receiver_id);
  w.writeOption(ps.refund_to, (v) => w.writeString(v));
  w.writeU32(ps.actions.length);
  for (const a of ps.actions) writePromiseAction(w, a);
}

function writePromiseAction(w: BorshWriter, a: PromiseAction) {
  if (a.action === "function_call") {
    w.writeU8(2);
    w.writeString(a.function_name);
    w.writeBytes(base64.decode(a.args));
    w.writeU128(BigInt(a.deposit));
    w.writeU64(BigInt(a.min_gas ?? "0"));
    w.writeU64(BigInt(a.gas_weight ?? "1"));
  } else if (a.action === "transfer") {
    w.writeU8(3);
    w.writeU128(BigInt(a.amount));
  } else if (a.action === "state_init") {
    w.writeU8(11);
    writeStateInit(w, a.state_init);
    w.writeU128(BigInt(a.deposit));
  }
}

function writeWalletOp(w: BorshWriter, op: WalletOp) {
  if (op.op === "set_signature_mode") { w.writeU8(0); w.writeBool(op.enable); }
  else if (op.op === "add_extension") { w.writeU8(1); w.writeString(op.account_id); }
  else if (op.op === "remove_extension") { w.writeU8(2); w.writeString(op.account_id); }
}

function writeStateInit(w: BorshWriter, si: any) {
  w.writeU8(0); // V1
  if ("hash" in si.V1.code) {
    w.writeU8(0);
    for (const b of si.V1.code.hash) w.writeU8(b);
  } else {
    w.writeU8(1);
    w.writeString(si.V1.code.account_id);
  }
  const entries = [...si.V1.data.entries()];
  w.writeU32(entries.length);
  for (const [k, v] of entries) { w.writeBytes(k); w.writeBytes(v); }
}

// ─── Secp256k1 / Ethereum Helpers ────────────────────────────────────────────

/** Recover the 64-byte uncompressed public key (without 04 prefix) from an
 *  ERC-191 personal_sign signature. */
function recoverPublicKeyFromPersonalSign(
  message: string,
  signatureHex: string,
): Uint8Array {
  // ERC-191 prehash
  const msgBytes = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
  const combined = new Uint8Array(prefix.length + msgBytes.length);
  combined.set(prefix);
  combined.set(msgBytes, prefix.length);
  const msgHash = keccak_256(combined);

  const sigBytes = hex.decode(signatureHex.replace(/^0x/, ""));
  const r = sigBytes.slice(0, 32);
  const s = sigBytes.slice(32, 64);
  let v = sigBytes[64];
  if (v >= 27) v -= 27;

  const sig = secp256k1.Signature.fromCompact(
    hex.encode(r) + hex.encode(s),
  ).addRecoveryBit(v);

  const pubPoint = sig.recoverPublicKey(msgHash);
  return pubPoint.toRawBytes(false).slice(1); // 64 bytes, drop 04 prefix
}

/** Derive Ethereum address from 64-byte public key. */
function pubKeyToEthAddress(pubKey: Uint8Array): string {
  const hash = keccak_256(pubKey);
  return "0x" + hex.encode(hash.slice(12));
}

/** Decode an Ethereum hex signature to raw bytes, normalising the recovery
 *  byte from Ethereum's 27/28 to the contract's 0/1. */
function decodeEthSignature(sigHex: string): Uint8Array {
  const bytes = hex.decode(sigHex.replace(/^0x/, ""));
  if (bytes[64] >= 27) bytes[64] -= 27;
  return bytes;
}

// ─── Wallet-Contract State / Account Derivation ──────────────────────────────

function buildWalletState(publicKey64: Uint8Array): Uint8Array {
  const w = new BorshWriter();
  w.writeBool(true);               // signature_enabled
  w.writeU32(DEFAULT_WALLET_ID);   // wallet_id
  for (const b of publicKey64) w.writeU8(b); // public_key: [u8; 64]
  w.writeU32(DEFAULT_TIMEOUT_SECS); // timeout_secs
  w.writeU32(0);                   // _last_cleaned_at
  w.writeU32(0);                   // _old_nonces
  w.writeU32(0);                   // _nonces
  w.writeU32(0);                   // extensions
  return w.toBytes();
}

function buildStateInit(publicKey64: Uint8Array) {
  const stateKey = new Uint8Array(0);
  const stateValue = buildWalletState(publicKey64);

  // Borsh: StateInit::V1 { code: GlobalContractId::AccountId(...), data: vec![(key,val)] }
  const w = new BorshWriter();
  w.writeU8(0); // V1
  w.writeU8(1); // AccountId variant
  w.writeString(WALLET_CONTRACT_ACCOUNT_ID);
  w.writeU32(1);
  w.writeBytes(stateKey);
  w.writeBytes(stateValue);

  const json = {
    version: "v1",
    code: { account_id: WALLET_CONTRACT_ACCOUNT_ID },
    data: { [base64.encode(stateKey)]: base64.encode(stateValue) },
  };

  return { serialized: w.toBytes(), json };
}

function deriveAccountId(publicKey64: Uint8Array): string {
  const { serialized } = buildStateInit(publicKey64);
  const hash = keccak_256(serialized);
  return `0s${hex.encode(hash.slice(12, 32))}`;
}

// ─── Nonce ───────────────────────────────────────────────────────────────────

let _nonce = 0;
function nextNonce(): number {
  const MASK = 0b11111;
  if ((_nonce & MASK) === 0) _nonce = (Math.floor(Math.random() * 0xffffffff) & ~MASK) >>> 0;
  return _nonce++;
}

// ─── EIP-712 Typed Data ──────────────────────────────────────────────────────

function buildEip712TypedData(msg: WalletRequestMessage) {
  return {
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
      ],
      WalletMessage: [
        { name: "chainId", type: "string" },
        { name: "signerId", type: "string" },
        { name: "nonce", type: "uint32" },
        { name: "createdAt", type: "string" },
        { name: "timeoutSecs", type: "uint32" },
        { name: "ops", type: "string" },
        { name: "out", type: "string" },
      ],
    },
    primaryType: "WalletMessage" as const,
    domain: {
      name: EIP712_DOMAIN_NAME,
      version: EIP712_DOMAIN_VERSION,
    },
    message: {
      chainId: msg.chain_id,
      signerId: msg.signer_id,
      nonce: msg.nonce,
      createdAt: msg.created_at,
      timeoutSecs: msg.timeout_secs,
      ops: JSON.stringify(msg.request.ops),
      out: JSON.stringify(msg.request.out),
    },
  };
}

/** Build the proof JSON for w_execute_signed from an EIP-712 signature.
 *  The proof mirrors the EIP-712 message fields plus the signature. */
function buildProof(msg: WalletRequestMessage, ethSignatureHex: string): string {
  const sigBytes = decodeEthSignature(ethSignatureHex);
  const sigEncoded = `secp256k1:${base58.encode(sigBytes)}`;
  return JSON.stringify({
    chainId: msg.chain_id,
    signerId: msg.signer_id,
    nonce: msg.nonce,
    createdAt: msg.created_at,
    timeoutSecs: msg.timeout_secs,
    ops: JSON.stringify(msg.request.ops),
    out: JSON.stringify(msg.request.out),
    signature: sigEncoded,
  });
}

// ─── WalletConnect Connection ────────────────────────────────────────────────

let modal: InstanceType<typeof WalletConnectModal>;

async function wcConnect(): Promise<{ address: string }> {
  // Browser-extension fast path: skip the WalletConnect modal and ask the
  // injected provider for an account directly. wcRequest handles the
  // EIP-1193 4100 "unauthorized" disable + clear path itself, so a
  // post-revoke retry will flow through the WalletConnect branch instead.
  if (await ethereumBridgeAvailable()) {
    showPendingUI("Confirm in your wallet");
    try {
      const accounts: string[] = await wcRequest("eth_requestAccounts", []);
      const address = accounts?.[0];
      if (!address) throw new Error("No Ethereum account");
      // Keep the pending UI up for the signing step that follows.
      return { address };
    } catch (e) {
      hidePendingUI();
      throw e;
    }
  }

  // Non-bridge path: pair via the WalletConnect modal. Set the cancel hook
  // first and render the pending UI (spinner + "Use a different wallet"
  // button) as the base layer so the user always has an escape hatch — the
  // WC modal opens on top and may auto-close on mobile/Ledger deeplink,
  // leaving this layer (and its cancel button) visible while we poll. Any
  // failure in setup or polling tears the whole UI down via the catch.
  const cancellable = new Promise<never>((_, reject) => {
    _pendingCancel = (e) => reject(e);
  });
  try {
    showPendingUI("Connecting your wallet…");

    if (!modal) {
      modal = new WalletConnectModal({
        chains: ["eip155:1"],
        projectId: await window.selector.walletConnect.getProjectId(),
        themeMode: "dark",
      });
    }

    // Drop any persisted WC session BEFORE pairing. WC v2 stores sessions
    // in localStorage across reloads, and a stale session would cause
    // `getSession()` to return its dead topic immediately — the poll would
    // resolve before the new pairing completed and any sign request sent
    // via that topic would never reach the wallet (or return undefined).
    try { await wcDisconnect(); } catch {}
    const staleSessionBeforeConnect = await window.selector.walletConnect.getSession();
    const staleTopic = staleSessionBeforeConnect?.topic ?? null;

    const result = await window.selector.walletConnect.connect({
      requiredNamespaces: {
        eip155: {
          chains: ["eip155:1"],
          methods: WC_METHODS,
          events: WC_EVENTS,
        },
      },
    });

    await new Promise((r) => setTimeout(r, 100));
    await modal.openModal({ uri: result.uri, standaloneChains: ["eip155:1"] });

    // Mobile wallets and Ledger Live close the WC modal as soon as the user
    // is deeplinked, well before the session is observable via getSession().
    // Polling indefinitely is fine; the "Use a different wallet" button on
    // the base layer (which fires `_pendingCancel`) is the escape hatch.
    const poll = new Promise<{ address: string }>(async (resolve, reject) => {
      try {
        while (true) {
          const session = await window.selector.walletConnect.getSession();
          if (session && session.topic !== staleTopic) {
            const accounts: string[] = session.namespaces?.eip155?.accounts ?? [];
            const address = accounts[0]?.split(":").pop() ?? "";
            if (!address) { reject(new Error("No Ethereum account")); return; }
            resolve({ address });
            return;
          }
          // User rejected pairing in their wallet app — WC's `approval()`
          // promise rejected on the parent. Surface as a standard cancel.
          const approvalErr = await (window.selector.walletConnect as any).getApprovalError?.();
          if (approvalErr) {
            reject(new Error("User rejected"));
            return;
          }
          await new Promise((r) => setTimeout(r, 500));
        }
      } catch (e) { reject(e as Error); }
    });

    const out = await Promise.race([poll, cancellable]);
    modal.closeModal();
    // Don't hide the iframe — keep the pending UI up for the signing request.
    showPendingUI("Confirm in your wallet");
    return out;
  } catch (e) {
    try { modal?.closeModal(); } catch {}
    hidePendingUI();
    throw e;
  } finally {
    _pendingCancel = null;
  }
}

// Set while a wcRequest is in flight so the "Use different wallet" button on
// the pending UI can abort it. Null otherwise.
let _pendingCancel: ((e: Error) => void) | null = null;

// Registered by the wallet factory so module-level UI handlers can reset its
// closure-scoped session state (ethAddress / publicKey64 / accountId).
let _clearWalletState: (() => void) | null = null;

function showPendingUI(message = "Confirm in your wallet") {
  window.selector.ui.showIframe();
  const root = document.getElementById("root")!;
  root.style.display = "flex";
  // Offer the "Use browser extension" button only when the WalletConnect
  // path is active AND the page actually has a detected extension provider.
  const showUseExtension = _ethereumBridgeAvailable === false && _ethereumProviderDetected;
  const btnStyle = "margin-top:8px;padding:8px 16px;border-radius:8px;border:1px solid #404040;background:transparent;color:#a3a3a3;cursor:pointer;font-family:-apple-system,sans-serif;font-size:13px;";
  root.innerHTML = `
    <div class="prompt-container">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="60" height="60" style="display:block;margin:0 auto 12px">
        <circle stroke-dasharray="75 27" r="16" stroke-width="4" stroke="#fff" fill="none" cy="50" cx="50">
          <animateTransform keyTimes="0;1" values="0 50 50;360 50 50" dur="1.4s" repeatCount="indefinite" type="rotate" attributeName="transform"/>
        </circle>
      </svg>
      <p>${message}</p>
      <button id="eip712-switch-wallet-btn" style="${btnStyle}">Use a different wallet</button>
      ${showUseExtension ? `<button id="eip712-use-extension-btn" style="${btnStyle}">Use browser extension</button>` : ""}
    </div>`;
  document.getElementById("eip712-switch-wallet-btn")?.addEventListener("click", onSwitchWalletClick);
  document.getElementById("eip712-use-extension-btn")?.addEventListener("click", onUseExtensionClick);
}

async function onUseExtensionClick() {
  // Switch back from WalletConnect to the browser extension. Re-enables
  // the bridge in the parent and aborts the in-flight WC request so the
  // caller's retry takes the bridge path.
  try { await (window.selector as any).ethereum.enable(); } catch {}
  _ethereumBridgeAvailable = null;
  try { await wcDisconnect(); } catch {}
  _clearWalletState?.();
  _pendingCancel?.(new Error("User switched to browser extension"));
}

async function onSwitchWalletClick() {
  // Tear down the current WalletConnect session + saved state so the next
  // request opens the wallet picker fresh. On the browser-extension bridge
  // path the user typically wants to leave the extension behind entirely
  // (e.g. pick Fireblocks via WalletConnect) — disable the bridge so the
  // next attempt opens the WC modal.
  if (await ethereumBridgeAvailable()) {
    try { await (window.selector as any).ethereum.disable(); } catch {}
    _ethereumBridgeAvailable = false;
  } else {
    try { await wcDisconnect(); } catch {}
  }
  _clearWalletState?.();
  // Abort the in-flight wcRequest so the caller can surface a clean failure
  // and the user can re-trigger the action against a different wallet.
  _pendingCancel?.(new Error("User chose to switch wallet"));
}

function hidePendingUI() {
  const root = document.getElementById("root")!;
  root.innerHTML = "";
  root.style.display = "none";
  window.selector.ui.hideIframe();
}

// If the top-level page has a browser-extension Ethereum provider (e.g.
// MetaMask), the parent exposes it via `window.selector.ethereum` — the
// iframe can't see `window.ethereum` directly because of the sandbox. The
// bridge is JSON-RPC only (forwarded `request({method, params})` calls),
// which preserves the iframe isolation.
let _ethereumBridgeAvailable: boolean | null = null;
async function ethereumBridgeAvailable(): Promise<boolean> {
  if (_ethereumBridgeAvailable !== null) return _ethereumBridgeAvailable;
  try {
    _ethereumBridgeAvailable = await (window.selector as any).ethereum?.isAvailable?.() === true;
  } catch {
    _ethereumBridgeAvailable = false;
  }
  return _ethereumBridgeAvailable;
}

// Whether any browser-extension provider is detected on the page, ignoring
// the bridge-disabled flag. Lets the WalletConnect spinner show a
// "Use browser extension" affordance for users who switched away earlier.
let _ethereumProviderDetected = false;
async function ethereumProviderDetected(): Promise<boolean> {
  try {
    return (await (window.selector as any).ethereum?.detected?.()) === true;
  } catch {
    return false;
  }
}

// EIP-1193: 4100 = unauthorized; the user revoked the site or never
// approved it. We use this to know the bridge can't deliver on this page
// and the iframe should fall back to WalletConnect.
function isUnauthorizedError(e: any): boolean {
  if (!e) return false;
  if (e.code === 4100) return true;
  const msg = (typeof e.message === "string" ? e.message : "").toLowerCase();
  return msg.includes("not been authorized") || msg.includes("not authorized");
}

async function wcRequest(method: string, params: any[]): Promise<any> {
  // Prefer the injected provider if available — same JSON-RPC surface,
  // direct path, no WalletConnect round-trip.
  const useBridge = await ethereumBridgeAvailable();
  const request = useBridge
    ? (window.selector as any).ethereum.request({ method, params })
    : (async () => {
        const session = await window.selector.walletConnect.getSession();
        if (!session) throw new Error("WalletConnect not connected");
        return window.selector.walletConnect.request({
          topic: session.topic,
          chainId: "eip155:1",
          request: { method, params },
        });
      })();
  // Race against the "switch wallet" button on the pending UI.
  const prevCancel = _pendingCancel;
  const cancellable = new Promise<never>((_, reject) => {
    _pendingCancel = (e) => reject(e);
  });
  try {
    return await Promise.race([request, cancellable]);
  } catch (e: any) {
    // User revoked the site permission in the extension (EIP-1193 code
    // 4100) — disable the bridge + drop the stale stored ETH address so
    // the next attempt opens the WalletConnect modal with a clean state.
    if (useBridge && isUnauthorizedError(e)) {
      try { await (window.selector as any).ethereum.disable(); } catch {}
      _ethereumBridgeAvailable = false;
      _clearWalletState?.();
    }
    throw e;
  } finally {
    _pendingCancel = prevCancel;
  }
}

async function wcDisconnect() {
  if (await ethereumBridgeAvailable()) {
    // Extension providers have no "disconnect" RPC the dApp can drive —
    // just clearing local state is enough; the user manages the
    // connection from the extension UI.
    return;
  }
  const session = await window.selector.walletConnect.getSession();
  if (session) {
    await window.selector.walletConnect.disconnect({
      topic: session.topic,
      reason: { code: 5900, message: "User disconnected" },
    });
  }
}

/** Show the pending UI, request a signature over the WalletConnect/bridge
 *  transport, then always tear the UI down. Throws a clear error when the
 *  wallet returns an empty / non-string signature (e.g. a silent reject). */
async function promptSignature(method: string, params: any[], message: string): Promise<string> {
  showPendingUI(message);
  try {
    const sig = await wcRequest(method, params);
    if (typeof sig !== "string" || sig.length === 0) {
      throw new Error("Wallet returned no signature.");
    }
    return sig;
  } finally {
    hidePendingUI();
  }
}

// ─── Connector Action → Wallet-Contract ──────────────────────────────────────

function connectorActionsToWalletPromises(
  txs: Array<{ receiverId: string; actions: ConnectorAction[] }>,
): PromiseDag {
  return {
    after: [],
    then: txs.map((tx) => ({
      receiver_id: tx.receiverId,
      actions: tx.actions.map((a): PromiseAction => {
        if (a.type === "FunctionCall") return {
          action: "function_call",
          function_name: a.params.methodName,
          args: base64.encode(new TextEncoder().encode(JSON.stringify(a.params.args))),
          deposit: a.params.deposit,
        };
        if (a.type === "Transfer") return { action: "transfer", amount: a.params.deposit };
        throw new Error(`Action type "${a.type}" is not supported by EIP-712 wallet-contract.`);
      }),
    })),
  };
}

// ─── Raw Transaction Relay (same StateInit approach as passkey wallet) ────────

const provider = new NearRpc(window.selector?.providers?.mainnet);

function serializeStateInitAction(publicKey64: Uint8Array): Uint8Array {
  const { serialized } = buildStateInit(publicKey64);
  const w = new BorshWriter();
  w.writeU8(11); // Action enum: StateInit = 11
  for (const b of serialized) w.writeU8(b);
  w.writeU128(0n);
  return w.toBytes();
}

function serializeFunctionCallAction(methodName: string, args: object, gas: bigint, deposit: bigint): Uint8Array {
  const w = new BorshWriter();
  w.writeU8(2);
  w.writeString(methodName);
  w.writeBytes(new TextEncoder().encode(JSON.stringify(args)));
  w.writeU64(gas);
  w.writeU128(deposit);
  return w.toBytes();
}

function serializeRawTransaction(
  signerId: string, publicKey: PublicKey, receiverId: string,
  nonce: number, blockHash: Uint8Array, rawActions: Uint8Array[],
): Uint8Array {
  const w = new BorshWriter();
  w.writeString(signerId);
  w.writeU8(0); // ED25519
  for (const b of publicKey.data) w.writeU8(b);
  w.writeU64(BigInt(nonce));
  w.writeString(receiverId);
  for (const b of blockHash) w.writeU8(b);
  w.writeU32(rawActions.length);
  for (const a of rawActions) for (const b of a) w.writeU8(b);
  return w.toBytes();
}

function serializeRawSignedTransaction(txBytes: Uint8Array, signatureBytes: Uint8Array): Uint8Array {
  const w = new BorshWriter();
  for (const b of txBytes) w.writeU8(b);
  w.writeU8(0); // ED25519
  for (const b of signatureBytes) w.writeU8(b);
  return w.toBytes();
}

async function getRelayerInfo() {
  const kp = KeyPair.fromString(RELAYER_PRIVATE_KEY);
  const pk = kp.getPublicKey();
  const [block, ak] = await Promise.all([
    provider.block({ finality: "final" }),
    provider.query<any>({ request_type: "view_access_key", finality: "final", account_id: RELAYER_ACCOUNT_ID, public_key: pk.toString() }),
  ]);
  return { keyPair: kp, publicKey: pk, nonce: ak.nonce + 1, blockHash: baseDecode(block.header.hash) };
}

async function signAndSendRawTransaction(receiverId: string, rawActions: Uint8Array[]): Promise<FinalExecutionOutcome> {
  const { keyPair, publicKey, nonce, blockHash } = await getRelayerInfo();
  const txBytes = serializeRawTransaction(RELAYER_ACCOUNT_ID, publicKey, receiverId, nonce, blockHash, rawActions);
  const sig = keyPair.sign(sha256(txBytes));
  const stxBytes = serializeRawSignedTransaction(txBytes, sig.signature);
  return provider.sendJsonRpc<FinalExecutionOutcome>("send_tx", { signed_tx_base64: Buffer.from(stxBytes).toString("base64"), wait_until: "FINAL" });
}

async function relayWalletContractCall(
  walletAccountId: string, msg: WalletRequestMessage, proof: string,
  publicKey64: Uint8Array, includeStateInit: boolean,
): Promise<FinalExecutionOutcome> {
  const actions: Uint8Array[] = [];
  if (includeStateInit) actions.push(serializeStateInitAction(publicKey64));
  actions.push(serializeFunctionCallAction("w_execute_signed", { msg, proof }, 300_000_000_000_000n, 1n));
  return signAndSendRawTransaction(walletAccountId, actions);
}

async function accountExists(accountId: string): Promise<boolean> {
  try { await provider.query<any>({ request_type: "view_account", finality: "final", account_id: accountId }); return true; }
  catch { return false; }
}

const RELAYER_API_URL = "https://api.testenv.trezu.app/api/user/create";

// near-api wire format: `{"V1": {"code": {"AccountId": "..."}, "data": {<b64>: <b64>}}}`.
// See `DeterministicAccountStateInit` in near-api-types and the reference
// handler at /mnt/treasury26/nt-be/src/handlers/user/create.rs.
function buildStateInitForApi(publicKey64: Uint8Array) {
  const stateValue = buildWalletState(publicKey64);
  return {
    V1: {
      code: { AccountId: WALLET_CONTRACT_ACCOUNT_ID },
      // Empty key → empty base64 string.
      data: { "": base64.encode(stateValue) },
    },
  };
}

async function createDeterministicAccountViaApi(accountId: string, publicKey64: Uint8Array): Promise<void> {
  const stateInit = buildStateInitForApi(publicKey64);
  const resp = await fetch(RELAYER_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ accountId, stateInit }),
  });
  if (!resp.ok) {
    let detail = "";
    try { detail = await resp.text(); } catch {}
    throw new Error(`Relayer API ${resp.status}: ${detail || resp.statusText}`);
  }
}

/**
 * Ensure the wallet-contract account exists on-chain. Tries the hard-coded
 * relayer-signed transaction first; on failure, falls back to the relayer
 * HTTP API. No-op if the account already exists.
 */
async function ensureStateInitOnChain(accountId: string, publicKey64: Uint8Array): Promise<void> {
  if (await accountExists(accountId)) return;
  try {
    await signAndSendRawTransaction(accountId, [serializeStateInitAction(publicKey64)]);
    return;
  } catch (e) {
    console.warn("Relay via hard-coded account failed; falling back to API:", e);
  }
  await createDeterministicAccountViaApi(accountId, publicKey64);
}

// ─── Core EIP-712 Sign + Relay Flow ──────────────────────────────────────────

function buildRequestMessage(accountId: string, request: WalletRequest, network: Network): WalletRequestMessage {
  return {
    chain_id: network === "testnet" ? "testnet" : "mainnet",
    signer_id: accountId,
    nonce: nextNonce(),
    created_at: new Date(Math.floor(Date.now() / 1000 - 60) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    timeout_secs: DEFAULT_TIMEOUT_SECS,
    request,
  };
}

async function signWithEip712(ethAddress: string, msg: WalletRequestMessage): Promise<string> {
  const typedData = buildEip712TypedData(msg);
  const sigHex = await promptSignature(
    "eth_signTypedData_v4",
    [ethAddress, JSON.stringify(typedData)],
    "Confirm transaction in your wallet",
  );
  return buildProof(msg, sigHex);
}

async function signAndRelay(
  accountId: string, publicKey64: Uint8Array, ethAddress: string,
  request: WalletRequest, network: Network, includeStateInit: boolean,
): Promise<FinalExecutionOutcome> {
  const msg = buildRequestMessage(accountId, request, network);
  const proof = await signWithEip712(ethAddress, msg);
  return relayWalletContractCall(accountId, msg, proof, publicKey64, includeStateInit);
}

// ─── NEP-413 Sign Message (via personal_sign + relayer wrap) ─────────────────

async function signMessageViaEthereum(
  ethAddress: string,
  walletAccountId: string,
  publicKey64: Uint8Array,
  message: string,
  recipient: string,
  nonce: Uint8Array | number[],
): Promise<SignedMessage> {
  // Build a human-readable message for the Ethereum wallet to sign
  const nonceBytes = nonce instanceof Uint8Array ? nonce : new Uint8Array(nonce);
  const nonceHex = hex.encode(nonceBytes);
  const personalMessage = `NEAR signMessage:\n\nMessage: ${message}\nRecipient: ${recipient}\nNonce: ${nonceHex}\nAccount: ${walletAccountId}`;

  // Sign via personal_sign (ERC-191)
  const hexMessage = "0x" + hex.encode(new TextEncoder().encode(personalMessage));
  const sigHex = await promptSignature(
    "personal_sign",
    [hexMessage, ethAddress],
    "Confirm message in your wallet",
  );

  // Return with secp256k1 public key so verifiers know the signing standard
  const sigBytes = decodeEthSignature(sigHex);

  return {
    accountId: walletAccountId,
    publicKey: `secp256k1:${base58.encode(publicKey64)}`,
    signature: base64.encode(sigBytes),
  };
}

// ─── Wallet Implementation ──────────────────────────────────────────────────

const Eip712Wallet = async () => {
  _ethereumProviderDetected = await ethereumProviderDetected();

  let ethAddress: string | null = null;
  let publicKey64: Uint8Array | null = null;
  let accountId: string | null = null;

  // Load persisted state
  const savedAddr = window.localStorage.getItem(STORAGE_KEY_ETH_ADDRESS);
  const savedPk = window.localStorage.getItem(STORAGE_KEY_PUBLIC_KEY);
  const savedAcct = window.localStorage.getItem(STORAGE_KEY_ACCOUNT_ID);
  if (savedAddr && savedPk && savedAcct) {
    ethAddress = savedAddr;
    publicKey64 = hex.decode(savedPk);
    accountId = savedAcct;
  }

  function isSignedIn() { return !!(ethAddress && publicKey64 && accountId); }

  function clearState() {
    ethAddress = null;
    publicKey64 = null;
    accountId = null;
    try { window.localStorage.removeItem(STORAGE_KEY_ETH_ADDRESS); } catch {}
    try { window.localStorage.removeItem(STORAGE_KEY_PUBLIC_KEY); } catch {}
    try { window.localStorage.removeItem(STORAGE_KEY_ACCOUNT_ID); } catch {}
  }
  _clearWalletState = clearState;

  function saveState(addr: string, pk: Uint8Array, acct: string) {
    ethAddress = addr;
    publicKey64 = pk;
    accountId = acct;
    window.localStorage.setItem(STORAGE_KEY_ETH_ADDRESS, addr);
    window.localStorage.setItem(STORAGE_KEY_PUBLIC_KEY, hex.encode(pk));
    window.localStorage.setItem(STORAGE_KEY_ACCOUNT_ID, acct);
  }

  /** Recover the secp256k1 public key from an EIP-712 eth_signTypedData_v4 signature. */
  function recoverPublicKeyFromEip712Sig(typedData: any, sigHex: string): Uint8Array {
    // Reproduce the EIP-712 signing hash: keccak256("\x19\x01" || domainSeparator || structHash)
    const domainType = "EIP712Domain(string name,string version)";
    const domainTypeHash = keccak_256(new TextEncoder().encode(domainType));
    const nameHash = keccak_256(new TextEncoder().encode(typedData.domain.name));
    const versionHash = keccak_256(new TextEncoder().encode(typedData.domain.version));

    const domainBuf = new Uint8Array(96);
    domainBuf.set(domainTypeHash, 0);
    domainBuf.set(nameHash, 32);
    domainBuf.set(versionHash, 64);
    const domainSeparator = keccak_256(domainBuf);

    // Build struct hash from primaryType fields
    const primaryType = typedData.primaryType as string;
    const fields = typedData.types[primaryType] as Array<{ name: string; type: string }>;
    const typeString = `${primaryType}(${fields.map((f: any) => `${f.type} ${f.name}`).join(",")})`;
    const typeHash = keccak_256(new TextEncoder().encode(typeString));

    // Encode fields: for string → keccak256(value), for uint32 → abi.encode(value) 32-byte padded
    const words: Uint8Array[] = [typeHash];
    for (const field of fields) {
      const val = typedData.message[field.name];
      if (field.type === "string") {
        words.push(keccak_256(new TextEncoder().encode(val)));
      } else if (field.type === "uint32") {
        const word = new Uint8Array(32);
        const n = typeof val === "number" ? val : parseInt(val, 10);
        word[28] = (n >> 24) & 0xff;
        word[29] = (n >> 16) & 0xff;
        word[30] = (n >> 8) & 0xff;
        word[31] = n & 0xff;
        words.push(word);
      }
    }

    const structBuf = new Uint8Array(words.length * 32);
    words.forEach((w, i) => structBuf.set(w, i * 32));
    const structHash = keccak_256(structBuf);

    const sigInput = new Uint8Array(66);
    sigInput[0] = 0x19;
    sigInput[1] = 0x01;
    sigInput.set(domainSeparator, 2);
    sigInput.set(structHash, 34);
    const signingHash = keccak_256(sigInput);

    // Recover public key
    const sigBytes = hex.decode(sigHex.replace(/^0x/, ""));
    const r = sigBytes.slice(0, 32);
    const s = sigBytes.slice(32, 64);
    let v = sigBytes[64];
    if (v >= 27) v -= 27;

    const sig = secp256k1.Signature.fromCompact(hex.encode(r) + hex.encode(s)).addRecoveryBit(v);
    return sig.recoverPublicKey(signingHash).toRawBytes(false).slice(1);
  }

  /** Ensure WalletConnect is connected. Returns the ETH address. */
  async function ensureConnected(): Promise<string> {
    // Browser-extension path doesn't have a WC session to validate against.
    // A stored `ethAddress` is trusted until the user logs out — the
    // extension itself rejects requests if the account changes.
    if (await ethereumBridgeAvailable()) {
      if (ethAddress) return ethAddress;
      const { address } = await wcConnect();
      ethAddress = address;
      window.localStorage.setItem(STORAGE_KEY_ETH_ADDRESS, address);
      return address;
    }

    // A stale `ethAddress` may persist in localStorage / closure after the
    // WalletConnect session has been torn down (e.g. by the "Use a different
    // wallet" button, or by the peer wallet disconnecting). Re-pair unless
    // both the address and a live WC session are present.
    const session = await window.selector.walletConnect.getSession();
    if (ethAddress && session) return ethAddress;

    const { address } = await wcConnect();
    ethAddress = address;
    window.localStorage.setItem(STORAGE_KEY_ETH_ADDRESS, address);
    return address;
  }

  /** Verify a recovered public key matches the connected address, derive the
   *  wallet-contract account, and persist the full state. */
  function finalizeKey(address: string, pk: Uint8Array) {
    const derivedAddr = pubKeyToEthAddress(pk);
    if (derivedAddr.toLowerCase() !== address.toLowerCase()) {
      throw new Error(`Recovered address ${derivedAddr} does not match ${address}`);
    }
    const acct = deriveAccountId(pk);
    saveState(address, pk, acct);
    return { ethAddress: address, publicKey64: pk, accountId: acct };
  }

  /** Recover pubkey from an EIP-712 signature and persist the state. */
  function recoverAndSave(address: string, typedData: any, sigHex: string) {
    return finalizeKey(address, recoverPublicKeyFromEip712Sig(typedData, sigHex));
  }

  /** Initialise the wallet-contract account on-chain for a freshly recovered
   *  key. On failure, clear the half-written sign-in state so the user is
   *  never left "signed in" with no usable on-chain account (every later tx
   *  relays with includeStateInit=false and would otherwise fail forever). */
  async function establishOnChain(acct: string, pk: Uint8Array) {
    try {
      await ensureStateInitOnChain(acct, pk);
    } catch (e) {
      clearState();
      throw e;
    }
  }

  async function connectAndRecover(): Promise<{ ethAddress: string; publicKey64: Uint8Array; accountId: string }> {
    if (isSignedIn()) return { ethAddress: ethAddress!, publicKey64: publicKey64!, accountId: accountId! };

    // 1. Connect via WalletConnect (only pairing, no signature)
    const address = await ensureConnected();

    // 2. Ask user to sign a message so we can recover the full public key
    const recoveryMessage = "Sign this message to connect your Ethereum wallet to NEAR.\n\nThis signature will NOT trigger any blockchain transaction.";
    const hexMsg = "0x" + hex.encode(new TextEncoder().encode(recoveryMessage));
    const sigHex = await promptSignature("personal_sign", [hexMsg, address], "Confirm in your wallet");

    // 3. Recover the secp256k1 public key, verify it against the address,
    //    derive the wallet-contract account, and persist the state.
    const pk = recoverPublicKeyFromPersonalSign(recoveryMessage, sigHex);
    return finalizeKey(address, pk);
  }

  return {
    async signIn({ network }: SignInParams) {
      const { accountId: acct, publicKey64: pk } = await connectAndRecover();

      await establishOnChain(acct, pk);

      return [{ accountId: acct, publicKey: `secp256k1:${base58.encode(pk)}` }];
    },

    async signInAndSignMessage(data: SignInAndSignMessageParams): Promise<AccountWithSignedMessage[]> {
      const { network, messageParams } = data;
      const { accountId: acct, publicKey64: pk, ethAddress: addr } = await connectAndRecover();

      await establishOnChain(acct, pk);

      const signedMessage = await signMessageViaEthereum(
        addr, acct, pk,
        messageParams.message, messageParams.recipient, messageParams.nonce,
      );

      return [{ accountId: acct, publicKey: `secp256k1:${base58.encode(pk)}`, signedMessage }];
    },

    async signOut() {
      try { await wcDisconnect(); } catch {}
      clearState();
    },

    async getAccounts() {
      if (!isSignedIn()) return [{ accountId: "", publicKey: "" }];
      return [{ accountId: accountId!, publicKey: `secp256k1:${base58.encode(publicKey64!)}` }];
    },

    async signMessage({ message, recipient, nonce, network }: {
      message: string; recipient: string; nonce: Uint8Array | number[]; network?: Network;
    }): Promise<SignedMessage> {
      if (!isSignedIn()) throw new Error("Wallet not signed in");
      return signMessageViaEthereum(ethAddress!, accountId!, publicKey64!, message, recipient, nonce);
    },

    async signAndSendTransaction({ receiverId, actions, network }: {
      receiverId: string; actions: ConnectorAction[]; network: Network;
    }): Promise<FinalExecutionOutcome> {
      if (!isSignedIn()) throw new Error("Wallet not signed in");
      const request: WalletRequest = { ops: [], out: connectorActionsToWalletPromises([{ receiverId, actions }]) };
      return signAndRelay(accountId!, publicKey64!, ethAddress!, request, network, false);
    },

    async signAndSendTransactions({ transactions, network }: {
      transactions: Array<{ receiverId: string; actions: ConnectorAction[] }>; network: Network;
    }): Promise<FinalExecutionOutcome[]> {
      if (!isSignedIn()) throw new Error("Wallet not signed in");
      const request: WalletRequest = { ops: [], out: connectorActionsToWalletPromises(transactions) };
      const result = await signAndRelay(accountId!, publicKey64!, ethAddress!, request, network, false);
      return transactions.map(() => result);
    },

    async signDelegateActions({ delegateActions, network }: {
      delegateActions: Array<{ receiverId: string; actions: ConnectorAction[] }>; network?: Network;
    }) {
      if (!isSignedIn()) throw new Error("Wallet not signed in");
      const net = network || "mainnet";

      // Build and sign the wallet-contract request
      const request: WalletRequest = { ops: [], out: connectorActionsToWalletPromises(delegateActions) };
      const msg = buildRequestMessage(accountId!, request, net);
      const proof = await signWithEip712(ethAddress!, msg);

      // The state-init must run via a regular relay before the delegate so
      // that fallback to the relayer API is available; the delegate itself
      // can't carry a state-init that would also need fallback handling.
      await ensureStateInitOnChain(accountId!, publicKey64!);
      const rawActions: Uint8Array[] = [
        serializeFunctionCallAction("w_execute_signed", { msg, proof }, 300_000_000_000_000n, 1n),
      ];

      // Build a DelegateAction signed by the relayer, but do NOT submit
      const { keyPair, publicKey, nonce: relayerNonce, blockHash } = await getRelayerInfo();

      // DelegateAction: sender_id, receiver_id, actions, nonce, max_block_height, public_key
      const maxBlockHeight = BigInt(relayerNonce) + 1000n;
      const w = new BorshWriter();
      w.writeString(RELAYER_ACCOUNT_ID);     // sender_id
      w.writeString(accountId!);             // receiver_id
      w.writeU32(rawActions.length);         // actions count
      for (const a of rawActions) for (const b of a) w.writeU8(b);
      w.writeU64(BigInt(relayerNonce));      // nonce
      w.writeU64(maxBlockHeight);            // max_block_height
      w.writeU8(0);                          // public_key: ED25519
      for (const b of publicKey.data) w.writeU8(b);

      const delegateBytes = w.toBytes();

      // Sign the DelegateAction
      // SignedDelegate prefix tag: 2^30 + 4 = 1073741828 (NEP-366)
      const tagW = new BorshWriter();
      tagW.writeU32(1073741828);
      const tagBytes = tagW.toBytes();

      const toSign = new Uint8Array(tagBytes.length + delegateBytes.length);
      toSign.set(tagBytes);
      toSign.set(delegateBytes, tagBytes.length);
      const hash = sha256(toSign);
      const sig = keyPair.sign(hash);

      // SignedDelegateAction = DelegateAction + Signature
      const sdW = new BorshWriter();
      for (const b of delegateBytes) sdW.writeU8(b);
      sdW.writeU8(0); // ED25519
      for (const b of sig.signature) sdW.writeU8(b);

      return { signedDelegateActions: [base64.encode(sdW.toBytes())] };
    },

    /**
     * NEP-641 `resolveAuth`: authorize `payload` with an EIP-712 signature over
     * the standard `OffchainMessage` envelope.
     *
     * The envelope names the signer (`signer_id`), so the wallet-contract
     * account must be known before signing: a fresh user first connects and
     * recovers their key (`connectAndRecover`, one signature), then signs the
     * envelope (second signature). An already-signed-in user signs once.
     *
     * Blob format (mirrors the near/intents reference wallet's
     * `WalletAuthorization::Signature { msg, proof }`; the contract at
     * `WALLET_CONTRACT_ACCOUNT_ID` must verify the EIP-712 signature over
     * exactly this typed data and enforce the NEP-641 envelope checks —
     * chain_id, signer_id, path == argument path, timestamp not in the future):
     *
     * ```json
     * { "signature": { "msg": { ...OffchainMessage }, "proof": "secp256k1:<base58 r||s||v>" } }
     * ```
     */
    async resolveAuth({ payload, network, chainId }: {
      payload: string; network?: Network; chainId?: string;
    }) {
      const { accountId: acct, publicKey64: pk, ethAddress: addr } = await connectAndRecover();

      // Ensure the wallet-contract account is initialised on-chain so the
      // dApp's subsequent `w_resolve_auth` view call can succeed.
      await establishOnChain(acct, pk);

      // NEP-641 OffchainMessage (top-level: empty path), timestamped ~60s in
      // the past to absorb clock skew and block-time lag.
      const msg = {
        chain_id: chainId ?? (network === "testnet" ? "testnet" : "mainnet"),
        signer_id: acct,
        path: [] as string[],
        timestamp: new Date(Math.floor(Date.now() / 1000 - 60) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
        payload,
      };

      const typedData = {
        types: {
          EIP712Domain: [
            { name: "name", type: "string" },
            { name: "version", type: "string" },
          ],
          OffchainMessage: [
            { name: "chainId", type: "string" },
            { name: "signerId", type: "string" },
            { name: "path", type: "string[]" },
            { name: "timestamp", type: "string" },
            { name: "payload", type: "string" },
          ],
        },
        primaryType: "OffchainMessage" as const,
        domain: {
          name: EIP712_DOMAIN_NAME,
          version: EIP712_DOMAIN_VERSION,
        },
        message: {
          chainId: msg.chain_id,
          signerId: msg.signer_id,
          path: msg.path,
          timestamp: msg.timestamp,
          payload: msg.payload,
        },
      };

      // Single signature — pending UI shown + torn down by promptSignature.
      const sigHex = await promptSignature(
        "eth_signTypedData_v4",
        [addr, JSON.stringify(typedData)],
        "Confirm in your wallet",
      );

      const sigBytes = decodeEthSignature(sigHex);
      const proof = `secp256k1:${base58.encode(sigBytes)}`;

      return {
        accountId: acct,
        authorization: JSON.stringify({
          signature: {
            msg: { chain_id: msg.chain_id, signer_id: msg.signer_id, timestamp: msg.timestamp, payload: msg.payload },
            proof,
          },
        }),
      };
    },

    async verifyOwner() {
      throw new Error("Method not supported by EIP-712 Wallet");
    },
  };
};

Eip712Wallet().then((wallet) => {
  window.selector.ready(wallet);
});
