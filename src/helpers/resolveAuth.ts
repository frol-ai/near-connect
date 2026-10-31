import type {
  AccountWithSignedMessage,
  NearWalletBase,
  ResolveAuthParams,
  ResolveAuthResponse,
  SignInAndSignMessageParams,
} from "../types";
import { encodeAccessKeyAuthorization, newOffchainMessage, normalizeNep413Signature, toNep413Payload } from "./nep641";

/**
 * NEP-641 default `resolveAuth` for wallets controlled by full-access keys,
 * built on top of NEP-413 `signMessage`.
 *
 * Per NEP-641 §"Access-key authorization", the signed material is the
 * `OffchainMessage` envelope `{ chain_id, signer_id, path: [], timestamp,
 * payload }`, mapped onto NEP-413 as: `message` = payload, `nonce` = the
 * envelope's canonical hash (binds every field), `recipient` =
 * `"<chain_id>: <signer_id> @ <timestamp>"` (what NEP-413 wallets render).
 *
 * The envelope names the signer, so the account must be known *before*
 * signing: a wallet that isn't signed in yet is signed in first (without
 * adding a key), then asked to sign — two user gestures. Wallets that want a
 * single gesture implement `resolveAuth` natively.
 *
 * The returned `authorization` is a JSON-stringified `AccessKeyAuthorization`
 * the dApp verifies offchain against the account's full-access keys at a
 * pinned block (see `verifyResolveAuth`). No contract is involved.
 */
export async function defaultResolveAuthViaSignMessage(
  wallet: Pick<NearWalletBase, "signIn" | "signMessage" | "getAccounts">,
  params: ResolveAuthParams,
): Promise<ResolveAuthResponse> {
  const chainId = params.chainId ?? params.network ?? "mainnet";

  let accounts = await wallet.getAccounts({ network: params.network }).catch(() => []);
  if (!accounts?.length || !accounts[0]?.accountId) {
    accounts = await wallet.signIn({ network: params.network });
  }
  const accountId = accounts?.[0]?.accountId;
  if (!accountId) throw new Error("Wallet returned no account during sign-in");

  const msg = newOffchainMessage({ chainId, signerId: accountId, payload: params.payload });
  const nep413 = toNep413Payload(msg);

  const signed = await wallet.signMessage({
    message: nep413.message,
    recipient: nep413.recipient,
    nonce: nep413.nonce,
    network: params.network,
    signerId: accountId,
  });
  if (signed.accountId && signed.accountId !== accountId) {
    throw new Error(`Wallet signed as ${signed.accountId}, expected ${accountId}`);
  }

  const authorization = encodeAccessKeyAuthorization({
    msg,
    via: { schema: "nep413", extra: {} },
    access_key: signed.publicKey,
    signature: normalizeNep413Signature(signed.signature, signed.publicKey),
  });

  return { accountId, authorization };
}

/**
 * Polyfill `signInAndSignMessage` for wallets that don't support the combined
 * flow natively but expose `signIn` (without addKey) + `signMessage`. The
 * polyfill runs sign-in followed by a separate signMessage on the
 * newly-connected account. Two user gestures instead of one.
 */
export async function polyfillSignInAndSignMessage(
  wallet: Pick<NearWalletBase, "signIn" | "signMessage">,
  data: SignInAndSignMessageParams,
): Promise<AccountWithSignedMessage[]> {
  const accounts = await wallet.signIn({
    network: data.network,
    addFunctionCallKey: data.addFunctionCallKey,
  });
  const signedMessage = await wallet.signMessage({
    ...data.messageParams,
    network: data.network,
  });
  return accounts.map((account) => ({ ...account, signedMessage }));
}

/**
 * Detects the "method not found" signal from a wallet's native `resolveAuth`
 * attempt. The sandbox executor rejects with the literal string
 * `"Method not found"` when the wallet code doesn't implement the method;
 * injected/parent-frame wallets surface the same condition via an `Error`
 * with a similar message. Used by the wrappers to fall through to the
 * default signMessage-based implementation even when the manifest claims
 * `resolveAuth: true`.
 */
export function isResolveAuthMethodNotFound(e: unknown): boolean {
  const probe =
    typeof e === "string"
      ? e
      : typeof (e as { message?: unknown } | undefined)?.message === "string"
        ? (e as { message: string }).message
        : "";
  const lower = probe.toLowerCase();
  return lower.includes("method not found") || lower.includes("methodnotfound");
}
