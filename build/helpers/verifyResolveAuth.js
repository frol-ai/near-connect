"use strict";
// NEP-641 offchain resolver (caller side). Implements the canonical algorithm
// from nep-0641.md §"Caller-side resolution algorithm":
//
// * the whole authorization tree is resolved against ONE pinned block hash;
// * every node is resolved BOTH as an access-key authorization (NEP-413-signed
//   `OffchainMessage` verified against a full-access key) and through the
//   `w_resolve_auth(path, authorization)` view call — the access-key result
//   takes precedence;
// * `pending` sub-authorizations are resolved recursively with the parent's ID
//   prepended to `path`, and each must return exactly its `expect` payload;
// * total sub-authorization count and depth are capped.
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyResolveAuth = verifyResolveAuth;
const nep641_1 = require("./nep641");
// ─── RPC ─────────────────────────────────────────────────────────────────────
class RpcError extends Error {
    causeName;
    data;
    constructor(message, causeName, data) {
        super(message);
        this.causeName = causeName;
        this.data = data;
    }
}
async function rpc(rpcUrl, method, params) {
    const resp = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const json = await resp.json();
    if (json.error) {
        // Generic JSON-RPC `message` (e.g. "Server error") hides the actual
        // failure, which lives in `error.data` / `error.cause`.
        throw new RpcError(formatRpcError(json.error), json.error.cause?.name, json.error.data ?? json.error.cause);
    }
    if (json.result?.error) {
        const data = json.result.error;
        throw new RpcError(typeof data === "string" ? data : JSON.stringify(data), undefined, data);
    }
    return json.result;
}
function formatRpcError(error) {
    const parts = [];
    if (error.message)
        parts.push(error.message);
    if (error.data != null)
        parts.push(typeof error.data === "string" ? error.data : JSON.stringify(error.data));
    if (error.cause != null)
        parts.push(typeof error.cause === "string" ? error.cause : JSON.stringify(error.cause));
    return parts.join(" — ") || "RPC error";
}
async function fetchBlock(rpcUrl, ref) {
    const r = await rpc(rpcUrl, "block", ref);
    return { hash: r.header.hash, height: r.header.height, timestampNanos: BigInt(r.header.timestamp_nanosec) };
}
async function fetchChainId(rpcUrl) {
    const r = await rpc(rpcUrl, "status", []);
    return r.chain_id;
}
async function viewCall(rpcUrl, accountId, methodName, args, blockHash) {
    const argsBase64 = btoa(JSON.stringify(args));
    const result = await rpc(rpcUrl, "query", {
        request_type: "call_function",
        block_id: blockHash,
        account_id: accountId,
        method_name: methodName,
        args_base64: argsBase64,
    });
    return { result: new Uint8Array(result.result), blockHash: result.block_hash };
}
async function viewAccessKey(rpcUrl, accountId, publicKey, blockHash) {
    try {
        const result = await rpc(rpcUrl, "query", {
            request_type: "view_access_key",
            block_id: blockHash,
            account_id: accountId,
            public_key: publicKey,
        });
        const permission = result.permission;
        const fullAccess = permission === "FullAccess" ||
            (typeof permission === "object" && permission !== null && "GasKeyFullAccess" in permission);
        return { kind: "found", fullAccess };
    }
    catch (e) {
        // Classify the key error first: the legacy `query` endpoint reports a
        // missing *account* as "access key ... does not exist while viewing" too,
        // so a missing key must never be mistaken for a missing account (that
        // would re-enable the implicit-account acceptance for a removed key).
        if (isUnknownAccessKeyError(e))
            return { kind: "key_not_found" };
        if (isUnknownAccountError(e))
            return { kind: "account_not_found" };
        throw e;
    }
}
function errorProbe(e) {
    const err = e;
    return `${err?.causeName ?? ""} ${err?.message ?? ""} ${typeof err?.data === "string" ? err.data : JSON.stringify(err?.data ?? "")}`.toLowerCase();
}
function isUnknownAccountError(e) {
    if (e?.causeName === "UNKNOWN_ACCOUNT")
        return true;
    const p = errorProbe(e);
    return p.includes("unknown_account") || /\baccount \S+ does not exist/.test(p);
}
function isUnknownAccessKeyError(e) {
    if (e?.causeName === "UNKNOWN_ACCESS_KEY")
        return true;
    const p = errorProbe(e);
    return p.includes("unknown_access_key") || (p.includes("access key") && p.includes("does not exist"));
}
/** No contract to resolve with: account missing, or no code deployed. */
function isNoContractError(e) {
    if (isUnknownAccountError(e))
        return true;
    const p = errorProbe(e);
    return p.includes("codedoesnotexist") || p.includes("contractcodenotfound") || p.includes("no contract code");
}
/** NEP-641 §"Access-key authorization" → "Verification procedure". */
async function resolveAccessKey(ctx, accountId, path, blob) {
    const auth = (0, nep641_1.parseAccessKeyAuthorization)(blob);
    if (!auth)
        return { ok: false, error: "not an access-key authorization", parsedAsAccessKey: false };
    const fail = (error) => ({ ok: false, error, parsedAsAccessKey: true });
    // 1. chain_id
    if (auth.msg.chain_id !== ctx.chainId)
        return fail(`invalid chain_id: expected ${ctx.chainId}`);
    // 2. signer_id
    if (auth.msg.signer_id !== accountId)
        return fail(`invalid signer_id: ${auth.msg.signer_id}`);
    // 3. path
    const signedPath = auth.msg.path ?? [];
    if (signedPath.length !== path.length || signedPath.some((id, i) => id !== path[i])) {
        return fail("invalid path");
    }
    // 4. signature
    if (!(0, nep641_1.verifyAccessKeyAuthorization)(auth))
        return fail("invalid signature");
    // 5. timestamp
    let timestampNanos;
    try {
        timestampNanos = (0, nep641_1.rfc3339ToNanos)(auth.msg.timestamp);
    }
    catch (e) {
        return fail(e.message);
    }
    if (timestampNanos > ctx.block.timestampNanos)
        return fail("message is from the future");
    // 6. access key at the pinned block
    const publicKey = (0, nep641_1.parsePublicKey)(auth.access_key);
    const lookup = await viewAccessKey(ctx.rpcUrl, accountId, auth.access_key, ctx.block.hash);
    const isFullAccess = lookup.kind === "found"
        ? lookup.fullAccess
        : lookup.kind === "key_not_found"
            ? // Account exists but the key is absent: the owner may have removed it
                // deliberately, even for an implicit-derived ID.
                false
            : // Account doesn't exist (yet): accept only if it is the implicit
                // account derived from this key — it can be claimed under it any time.
                (0, nep641_1.implicitAccountId)(publicKey) === accountId;
    if (!isFullAccess)
        return fail(`access key without FullAccess permission: ${auth.access_key}`);
    // 7. leaf
    return { ok: true, res: { payload: auth.msg.payload, pending: [] } };
}
/** `w_resolve_auth(path, authorization)` view call at the pinned block. */
async function resolveContract(ctx, accountId, path, blob) {
    let bytes;
    try {
        const r = await viewCall(ctx.rpcUrl, accountId, "w_resolve_auth", { path, authorization: blob }, ctx.block.hash);
        if (r.blockHash !== ctx.block.hash) {
            return { ok: false, error: "returned block doesn't match the requested one", parsedAsAccessKey: false };
        }
        bytes = r.result;
    }
    catch (e) {
        const error = isNoContractError(e)
            ? "account does not exist, has not been initialized yet or has no contract deployed"
            : (e.message ?? String(e));
        return { ok: false, error, parsedAsAccessKey: false };
    }
    let parsed;
    try {
        parsed = JSON.parse(new TextDecoder().decode(bytes));
    }
    catch {
        return { ok: false, error: "w_resolve_auth returned non-JSON", parsedAsAccessKey: false };
    }
    if (typeof parsed?.payload !== "string") {
        return { ok: false, error: "w_resolve_auth returned no payload", parsedAsAccessKey: false };
    }
    const pending = parsed.pending ?? [];
    if (!Array.isArray(pending) ||
        !pending.every((p) => typeof p?.account_id === "string" && typeof p?.authorization === "string" && typeof p?.expect === "string")) {
        return { ok: false, error: "w_resolve_auth returned malformed pending list", parsedAsAccessKey: false };
    }
    return { ok: true, res: { payload: parsed.payload, pending } };
}
/**
 * NEP-641 §"Resolution of a single authorization": attempt both, concurrently.
 * A successful access-key resolution takes precedence. If both fail, report
 * the access-key error when the blob parsed as an `AccessKeyAuthorization` but
 * failed key verification; otherwise the contract error.
 */
async function resolveSingle(ctx, accountId, path, blob, expect) {
    const [accessKey, contract] = await Promise.all([
        resolveAccessKey(ctx, accountId, path, blob).catch((e) => ({ ok: false, error: e.message ?? String(e), parsedAsAccessKey: true })),
        resolveContract(ctx, accountId, path, blob).catch((e) => ({ ok: false, error: e.message ?? String(e), parsedAsAccessKey: false })),
    ]);
    const at = (error) => ({ ok: false, error: `${[...path].reverse().concat(accountId).join(" -> ")}: ${error}` });
    let res;
    if (accessKey.ok)
        res = accessKey.res;
    else if (contract.ok)
        res = contract.res;
    else
        return at(accessKey.parsedAsAccessKey ? accessKey.error : contract.error);
    if (expect !== null && res.payload !== expect) {
        return at(`resolved payload is invalid: expected: ${expect}, got: ${res.payload}`);
    }
    return { ok: true, res };
}
const DEFAULT_MAX_SUB_AUTHORIZATIONS = 8;
const DEFAULT_MAX_DEPTH = 8;
// Account-not-found can transiently appear after a relayer creates the
// wallet-contract account: the dApp's view call may race ahead of the chain
// indexing the new account. Retry the resolution with exponential backoff so
// the caller doesn't see a false negative.
const ACCOUNT_NOT_FOUND_RETRY_DELAYS_MS = [1000, 2000, 4000, 8000, 16000];
const NO_CONTRACT_MARKER = "account does not exist, has not been initialized yet or has no contract deployed";
function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
}
async function accountExists(rpcUrl, accountId) {
    try {
        await rpc(rpcUrl, "query", { request_type: "view_account", finality: "final", account_id: accountId });
        return true;
    }
    catch (e) {
        // Be conservative on unrelated RPC failures: don't spend the retry budget.
        return !isUnknownAccountError(e);
    }
}
async function resolveOnce(args, chainId) {
    const maxSub = args.maxSubAuthorizations ?? DEFAULT_MAX_SUB_AUTHORIZATIONS;
    const maxDepth = args.maxDepth ?? DEFAULT_MAX_DEPTH;
    // Pin the whole graph to one block.
    const block = await fetchBlock(args.rpcUrl, args.blockId != null ? { block_id: args.blockId } : { finality: "final" });
    const ctx = { rpcUrl: args.rpcUrl, chainId, block };
    // Top-level first: its payload is the result.
    const top = await resolveSingle(ctx, args.accountId, [], args.authorization, null);
    if (!top.ok)
        return { status: "INVALID", errorMessage: top.error };
    const payload = top.res.payload;
    // Breadth-first over pending sub-authorizations; siblings resolve concurrently.
    let total = 0;
    let frontier = [
        { accountId: args.accountId, path: [], res: top.res },
    ];
    while (frontier.length) {
        const next = [];
        for (const node of frontier) {
            if (!node.res.pending.length)
                continue;
            if (node.path.length >= maxDepth) {
                return { status: "INVALID", errorMessage: `max depth exceeded, maximum is set to: ${maxDepth}` };
            }
            total += node.res.pending.length;
            if (total > maxSub) {
                return { status: "INVALID", errorMessage: `too many sub-authorizations, maximum is set to: ${maxSub}` };
            }
            const subPath = [node.accountId, ...node.path]; // prepend parent ID (bottom-up)
            for (const sub of node.res.pending) {
                next.push(resolveSingle(ctx, sub.account_id, subPath, sub.authorization, sub.expect).then((r) => r.ok ? { accountId: sub.account_id, path: subPath, res: r.res } : { error: r.error }));
            }
        }
        const settled = await Promise.all(next);
        const failed = settled.find((r) => "error" in r);
        if (failed)
            return { status: "INVALID", errorMessage: failed.error };
        frontier = settled;
    }
    return { status: "RESOLVED", payload };
}
/**
 * Resolve a NEP-641 authorization to its authorized payload.
 *
 * The dApp MUST then check the returned payload: either that it equals the one
 * it issued, or by validating it (domain, action, nonce/expiry).
 */
async function verifyResolveAuth(args) {
    const chainId = args.chainId ?? (await fetchChainId(args.rpcUrl));
    let last = null;
    for (let attempt = 0; attempt <= ACCOUNT_NOT_FOUND_RETRY_DELAYS_MS.length; attempt++) {
        if (attempt > 0)
            await sleep(ACCOUNT_NOT_FOUND_RETRY_DELAYS_MS[attempt - 1]);
        // Re-pin the block each attempt so the retry sees the account once it
        // materializes.
        last = await resolveOnce(args, chainId);
        if (last.status === "RESOLVED")
            return last;
        // Retry only when the top-level account has no resolver at all *and*
        // genuinely doesn't exist yet.
        const topLevelNoResolver = last.errorMessage === `${args.accountId}: ${NO_CONTRACT_MARKER}`;
        if (!topLevelNoResolver || (await accountExists(args.rpcUrl, args.accountId)))
            return last;
    }
    return last;
}
//# sourceMappingURL=verifyResolveAuth.js.map