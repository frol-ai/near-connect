export type VerifyResolveAuthResult = {
    status: "RESOLVED";
    payload: string;
} | {
    status: "INVALID";
    errorMessage: string;
};
export interface VerifyResolveAuthArgs {
    rpcUrl: string;
    /** Top-level resolver account. */
    accountId: string;
    /** Top-level authorization blob (from the wallet's `resolveAuth`). */
    authorization: string;
    /** Chain ID the envelope must be bound to. Fetched from the RPC `status` if omitted. */
    chainId?: string;
    /** Resolve against this block instead of the latest final one (e.g. audits). */
    blockId?: string | number;
    /** Cap on the total number of sub-authorizations. Defaults to 8. */
    maxSubAuthorizations?: number;
    /** Cap on the depth of sub-authorization branches. Defaults to 8. */
    maxDepth?: number;
}
/**
 * Resolve a NEP-641 authorization to its authorized payload.
 *
 * The dApp MUST then check the returned payload: either that it equals the one
 * it issued, or by validating it (domain, action, nonce/expiry).
 */
export declare function verifyResolveAuth(args: VerifyResolveAuthArgs): Promise<VerifyResolveAuthResult>;
