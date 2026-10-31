import type { FinalExecutionOutcome } from "@near-js/types";
import type { Action } from "@near-js/transactions";
import type { ConnectorAction } from "../actions/types";
export type { FinalExecutionOutcome, Action };
export type Logger = {
    log: (...logs: any[]) => void;
};
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type Network = "mainnet" | "testnet";
export interface FunctionCallAccessKey_AllowMethods_AnyMethod {
    anyMethod: true;
}
export interface FunctionCallAccessKey_AllowMethods_SelectMethods {
    anyMethod: false;
    methodNames: string[];
}
export type AddFunctionCallKey_AllowMethods = FunctionCallAccessKey_AllowMethods_AnyMethod | FunctionCallAccessKey_AllowMethods_SelectMethods;
export interface FunctionCallAccessKey_GasAllowance_Unlimited {
    kind: "unlimited";
}
export interface FunctionCallAccessKey_GasAllowance_Limited {
    kind: "limited";
    /** The amount of gas allowed over the lifetime of the key in yoctoNEAR. */
    amount: string;
}
export type AddFunctionCallKey_GasAllowance = FunctionCallAccessKey_GasAllowance_Unlimited | FunctionCallAccessKey_GasAllowance_Limited;
export interface AddFunctionCallKeyParams {
    contractId: string;
    /** Using format "<key_type>:<base58_public_key>" e.g. "ed25519:3N5QmbhVqLh9ZtZs1zj8X9v1u1Z1Z1Z1Z1Z1Z1Z1Z1Z" */
    publicKey: string;
    /** Define which methods can be called by this Function Call Key on the "contractId" account */
    allowMethods: AddFunctionCallKey_AllowMethods;
    /** Optional:  The gas allowance for the Function Call Key over its lifetime of executing transactions.
     *  Default to "limited" with 0.25 NEAR (non-Yocto). */
    gasAllowance?: AddFunctionCallKey_GasAllowance;
}
export interface NearConnector_ConnectOptions {
    walletId?: string;
    /**
     * If this is provided, the connector will filter for wallets that support the "signInAndSignMessage" feature and use these params for the message to be signed along with sign in.
     *
     * The account and the signed message can be listened for using the "wallet:signInAndSignMessage" event, which will be emitted along
     * with the "wallet:signIn" event. This allows you to get the signed message right after sign in.
     *
     * This is useful for cases where you want to verify ownership of the account during sign in without any additional steps.
     */
    signMessageParams?: SignMessageDuringSignInParams;
    /**
     * If this is provided, the connector will filter for wallets that support the "signInWithFunctionCallAccessKey" feature and use these
     * params to add a function call access key during sign in.
     *
     * These params indicate to the wallet that a Function Call Key with these parameters should be added during the sign in process with the specified parameters.
     *
     * See: https://docs.near.org/protocol/access-keys#function-call-keys
     */
    addFunctionCallKey?: AddFunctionCallKeyParams;
}
export interface Account {
    accountId: string;
    publicKey?: string;
}
export interface AccountWithSignedMessage extends Account {
    signedMessage: SignedMessage;
}
export interface SignMessageParams {
    message: string;
    recipient: string;
    nonce: Uint8Array;
    network?: Network;
    signerId?: string;
}
export type SignMessageDuringSignInParams = Omit<SignMessageParams, "signerId" | "network">;
export interface SignedMessage {
    accountId: string;
    publicKey: string;
    signature: string;
}
export type EventNearWalletInjected = CustomEvent<NearWalletBase>;
export interface WalletPermissions {
    storage?: boolean;
    external?: string[];
    walletConnect?: boolean;
    allowsOpen?: string[];
    clipboardRead?: boolean;
    clipboardWrite?: boolean;
    usb?: boolean;
    hid?: boolean;
    bluetooth?: boolean;
    webauthn?: boolean;
}
export interface SignAndSendTransactionParams {
    network?: Network;
    signerId?: string;
    receiverId: string;
    actions: Array<Action | ConnectorAction>;
}
export interface SignAndSendTransactionsParams {
    network?: Network;
    signerId?: string;
    transactions: Array<{
        receiverId: string;
        actions: Array<Action | ConnectorAction>;
    }>;
}
export interface SignDelegateActionsParams {
    network?: Network;
    signerId?: string;
    delegateActions: Array<{
        actions: Array<Action | ConnectorAction>;
        receiverId: string;
    }>;
}
export interface SignDelegateActionsResponse {
    signedDelegateActions: string[];
}
/**
 * NEP-641 domain-separated JSON payload (recommended top-level `payload`
 * structure). Since the dApp accepts only payloads it issued byte-for-byte,
 * `domain` and `action` rule out cross-dApp and cross-action replay.
 */
export interface Nep641JsonPayload {
    /** dApp or protocol domain, e.g. `near.com` or `Near MPC`. */
    domain: string;
    /** Action taken on the dApp/protocol, e.g. `Login` or `Sign`. */
    action: string;
    /** dApp-specific message: plain text or JSON; may carry nonces, deadlines, TTLs, etc. */
    msg: string;
}
/**
 * NEP-641 `OffchainMessage`: the standardized signable envelope. Signature-based
 * resolvers MUST verify a signature over the entire message.
 */
export interface Nep641OffchainMessage {
    /** Chain ID, e.g. `mainnet`. */
    chain_id: string;
    /** Account this message authorizes for. */
    signer_id: string;
    /** Bottom-up path to the top-level resolver. Empty (or omitted) = top-level. */
    path?: string[];
    /** UNIX timestamp at signing, RFC-3339 string. */
    timestamp: string;
    /** The authorized payload. */
    payload: string;
}
/**
 * NEP-641 `AccessKeyAuthorization`: the standardized blob for accounts verified
 * against full-access keys (no contract to define one).
 */
export interface Nep641AccessKeyAuthorization {
    /** Signed offchain message. */
    msg: Nep641OffchainMessage;
    /** Signature schema and signing metadata. */
    via: {
        schema: "nep413";
        extra: {
            callback_url?: string;
        };
    };
    /** Access key with `FullAccess` permission: `ed25519:...` | `secp256k1:...`. */
    access_key: string;
    /** Signature: `ed25519:...` | `secp256k1:...`. */
    signature: string;
}
export interface ResolveAuthParams {
    network?: Network;
    /**
     * Chain ID bound into the signed `OffchainMessage`. Defaults to `network`
     * (`mainnet` / `testnet`); set explicitly for custom networks (e.g. a
     * sandbox), where it MUST match the chain ID reported by the RPC.
     */
    chainId?: string;
    /**
     * The payload to authorize. It is opaque to the protocol; dApps SHOULD use the
     * human-readable {@link Nep641JsonPayload} structure (pretty-printed JSON) so
     * wallets render it consistently. The dApp accepts only payloads it issued,
     * byte-for-byte, so replay protection (nonces, expiry) lives inside it.
     */
    payload: string;
}
export interface ResolveAuthResponse {
    accountId: string;
    /**
     * JSON-stringified NEP-641 authorization blob to pass to
     * `w_resolve_auth(path: [], authorization)` on `accountId` — or, for a
     * regular account, an {@link Nep641AccessKeyAuthorization} verified
     * offchain against the account's full-access keys.
     */
    authorization: string;
}
export interface WalletManifest {
    id: string;
    platform: string[];
    name: string;
    icon: string;
    description: string;
    website: string;
    version: string;
    executor: string;
    type: "sandbox" | "injected";
    permissions: WalletPermissions;
    features: WalletFeatures;
    debug?: boolean;
}
export interface WalletFeatures {
    signMessage: boolean;
    signTransaction: boolean;
    signAndSendTransaction: boolean;
    signAndSendTransactions: boolean;
    signInWithoutAddKey: boolean;
    signInAndSignMessage: boolean;
    signInWithFunctionCallKey: boolean;
    signDelegateActions: boolean;
    resolveAuth: boolean;
    mainnet: boolean;
    testnet: boolean;
}
export interface SignInParams {
    network?: Network;
    addFunctionCallKey?: AddFunctionCallKeyParams;
}
export interface SignInAndSignMessageParams extends SignInParams {
    messageParams: SignMessageDuringSignInParams;
}
export interface NearWalletBase {
    manifest: WalletManifest;
    /**
     * Programmatically sign in. Hardware wallets (e.g. Ledger) require `derivationPaths` to validate access key permissions.
     */
    signIn(data?: SignInParams): Promise<Array<Account>>;
    /**
     * Programmatically sign in. Hardware wallets (e.g. Ledger) require `derivationPaths` to validate access key permissions.
     */
    signInAndSignMessage(data: SignInAndSignMessageParams): Promise<Array<AccountWithSignedMessage>>;
    /**
     * Sign out from the wallet.
     */
    signOut(data?: {
        network?: Network;
    }): Promise<void>;
    /**
     * Returns one or more accounts when signed in.
     * This method can be useful for wallets that support accounts at once such as WalletConnect.
     * In this case, you can use an `accountId` returned as the `signerId` for `signAndSendTransaction`.
     */
    getAccounts(data?: {
        network?: Network;
    }): Promise<Array<Account>>;
    /**
     * Signs one or more NEAR Actions before sending to the network.
     * The user must be signed in to call this method as there's at least charges for gas spent.
     */
    signAndSendTransaction(params: SignAndSendTransactionParams): Promise<FinalExecutionOutcome>;
    /**
     * Signs one or more transactions before sending to the network.
     * The user must be signed in to call this method as there's at least charges for gas spent.
     */
    signAndSendTransactions(params: SignAndSendTransactionsParams): Promise<Array<FinalExecutionOutcome>>;
    signMessage(params: SignMessageParams): Promise<SignedMessage>;
    signDelegateActions(params: SignDelegateActionsParams): Promise<SignDelegateActionsResponse>;
    /**
     * NEP-641: authorize `payload` offchain and return the authorization blob.
     *
     * Wallet contracts return their contract-defined blob (resolved by the dApp
     * through the `w_resolve_auth(path, authorization)` view call); regular
     * accounts return an {@link Nep641AccessKeyAuthorization} — the
     * `OffchainMessage` envelope signed via NEP-413 with a full-access key,
     * which the dApp verifies offchain. See `verifyResolveAuth`.
     *
     * Only available when the wallet's `resolveAuth` feature is `true`.
     */
    resolveAuth?(params: ResolveAuthParams): Promise<ResolveAuthResponse>;
}
export interface EventMap {
    "wallet:signIn": {
        wallet: NearWalletBase;
        accounts: Account[];
        success: boolean;
        source: "signIn" | "signInAndSignMessage";
    };
    "wallet:signInAndSignMessage": {
        wallet: NearWalletBase;
        accounts: AccountWithSignedMessage[];
        success: boolean;
    };
    "wallet:signOut": any;
    "selector:manifestUpdated": any;
    "selector:walletsChanged": any;
}
export type EventType = keyof EventMap;
export type EventCallback<K extends EventType> = (payload: EventMap[K]) => void;
export type WalletEvents = {
    signedIn: {
        contractId: string;
        methodNames: Array<string>;
        accounts: Array<Account>;
    };
    accountsChanged: {
        accounts: Array<Account>;
    };
    networkChanged: {
        networkId: string;
    };
    signedOut: null;
};
export interface AbstractWalletConnect {
    connect: (params: any) => Promise<{
        uri?: string;
        approval: () => Promise<any>;
    }>;
    disconnect: (params: any) => Promise<void>;
    request: (params: any) => Promise<any>;
    session: {
        keys: string[];
        get: (key: string) => {
            topic: string;
            namespaces: any;
        };
    };
    core: {
        projectId?: string;
    };
}
export interface FooterBranding {
    icon?: string;
    heading: string;
    link: string;
    linkText: string;
}
