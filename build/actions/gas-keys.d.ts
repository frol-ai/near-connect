import type { ConnectorAction } from "./types";
import type { WalletFeatures } from "../types";
/** The three connector-action shapes that only a gas-key-aware wallet can sign. */
export declare const isGasKeyAction: (action: ConnectorAction) => boolean;
/**
 * Refuse gas-key actions unless the wallet advertises `features.gasKeys`.
 *
 * Fail-closed on purpose: a wallet that predates gas keys would at best reject
 * the request, and at worst ignore the unknown `gasKeyInfo` field and add a
 * *plain* key with whatever permission it does understand. Flip the manifest
 * flag for a wallet only after a real sign-and-send has been verified with it.
 */
export declare function assertGasKeyActionsSupported(features: Partial<WalletFeatures> | undefined, actions: ConnectorAction[], walletName: string): void;
