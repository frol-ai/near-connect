import { WalletManifest, WalletPermissions } from "../types";
import { NearConnector } from "../NearConnector";
import IframeExecutor from "./iframe";
declare class SandboxExecutor {
    readonly connector: NearConnector;
    readonly manifest: WalletManifest;
    private activePanels;
    readonly storageSpace: string;
    /** The `keepAlive` iframe, reused across calls (see WalletManifest.keepAlive). */
    private keptAlive;
    /** Live camera streams run on behalf of sandboxed wallets, per iframe. */
    private cameras;
    constructor(connector: NearConnector, manifest: WalletManifest);
    checkPermissions(action: keyof WalletPermissions, params?: {
        url?: string;
        entity?: string;
    }): boolean | undefined;
    assertPermissions(iframe: IframeExecutor, action: keyof WalletPermissions, event: MessageEvent): void;
    _onMessage: (iframe: IframeExecutor, event: MessageEvent) => Promise<void>;
    private actualCode;
    checkNewVersion(executor: SandboxExecutor, currentVersion: string | null): Promise<string>;
    loadCode(): Promise<string>;
    private createIframe;
    /** A fresh iframe per call, or the kept-alive one for `keepAlive` wallets. */
    private acquireIframe;
    private releaseIframe;
    call<T>(method: string, params: any): Promise<T>;
    private startCamera;
    /** The current camera frame, downscaled so its longer edge is at most `maxEdge`. */
    private cameraFrame;
    /** Stop the camera run for `iframe` (on camera.stop, dispose, or close). */
    releaseCamera(iframe: IframeExecutor): void;
    getAllStorage(): Promise<Record<string, any>>;
    clearStorage(): Promise<void>;
}
export default SandboxExecutor;
