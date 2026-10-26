import { WalletManifest, WalletPermissions } from "../types";
import { NearConnector } from "../NearConnector";
import { parseUrl } from "../helpers/url";
import { uuid4 } from "../helpers/uuid";
import { copyText } from "../helpers/clipboard";
import { isTelegramMiniApp, openExternalLink, openTelegramLink } from "../helpers/telegram";

import IframeExecutor from "./iframe";

const cacheId = uuid4();

interface CameraSession {
  stream: MediaStream;
  video: HTMLVideoElement;
  canvas: HTMLCanvasElement;
}

class SandboxExecutor {
  private activePanels: Record<string, Window> = {};
  readonly storageSpace: string;
  /** Live camera streams run on behalf of sandboxed wallets, per iframe. */
  private cameras = new Map<string, CameraSession>();

  constructor(readonly connector: NearConnector, readonly manifest: WalletManifest) {
    this.storageSpace = manifest.id;
  }

  checkPermissions(action: keyof WalletPermissions, params?: { url?: string; entity?: string }) {
    if (action === "walletConnect") {
      return !!this.manifest.permissions.walletConnect;
    }

    if (action === "external") {
      const external = this.manifest.permissions.external;
      if (!external || !params?.entity) return false;
      return external.includes(params.entity);
    }

    if (action === "allowsOpen") {
      const openUrl = parseUrl(params?.url || "");
      const allowsOpen = this.manifest.permissions.allowsOpen;

      if (!openUrl || !allowsOpen || !Array.isArray(allowsOpen) || allowsOpen.length === 0) return false;
      const isAllowed = allowsOpen.some((path) => {
        const url = parseUrl(path);
        if (!url) return false;

        if (openUrl.protocol !== url.protocol) return false;
        if (!!url.hostname && openUrl.hostname !== url.hostname) return false;
        if (!!url.pathname && url.pathname !== "/" && openUrl.pathname !== url.pathname) return false;
        return true;
      });

      return isAllowed;
    }

    return this.manifest.permissions[action];
  }

  assertPermissions(iframe: IframeExecutor, action: keyof WalletPermissions, event: MessageEvent) {
    if (!this.checkPermissions(action, event.data.params)) {
      iframe.postMessage({ ...event.data, status: "failed", result: "Permission denied" });
      throw new Error("Permission denied");
    }
  }

  _onMessage = async (iframe: IframeExecutor, event: MessageEvent) => {
    const success = (result: any) => {
      iframe.postMessage({ ...event.data, status: "success", result: result });
    };

    const failed = (error: any) => {
      iframe.postMessage({ ...event.data, status: "failed", result: error });
    };

    if (event.data.method === "ui.showIframe") {
      iframe.show();
      success(null);
      return;
    }

    if (event.data.method === "ui.hideIframe") {
      iframe.hide();
      success(null);
      return;
    }

    // Camera bridge: a sandboxed (opaque-origin) iframe gets no camera
    // permission prompt of its own, so the dApp page opens the camera (the
    // prompt names the dApp) and hands frames to the wallet as ImageData.
    if (event.data.method === "camera.start") {
      this.assertPermissions(iframe, "camera", event);
      try {
        success(await this.startCamera(iframe, event.data.params ?? {}));
      } catch (e: any) {
        failed({ name: e?.name ?? "Error", message: e?.message ?? String(e) });
      }
      return;
    }

    if (event.data.method === "camera.frame") {
      this.assertPermissions(iframe, "camera", event);
      try {
        success(this.cameraFrame(iframe, event.data.params ?? {}));
      } catch (e: any) {
        failed({ name: e?.name ?? "Error", message: e?.message ?? String(e) });
      }
      return;
    }

    if (event.data.method === "camera.stop") {
      this.releaseCamera(iframe);
      success(null);
      return;
    }

    if (event.data.method === "storage.set") {
      this.assertPermissions(iframe, "storage", event);
      localStorage.setItem(`${this.storageSpace}:${event.data.params.key}`, event.data.params.value);
      success(null);
      return;
    }

    if (event.data.method === "storage.get") {
      this.assertPermissions(iframe, "storage", event);
      const value = localStorage.getItem(`${this.storageSpace}:${event.data.params.key}`);
      success(value);
      return;
    }

    if (event.data.method === "storage.keys") {
      this.assertPermissions(iframe, "storage", event);
      const keys = Object.keys(localStorage).filter((key) => key.startsWith(`${this.storageSpace}:`));
      success(keys);
      return;
    }

    if (event.data.method === "storage.remove") {
      this.assertPermissions(iframe, "storage", event);
      localStorage.removeItem(`${this.storageSpace}:${event.data.params.key}`);
      success(null);
      return;
    }

    if (event.data.method === "panel.focus") {
      const panel = this.activePanels[event.data.params.windowId];
      if (panel) panel.focus();
      success(null);
      return;
    }

    if (event.data.method === "panel.postMessage") {
      const panel = this.activePanels[event.data.params.windowId];
      if (panel) panel.postMessage(event.data.params.data, "*");
      success(null);
      return;
    }

    if (event.data.method === "panel.close") {
      const panel = this.activePanels[event.data.params.windowId];
      if (panel) panel.close();

      delete this.activePanels[event.data.params.windowId];
      success(null);
      return;
    }

    if (event.data.method === "walletConnect.connect") {
      this.assertPermissions(iframe, "walletConnect", event);
      try {
        if (!this.connector.walletConnect) throw new Error("WalletConnect is not configured");
        const client = await this.connector.walletConnect;
        const result = await client.connect(event.data.params);
        result.approval();
        success({ uri: result.uri });
      } catch (e) {
        failed(e);
      }
      return;
    }

    if (event.data.method === "walletConnect.getProjectId") {
      if (!this.connector.walletConnect) throw new Error("WalletConnect is not configured");
      this.assertPermissions(iframe, "walletConnect", event);
      const client = await this.connector.walletConnect;
      success(client.core.projectId);
      return;
    }

    if (event.data.method === "walletConnect.disconnect") {
      this.assertPermissions(iframe, "walletConnect", event);
      try {
        if (!this.connector.walletConnect) throw new Error("WalletConnect is not configured");
        const client = await this.connector.walletConnect;
        const result = await client.disconnect(event.data.params);
        success(result);
      } catch (e) {
        failed(e);
      }
      return;
    }

    if (event.data.method === "walletConnect.getSession") {
      this.assertPermissions(iframe, "walletConnect", event);
      try {
        if (!this.connector.walletConnect) throw new Error("WalletConnect is not configured");
        const client = await this.connector.walletConnect;
        const key = client.session.keys[client.session.keys.length - 1];
        const session = key ? client.session.get(key) : null;
        success(session ? { topic: session.topic, namespaces: session.namespaces } : null);
      } catch (e) {
        failed(e);
      }
      return;
    }

    if (event.data.method === "walletConnect.request") {
      this.assertPermissions(iframe, "walletConnect", event);
      try {
        if (!this.connector.walletConnect) throw new Error("WalletConnect is not configured");
        const client = await this.connector.walletConnect;
        const result = await client.request(event.data.params);
        success(result);
      } catch (e) {
        failed(e);
      }
      return;
    }

    if (event.data.method === "clipboard.writeText") {
      this.assertPermissions(iframe, "clipboardWrite", event);
      try {
        await copyText(event.data.params.text);
        success(null);
      } catch (e) {
        failed(e);
      }
      return;
    }

    if (event.data.method === "external") {
      this.assertPermissions(iframe, "external", event);
      try {
        const { entity, key, args } = event.data.params;
        const obj = entity.split(".").reduce((acc: any, key: string) => acc[key], window);

        // TODO: remove hack after Nightly fixes.
        // Their method wait near.Transaction and call encode() to get bytes.
        // External API should not require non-serializable data, this is unsafe from an isolation point of view.
        if (entity === "nightly.near" && key === "signTransaction") {
          args[0].encode = () => args[0];
        }

        const result = typeof obj[key] === "function" ? await obj[key](...(args || [])) : obj[key];
        success(result);
      } catch (e) {
        failed(e);
      }
      return;
    }

    if (event.data.method === "open") {
      this.assertPermissions(iframe, "allowsOpen", event);

      // Telegram Mini App blocks window.open, links go through Telegram (no panel to track)
      const tgUrl = parseUrl(event.data.params.url);
      if (tgUrl && tgUrl.protocol === "https:" && isTelegramMiniApp()) {
        if (tgUrl.hostname === "t.me") openTelegramLink(tgUrl);
        else openExternalLink(tgUrl);
        success(null);
        return;
      }

      const panel = window.open(event.data.params.url, "_blank", event.data.params.features);
      const panelId = panel ? uuid4() : null;

      const handler = (ev: MessageEvent) => {
        const url = parseUrl(event.data.params.url);
        if (url && url.origin === ev.origin) {
          iframe.postMessage(ev.data);
        }
      };

      success(panelId);
      window.addEventListener("message", handler);

      if (panel && panelId) {
        this.activePanels[panelId] = panel;
        const interval = setInterval(() => {
          if (!panel?.closed) return;

          window.removeEventListener("message", handler);
          const args = { method: "proxy-window:closed", windowId: panelId };
          delete this.activePanels[panelId];
          clearInterval(interval);

          try {
            iframe.postMessage(args);
          } catch {}
        }, 500);
      }

      return;
    }

    if (event.data.method === "open.nativeApp") {
      this.assertPermissions(iframe, "allowsOpen", event);

      const url = parseUrl(event.data.params.url);
      const invalid = ["https", "http", "javascript:", "file:", "data:", "blob:", "about:"];
      if (!url || invalid.includes(url.protocol)) {
        failed("Invalid URL");
        throw new Error("[open.nativeApp] Invalid URL");
      }

      const linkIframe = document.createElement("iframe");
      linkIframe.src = event.data.params.url;
      linkIframe.style.display = "none";
      document.body.appendChild(linkIframe);
      iframe.postMessage({ ...event.data, status: "success", result: null });
      return;
    }
  };

  private actualCode: string | null = null;
  async checkNewVersion(executor: SandboxExecutor, currentVersion: string | null) {
    if (this.actualCode) {
      this.connector.logger?.log(`New version of code already checked`);
      return this.actualCode;
    }

    let url = parseUrl(executor.manifest.executor);
    if (!url) url = parseUrl(location.origin + executor.manifest.executor); // relative url
    if (!url) throw new Error("Invalid executor URL");

    url.searchParams.set("nonce", cacheId);
    const newVersion = await fetch(url.toString()).then((res) => {
      // An error page (raw.githubusercontent 429/5xx) must not be cached and run as the executor
      if (!res.ok) throw new Error(`Failed to load executor: ${res.status}`);
      return res.text();
    });
    this.connector.logger?.log(`New version of code fetched`);
    this.actualCode = newVersion;

    if (newVersion === currentVersion) {
      this.connector.logger?.log(`New version of code is the same as the current version`);
      return this.actualCode;
    }

    // The cache is optional: IndexedDB fails on iOS Safari ("Connection to Indexed Database server lost", private mode),
    // and a failed write must not keep the wallet from opening
    await this.connector.db
      .setItem(`${this.manifest.id}:${this.manifest.version}`, newVersion)
      .then(() => this.connector.logger?.log(`New version of code saved to cache`))
      .catch((e) => this.connector.logger?.log(`Failed to cache new version of code`, e));

    return newVersion;
  }

  async loadCode(): Promise<string> {
    const cachedCode = await this.connector.db.getItem<string>(`${this.manifest.id}:${this.manifest.version}`).catch(() => null);
    this.connector.logger?.log(`Code loaded from cache`, cachedCode !== null);

    const task = this.checkNewVersion(this, cachedCode as string | null);
    if (cachedCode) return cachedCode;
    return await task;
  }

  async call<T>(method: string, params: any): Promise<T> {
    this.connector.logger?.log(`Add to queue`, method, params);

    // return this.queue.enqueue(async () => {
    this.connector.logger?.log(`Calling method`, method, params);

    const code = await this.loadCode();
    this.connector.logger?.log(`Code loaded, preparing`);

    const iframe = new IframeExecutor(this, code, this._onMessage, this.connector.cspNonce);
    this.connector.logger?.log(`Code loaded, iframe initialized`);

    await iframe.readyPromise;
    this.connector.logger?.log(`Iframe ready`);

    const id = uuid4();
    return new Promise<T>((resolve, reject) => {
      try {
        const handler = (event: MessageEvent) => {
          if (event.data.id !== id || event.data.origin !== iframe.origin) return;

          iframe.dispose();
          window.removeEventListener("message", handler);
          this.connector.logger?.log("postMessage", { result: event.data, request: { method, params } });

          if (event.data.status === "failed") reject(event.data.result);
          else resolve(event.data.result);
        };

        window.addEventListener("message", handler);
        iframe.postMessage({ method, params, id });
        iframe.on("close", () => reject(new Error("Wallet closed")));
      } catch (e) {
        this.connector.logger?.log(`Iframe error`, e);
        reject(e);
      }
    });
    // });
  }

  // ─── Camera bridge ─────────────────────────────────────────────────────────

  private async startCamera(iframe: IframeExecutor, params: { facingMode?: string; width?: number; height?: number }) {
    this.releaseCamera(iframe);
    if (!navigator.mediaDevices?.getUserMedia) {
      throw Object.assign(new Error("Camera is not available in this browser"), { name: "NotSupportedError" });
    }
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: {
        facingMode: { ideal: params.facingMode ?? "environment" },
        width: { ideal: params.width ?? 1920 },
        height: { ideal: params.height ?? 1080 },
      },
    });

    // The video must be in the document to keep decoding frames; keep it out of sight.
    const video = document.createElement("video");
    video.muted = true;
    video.playsInline = true;
    video.setAttribute("aria-hidden", "true");
    video.style.cssText = "position:fixed;width:1px;height:1px;opacity:0;pointer-events:none;left:-10px;top:-10px;";
    video.srcObject = stream;
    document.body.appendChild(video);
    await video.play().catch(() => {});
    if (video.readyState < 2) {
      await new Promise<void>((resolve) => video.addEventListener("loadeddata", () => resolve(), { once: true }));
    }

    this.cameras.set(iframe.origin, { stream, video, canvas: document.createElement("canvas") });
    const settings = stream.getVideoTracks()[0]?.getSettings() ?? {};
    return { facingMode: settings.facingMode ?? null, width: video.videoWidth, height: video.videoHeight };
  }

  /** The current camera frame, downscaled so its longer edge is at most `maxEdge`. */
  private cameraFrame(iframe: IframeExecutor, params: { maxEdge?: number }): ImageData {
    const session = this.cameras.get(iframe.origin);
    if (!session) throw Object.assign(new Error("Camera is not running"), { name: "InvalidStateError" });
    const { video, canvas } = session;
    if (video.videoWidth === 0) throw Object.assign(new Error("Camera is not ready"), { name: "InvalidStateError" });
    const maxEdge = Math.min(Math.max(params.maxEdge ?? 1280, 160), 1920);
    const scale = Math.min(1, maxEdge / Math.max(video.videoWidth, video.videoHeight));
    canvas.width = Math.round(video.videoWidth * scale);
    canvas.height = Math.round(video.videoHeight * scale);
    const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    return ctx.getImageData(0, 0, canvas.width, canvas.height);
  }

  /** Stop the camera run for `iframe` (on camera.stop, dispose, or close). */
  releaseCamera(iframe: IframeExecutor) {
    const session = this.cameras.get(iframe.origin);
    if (!session) return;
    this.cameras.delete(iframe.origin);
    session.stream.getTracks().forEach((track) => track.stop());
    session.video.srcObject = null;
    session.video.remove();
  }

  async getAllStorage() {
    const keys = Object.keys(localStorage).filter((key) => key.startsWith(`${this.storageSpace}:`));
    const storage: Record<string, any> = {};

    for (const key of keys) {
      storage[key.replace(`${this.storageSpace}:`, "")] = localStorage.getItem(key);
    }

    return storage;
  }

  async clearStorage() {
    const keys = Object.keys(localStorage).filter((key) => key.startsWith(`${this.storageSpace}:`));
    for (const key of keys) {
      localStorage.removeItem(key);
    }
  }
}

export default SandboxExecutor;
